#!/usr/bin/env python3
"""Collect point-in-time evidence from an AWS account for the controls in controls/controls.yaml.

Each check returns a structured finding: control id, SOC 2 criteria, what was tested, the
population examined, the result (PASS / FAIL / WARN / NOT_TESTED) and the raw evidence
an auditor could re-perform the test from. Output is a dated JSON file plus a Markdown
summary under evidence/aws/.

Read-only: every API call is a Get/List/Describe. Nothing is modified.

Usage:
    python scripts/collect_aws_evidence.py [--profile NAME] [--region us-east-1] [--out evidence/aws]

Requires: boto3, credentials with SecurityAudit-equivalent read permissions.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

ROOT = Path(__file__).resolve().parents[1]

# Which register controls each check evidences. Keep in sync with controls/controls.yaml.
CONTROL_MAP = {
    "iam_root_no_access_keys": ("ACC-01", ["CC6.1", "CC6.2"]),
    "iam_root_mfa": ("ACC-01", ["CC6.1"]),
    "iam_users_mfa": ("ACC-01", ["CC6.1"]),
    "iam_password_policy": ("ACC-01", ["CC6.1"]),
    "iam_stale_access_keys": ("ACC-03", ["CC6.3"]),
    "s3_default_encryption": ("DAT-01", ["CC6.1", "CC6.7"]),
    "s3_public_access_block": ("NET-01", ["CC6.6"]),
    "ebs_default_encryption": ("DAT-01", ["CC6.1"]),
    "cloudtrail_enabled": ("OPS-02", ["CC7.2", "CC7.3"]),
    "guardduty_enabled": ("OPS-02", ["CC7.2"]),
    "config_recorder": ("CHG-02", ["CC7.1", "CC5.2"]),
}

STALE_KEY_DAYS = 90


def finding(check: str, result: str, tested: str, population: int, evidence, notes: str = "") -> dict:
    control, criteria = CONTROL_MAP[check]
    return {
        "check": check,
        "control": control,
        "soc2": criteria,
        "result": result,
        "tested": tested,
        "population": population,
        "evidence": evidence,
        "notes": notes,
    }


def not_tested(check: str, reason: str) -> dict:
    control, criteria = CONTROL_MAP[check]
    return {"check": check, "control": control, "soc2": criteria, "result": "NOT_TESTED",
            "tested": "", "population": 0, "evidence": None, "notes": reason}


# --------------------------------------------------------------------------- IAM

def check_iam_root(session) -> list[dict]:
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    out = []
    keys = summary.get("AccountAccessKeysPresent", 0)
    out.append(finding("iam_root_no_access_keys", "PASS" if keys == 0 else "FAIL",
                       "Root account has no access keys", 1, {"AccountAccessKeysPresent": keys}))
    mfa = summary.get("AccountMFAEnabled", 0)
    out.append(finding("iam_root_mfa", "PASS" if mfa == 1 else "FAIL",
                       "Root account has MFA enabled", 1, {"AccountMFAEnabled": mfa}))
    return out


def check_iam_users(session) -> list[dict]:
    iam = session.client("iam")
    users = [u for page in iam.get_paginator("list_users").paginate() for u in page["Users"]]
    now = dt.datetime.now(dt.timezone.utc)
    no_mfa, stale, rows = [], [], []
    for u in users:
        name = u["UserName"]
        has_console = True
        try:
            iam.get_login_profile(UserName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                has_console = False
            else:
                raise
        mfa_devices = iam.list_mfa_devices(UserName=name)["MFADevices"]
        if has_console and not mfa_devices:
            no_mfa.append(name)
        keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        key_rows = []
        for k in keys:
            age = (now - k["CreateDate"]).days
            last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"]
            last_used = last.get("LastUsedDate")
            idle = (now - last_used).days if last_used else age
            key_rows.append({"id": k["AccessKeyId"][-4:].rjust(len(k["AccessKeyId"]), "*"),
                             "status": k["Status"], "age_days": age, "idle_days": idle})
            if k["Status"] == "Active" and idle > STALE_KEY_DAYS:
                stale.append(f"{name}:{k['AccessKeyId'][-4:]}")
        rows.append({"user": name, "console": has_console, "mfa": bool(mfa_devices), "keys": key_rows})
    out = [
        finding("iam_users_mfa", "PASS" if not no_mfa else "FAIL",
                "Every IAM user with console access has an MFA device", len(users), rows,
                f"Users without MFA: {no_mfa}" if no_mfa else ""),
        finding("iam_stale_access_keys", "PASS" if not stale else "WARN",
                f"No active access key unused for more than {STALE_KEY_DAYS} days", len(users), rows,
                f"Stale keys: {stale}" if stale else ""),
    ]
    return out


def check_password_policy(session) -> list[dict]:
    iam = session.client("iam")
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return [finding("iam_password_policy", "FAIL", "Account password policy exists and meets baseline",
                            1, None, "No password policy set")]
        raise
    problems = []
    if p.get("MinimumPasswordLength", 0) < 14:
        problems.append("length < 14")
    if not p.get("RequireUppercaseCharacters"):
        problems.append("no uppercase requirement")
    if not p.get("RequireNumbers"):
        problems.append("no number requirement")
    if p.get("PasswordReusePrevention", 0) < 12:
        problems.append("reuse prevention < 12")
    return [finding("iam_password_policy", "PASS" if not problems else "WARN",
                    "Account password policy: length>=14, upper, number, reuse>=12", 1, p, "; ".join(problems))]


# --------------------------------------------------------------------------- S3 / EBS

def check_s3(session) -> list[dict]:
    s3 = session.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    unencrypted, public, rows = [], [], []
    for b in buckets:
        enc = None
        try:
            enc = s3.get_bucket_encryption(Bucket=b)["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                raise
        if enc is None:
            unencrypted.append(b)
        pab = None
        try:
            pab = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
        all_blocked = bool(pab) and all(pab.values())
        if not all_blocked:
            public.append(b)
        rows.append({"bucket": b, "default_encryption": enc, "public_access_block": pab})
    return [
        finding("s3_default_encryption", "PASS" if not unencrypted else "FAIL",
                "Every bucket has default server-side encryption", len(buckets), rows,
                f"Unencrypted: {unencrypted}" if unencrypted else ""),
        finding("s3_public_access_block", "PASS" if not public else "FAIL",
                "Every bucket blocks all public access", len(buckets), rows,
                f"Not fully blocked: {public}" if public else ""),
    ]


def check_ebs(session) -> list[dict]:
    ec2 = session.client("ec2")
    on = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    return [finding("ebs_default_encryption", "PASS" if on else "FAIL",
                    "EBS encryption by default is enabled in the region", 1, {"EbsEncryptionByDefault": on})]


# --------------------------------------------------------------------------- Logging / detection

def check_cloudtrail(session) -> list[dict]:
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    rows = []
    good = False
    for t in trails:
        status = ct.get_trail_status(Name=t["TrailARN"])
        row = {"name": t["Name"], "multi_region": t.get("IsMultiRegionTrail"),
               "log_validation": t.get("LogFileValidationEnabled"), "logging": status.get("IsLogging"),
               "bucket": t.get("S3BucketName")}
        rows.append(row)
        if row["multi_region"] and row["logging"] and row["log_validation"]:
            good = True
    return [finding("cloudtrail_enabled", "PASS" if good else "FAIL",
                    "At least one multi-region trail is logging with log file validation", len(trails), rows)]


def check_guardduty(session) -> list[dict]:
    gd = session.client("guardduty")
    ids = gd.list_detectors()["DetectorIds"]
    rows = []
    enabled = False
    for d in ids:
        det = gd.get_detector(DetectorId=d)
        rows.append({"detector": d, "status": det.get("Status")})
        if det.get("Status") == "ENABLED":
            enabled = True
    return [finding("guardduty_enabled", "PASS" if enabled else "FAIL",
                    "GuardDuty detector enabled in the region", len(ids), rows)]


def check_config(session) -> list[dict]:
    cfg = session.client("config")
    recorders = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    rows = [{"name": r["name"], "recording": r.get("recording")} for r in recorders]
    return [finding("config_recorder", "PASS" if any(r.get("recording") for r in recorders) else "FAIL",
                    "AWS Config recorder is recording", len(recorders), rows)]


CHECKS: list[tuple[str, Callable]] = [
    ("iam_root", check_iam_root), ("iam_users", check_iam_users), ("password_policy", check_password_policy),
    ("s3", check_s3), ("ebs", check_ebs), ("cloudtrail", check_cloudtrail),
    ("guardduty", check_guardduty), ("config", check_config),
]
GROUP_TO_CHECKS = {
    "iam_root": ["iam_root_no_access_keys", "iam_root_mfa"], "iam_users": ["iam_users_mfa", "iam_stale_access_keys"],
    "password_policy": ["iam_password_policy"], "s3": ["s3_default_encryption", "s3_public_access_block"],
    "ebs": ["ebs_default_encryption"], "cloudtrail": ["cloudtrail_enabled"], "guardduty": ["guardduty_enabled"],
    "config": ["config_recorder"],
}


def run(session, region: str) -> list[dict]:
    findings = []
    for group, fn in CHECKS:
        try:
            findings.extend(fn(session))
        except (ClientError, BotoCoreError) as e:
            for c in GROUP_TO_CHECKS[group]:
                findings.append(not_tested(c, f"{type(e).__name__}: {e}"))
    return findings


def write_outputs(findings: list[dict], account: str, region: str, out_dir: Path) -> tuple[Path, Path]:
    stamp = dt.datetime.now(dt.timezone.utc)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"{stamp:%Y-%m-%d}_{account}_{region}"
    payload = {"collected_at": stamp.isoformat(), "account": account, "region": region, "findings": findings}
    json_path = base.with_suffix(".json")
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    counts = {k: sum(1 for f in findings if f["result"] == k) for k in ("PASS", "FAIL", "WARN", "NOT_TESTED")}
    lines = [f"# AWS evidence collection — account {account}, region {region}", "",
             f"Collected {stamp:%Y-%m-%d %H:%M} UTC · PASS {counts['PASS']} · FAIL {counts['FAIL']} · "
             f"WARN {counts['WARN']} · NOT TESTED {counts['NOT_TESTED']}", "",
             "| Result | Control | SOC 2 | Test | Population | Notes |", "|---|---|---|---|---|---|"]
    for f in sorted(findings, key=lambda x: ("FAIL", "WARN", "NOT_TESTED", "PASS").index(x["result"])):
        lines.append(f"| {f['result']} | {f['control']} | {', '.join(f['soc2'])} | {f['tested']} | "
                     f"{f['population']} | {f['notes']} |")
    lines += ["", f"Raw evidence: `{json_path.name}`. Access key IDs are masked to their last four characters.", ""]
    md_path = base.with_suffix(".md")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", help="AWS CLI profile name")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--out", default=str(ROOT / "evidence" / "aws"))
    args = ap.parse_args(argv)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as e:
        print(f"Cannot authenticate to AWS: {e}", file=sys.stderr)
        return 2

    findings = run(session, args.region)
    json_path, md_path = write_outputs(findings, account, args.region, Path(args.out))
    for f in findings:
        print(f"{f['result']:<10} {f['control']:<7} {f['tested']}" + (f"  [{f['notes']}]" if f["notes"] else ""))
    print(f"\nWrote {md_path.relative_to(ROOT) if md_path.is_relative_to(ROOT) else md_path}")
    return 1 if any(f["result"] == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
