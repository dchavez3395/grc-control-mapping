"""Exercise collect_aws_evidence.py against a mocked AWS account (moto).

The mock account is deliberately half-compliant so each check has something to find:
  - one user with console access and no MFA, one with MFA
  - one access key idle for 200 days, one fresh
  - one encrypted bucket with public access blocked, one bucket with neither
  - no password policy, no CloudTrail, GuardDuty enabled, EBS default encryption off
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path
from unittest import mock

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_aws_evidence as cae  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials():
    os.environ.update({"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SECURITY_TOKEN": "testing", "AWS_SESSION_TOKEN": "testing",
                       "AWS_DEFAULT_REGION": REGION})


def seed(session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Xx1!aaaaaaaaaaaaaa")
    iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam.enable_mfa_device(UserName="alice", SerialNumber="arn:aws:iam::123456789012:mfa/alice-mfa",
                          AuthenticationCode1="123456", AuthenticationCode2="654321")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Xx1!bbbbbbbbbbbbbb")  # console, no MFA
    iam.create_access_key(UserName="bob")
    iam.create_user(UserName="svc-deploy")  # no console; stale key simulated below
    iam.create_access_key(UserName="svc-deploy")

    s3 = session.client("s3")
    s3.create_bucket(Bucket="good-bucket")
    s3.put_bucket_encryption(Bucket="good-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.put_public_access_block(Bucket="good-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.create_bucket(Bucket="bad-bucket")

    session.client("guardduty").create_detector(Enable=True)


@mock_aws
def test_findings_on_half_compliant_account(tmp_path):
    session = boto3.Session(region_name=REGION)
    seed(session)

    # Make svc-deploy's key look 200 days old and never used.
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200)
    real_list_keys = session.client("iam").list_access_keys

    def aged_list_keys(UserName):
        r = real_list_keys(UserName=UserName)
        if UserName == "svc-deploy":
            for k in r["AccessKeyMetadata"]:
                k["CreateDate"] = old
        return r

    with mock.patch.object(cae, "boto3") as b3:
        real = boto3.Session(region_name=REGION)
        iam = real.client("iam")
        iam.list_access_keys = aged_list_keys
        b3.Session.return_value = real
        clients = {"iam": iam}
        real_client = real.client

        def client(name, **kw):
            return clients.get(name) or real_client(name, **kw)
        real.client = client
        findings = cae.run(real, REGION)

    by = {f["check"]: f for f in findings}
    assert by["iam_root_no_access_keys"]["result"] == "PASS"
    assert by["iam_users_mfa"]["result"] == "FAIL" and "bob" in by["iam_users_mfa"]["notes"]
    assert by["iam_stale_access_keys"]["result"] == "WARN" and "svc-deploy" in by["iam_stale_access_keys"]["notes"]
    assert by["iam_password_policy"]["result"] == "FAIL"
    assert by["s3_default_encryption"]["result"] == "FAIL" and "bad-bucket" in by["s3_default_encryption"]["notes"]
    assert by["s3_public_access_block"]["result"] == "FAIL" and "good-bucket" not in by["s3_public_access_block"]["notes"]
    assert by["ebs_default_encryption"]["result"] == "FAIL"
    assert by["cloudtrail_enabled"]["result"] == "FAIL"
    assert by["guardduty_enabled"]["result"] == "PASS"
    assert by["config_recorder"]["result"] == "FAIL"

    # every finding maps to a control that exists in the register
    import yaml
    controls = {c["id"] for c in yaml.safe_load((Path(cae.ROOT) / "controls" / "controls.yaml").read_text())}
    assert all(f["control"] in controls for f in findings)

    json_path, md_path = cae.write_outputs(findings, "123456789012", REGION, tmp_path)
    assert json_path.exists() and md_path.exists()
    md = md_path.read_text()
    assert "FAIL" in md and "ACC-01" in md
    # access key ids are masked in the raw evidence
    assert "AKIA" not in json_path.read_text()
