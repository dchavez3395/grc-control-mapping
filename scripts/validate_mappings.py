#!/usr/bin/env python3
"""Validate the control register against the SOC 2 criteria list and the framework crosswalk.

Checks
  1. Every SOC 2 criterion referenced by a control or the crosswalk exists in soc2_tsc.csv.
  2. Every framework reference in the crosswalk (NIST CSF category, ISO Annex A control,
     PCI requirement) exists in frameworks.json.
  3. Every SOC 2 criterion is covered by at least one control (coverage gap = finding).
  4. Every control has the required fields and a non-empty evidence list.

Writes docs/coverage_report.md and exits non-zero if any hard error is found, so it can
run in CI. Usage: python scripts/validate_mappings.py [--strict]  (strict also fails on gaps)
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TSC = ROOT / "mappings" / "soc2_tsc.csv"
CROSSWALK = ROOT / "mappings" / "crosswalk.csv"
FRAMEWORKS = ROOT / "mappings" / "frameworks.json"
CONTROLS = ROOT / "controls" / "controls.yaml"
REPORT = ROOT / "docs" / "coverage_report.md"

REQUIRED_FIELDS = {"id", "name", "description", "owner", "frequency", "type", "evidence", "soc2"}
CONTROL_TYPES = {"preventive", "detective", "corrective"}


def load_tsc() -> dict[str, dict]:
    with TSC.open(newline="", encoding="utf-8") as f:
        return {r["criterion_id"]: r for r in csv.DictReader(f)}


def load_crosswalk() -> list[dict]:
    with CROSSWALK.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def split(cell: str) -> list[str]:
    return [x.strip() for x in cell.split(";") if x.strip()]


def main(strict: bool = False) -> int:
    errors: list[str] = []
    warnings: list[str] = []

    tsc = load_tsc()
    frameworks = json.loads(FRAMEWORKS.read_text(encoding="utf-8"))
    nist = set(frameworks["nist_csf_2"]["categories"])
    iso = set(frameworks["iso_27001_2022"]["controls"])
    pci = set(frameworks["pci_dss_v4"]["requirements"])
    controls = yaml.safe_load(CONTROLS.read_text(encoding="utf-8"))

    # --- crosswalk integrity ---------------------------------------------------------
    crosswalk = load_crosswalk()
    mapped_in_crosswalk = set()
    for row in crosswalk:
        c = row["soc2_criterion"]
        mapped_in_crosswalk.add(c)
        if c not in tsc:
            errors.append(f"crosswalk: unknown SOC 2 criterion {c}")
        for ref in split(row["nist_csf_2_category"]):
            if ref not in nist:
                errors.append(f"crosswalk {c}: unknown NIST CSF category {ref}")
        for ref in split(row["iso_27001_2022_annex_a"]):
            if ref not in iso:
                errors.append(f"crosswalk {c}: ISO control {ref} not in frameworks.json")
        for ref in split(row["pci_dss_v4_requirement"]):
            req = ref.split(".")[0]
            if req not in pci:
                errors.append(f"crosswalk {c}: unknown PCI requirement {ref}")
    for c in tsc:
        if c not in mapped_in_crosswalk:
            warnings.append(f"crosswalk: criterion {c} has no framework mapping")

    # --- control register integrity ------------------------------------------------
    coverage: dict[str, list[str]] = defaultdict(list)
    seen_ids = set()
    for ctl in controls:
        cid = ctl.get("id", "<missing id>")
        if cid in seen_ids:
            errors.append(f"control {cid}: duplicate id")
        seen_ids.add(cid)
        missing = REQUIRED_FIELDS - set(ctl)
        if missing:
            errors.append(f"control {cid}: missing fields {sorted(missing)}")
            continue
        if ctl["type"] not in CONTROL_TYPES:
            errors.append(f"control {cid}: type must be one of {sorted(CONTROL_TYPES)}")
        if not ctl["evidence"]:
            errors.append(f"control {cid}: evidence list is empty")
        if not ctl["soc2"]:
            errors.append(f"control {cid}: maps to no SOC 2 criteria")
        for c in ctl["soc2"]:
            if c not in tsc:
                errors.append(f"control {cid}: unknown SOC 2 criterion {c}")
            else:
                coverage[c].append(cid)

    gaps = [c for c in tsc if c not in coverage]
    for c in gaps:
        warnings.append(f"coverage gap: {c} ({tsc[c]['category']}) has no control")

    # --- report -----------------------------------------------------------------------
    by_cat: dict[str, list[str]] = defaultdict(list)
    for c, row in tsc.items():
        by_cat[row["category"]].append(c)

    lines = ["# SOC 2 coverage report", "",
             f"Controls: **{len(controls)}** · Criteria: **{len(tsc)}** · "
             f"Covered: **{len(tsc) - len(gaps)}** · Gaps: **{len(gaps)}**", ""]
    for cat, crits in by_cat.items():
        lines += [f"## {cat}", "", "| Criterion | Controls | NIST CSF 2.0 | ISO 27001:2022 | PCI DSS v4 |", "|---|---|---|---|---|"]
        xw = {r["soc2_criterion"]: r for r in crosswalk}
        for c in crits:
            r = xw.get(c, {})
            ctls = ", ".join(coverage.get(c, [])) or "**GAP**"
            lines.append(f"| {c} | {ctls} | {r.get('nist_csf_2_category', '')} | {r.get('iso_27001_2022_annex_a', '')} | {r.get('pci_dss_v4_requirement', '')} |")
        lines.append("")
    if warnings:
        lines += ["## Warnings", ""] + [f"- {w}" for w in warnings] + [""]
    if errors:
        lines += ["## Errors", ""] + [f"- {e}" for e in errors] + [""]
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    print(f"\n{len(controls)} controls, {len(tsc)} criteria, {len(gaps)} gaps, "
          f"{len(warnings)} warnings, {len(errors)} errors -> {REPORT.relative_to(ROOT)}")
    if errors or (strict and gaps):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(strict="--strict" in sys.argv))
