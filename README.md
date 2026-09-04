# grc-control-mapping

A control register for a small SaaS company, mapped to SOC 2 (2017 Trust Services Criteria), with a crosswalk to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A and PCI DSS v4, and a validator that fails CI when a criterion has no control behind it.

I built this to learn how compliance programs are actually structured: not as a list of frameworks, but as a set of concrete controls with an owner, a frequency, and the evidence an auditor will ask for. The frameworks are the lens; the controls are the work.

## What's here

| Path | What it is |
|---|---|
| `controls/controls.yaml` | 25 controls for a ~30-person SaaS company on AWS, GitHub, Google Workspace and an identity provider. Each has an owner, frequency, control type, evidence list and the SOC 2 criteria it satisfies. |
| `mappings/soc2_tsc.csv` | The SOC 2 Common Criteria (CC1–CC9) plus Availability and Confidentiality, one row per criterion. |
| `mappings/crosswalk.csv` | Each SOC 2 criterion mapped to NIST CSF 2.0 categories, ISO 27001:2022 Annex A controls and PCI DSS v4 requirements, with a note on why. |
| `mappings/frameworks.json` | Reference lists of the framework identifiers used in the crosswalk, so the validator can catch typos. |
| `evidence/evidence_checklist.md` | The artefact an auditor will request for each control, where it lives, and how often it must be refreshed. |
| `scripts/validate_mappings.py` | Checks referential integrity across all of the above and writes `docs/coverage_report.md`. |
| `docs/coverage_report.md` | Generated. Coverage by criterion with the mapped frameworks alongside. |
| `assessments/vercel-2026-09.md` | A worked third-party risk assessment of a real vendor (Vercel) from public sources: inherent-risk tiering, control review by domain, ten findings, conditions for approval, monitoring plan. Evidence for control RSK-02. |
| `assessments/vanta-2026-09.md` | Second worked assessment: Vanta, the compliance-automation vendor itself. Six findings including its 2025 cross-customer exposure and a 99% SLA; approve with conditions. |
| `assessments/TEMPLATE.md` | The blank assessment template both reviews follow. |
| `scripts/collect_aws_evidence.py` | Read-only evidence collector for an AWS account: root MFA and access keys, IAM user MFA, stale access keys, password policy, S3 default encryption and public-access block, EBS default encryption, CloudTrail, GuardDuty, AWS Config. Every result is tagged with the register control and SOC 2 criteria it evidences. Writes a dated JSON + Markdown pair under `evidence/aws/`. |
| `tests/test_collect_aws_evidence.py` | Runs the collector against a mocked, deliberately half-compliant account (moto) and asserts each check catches what it should. |
| `evidence/aws/SAMPLE_*` | What the collector's output looks like, generated from the mock account. Real runs are git-ignored. |

## Run it

```bash
pip install -r requirements.txt -r requirements-dev.txt
python scripts/validate_mappings.py --strict          # register/crosswalk integrity; fails on gaps
python -m pytest tests -q                              # collector against a mocked AWS account
python scripts/collect_aws_evidence.py --profile audit # real account, read-only, needs SecurityAudit-level creds
```

The collector exits non-zero on any FAIL so it can gate a pipeline, and masks access key IDs in the raw evidence.

Current state: 25 controls, 38 criteria, 0 gaps. The GitHub Action runs the strict check on every push.

## How to use it for a real program

1. Replace the controls with yours. Keep the shape: one control, one owner, one frequency, evidence you could produce tomorrow.
2. Run the validator. A gap means a criterion an auditor will test that you have nothing to show for.
3. Use `evidence_checklist.md` as the audit-period tracker and link artefacts into the Location column.
4. When you add a framework, add its identifiers to `frameworks.json` and a column to the crosswalk; the validator will enforce the references.

## Design notes and known limits

- The SOC 2 criteria text is paraphrased from the 2017 TSC (with 2022 points of focus in mind), not reproduced verbatim; the AICPA publication is the authority.
- Processing Integrity and Privacy categories are intentionally out of scope. Most small SaaS audits cover Security plus Availability and/or Confidentiality.
- The crosswalk maps at the criterion-to-category level. Real audits map at the control-to-point-of-focus level; this repo is the scaffold you'd do that on.
- The company profile is a composite, not a real client.

## Why I built it

I spent three years on a regulated lending desk applying lender policy to files and chasing evidence to closure, then four years as a developer. This repo is the same motion (read the standard, apply it to a real system, write down the finding, automate the check) pointed at security compliance. It is the three artefacts of a 90-day plan toward a compliance analyst role: the control register, the vendor assessment under `assessments/`, and the AWS evidence collector under `scripts/`.

MIT licensed. Corrections welcome, especially on the crosswalk.
