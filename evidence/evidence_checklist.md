# Evidence collection checklist

What an auditor will ask for, organised by control, with where it usually lives and how often it must be refreshed. Populate the **Status** column during the audit period and link each artefact from the **Location** column. Evidence older than the observation period is not evidence.

| Control | Artefact | Source system | Refresh | Status | Location |
|---|---|---|---|---|---|
| ORG-01 | Approved policy set with version history | Document store | Annual | | |
| ORG-01 | Employee policy acknowledgements | HRIS / e-sign | Per hire + annual | | |
| ORG-02 | Org chart and control-owner list | HRIS, this repo | Annual | | |
| ORG-03 | Screening confirmation per hire | HRIS | Per hire | | |
| ORG-03 | Signed confidentiality agreement | E-sign | Per hire | | |
| ORG-04 | Training completion report | Training platform | Annual | | |
| ORG-04 | Phishing simulation results | Email security | Quarterly | | |
| RSK-01 | Risk register with review date and owners | Spreadsheet / GRC tool | Annual | | |
| RSK-02 | Vendor inventory with tier and last review | Spreadsheet / GRC tool | Annual | | |
| RSK-02 | Vendor SOC 2 reports or questionnaires (critical tier) | Vendor portal | Annual | | |
| MON-01 | Quarterly control review and deficiency log | Ticketing | Quarterly | | |
| ACC-01 | IdP MFA enforcement policy and user MFA status export | Identity provider | Quarterly | | |
| ACC-02 | Sample of access request tickets with approvals | Ticketing | Per request | | |
| ACC-02 | Role / permission matrix | Wiki | Annual | | |
| ACC-03 | Quarterly access review sign-offs and removal tickets | IdP + ticketing | Quarterly | | |
| ACC-04 | Offboarding checklists with revocation timestamps | HRIS + IdP logs | Per leaver | | |
| ACC-05 | Badge user list, visitor log, AWS SOC 2 report | Badge system, AWS Artifact | Annual | | |
| DAT-01 | TLS scan of public endpoints | Scanner | Quarterly | | |
| DAT-01 | Encryption-at-rest configuration export | AWS Config | Quarterly | | |
| DAT-02 | Classification policy and data inventory | Wiki | Annual | | |
| DAT-03 | Retention schedule, deletion job logs, destruction certificates | Wiki, job logs, vendor | Per event | | |
| END-01 | MDM compliance report, EDR coverage report | MDM, EDR console | Quarterly | | |
| OPS-01 | Vulnerability scan reports and remediation tickets with SLA dates | Scanner, ticketing | Continuous | | |
| OPS-02 | Log retention setting, alert rule inventory, sample triaged alerts | Log platform | Quarterly | | |
| OPS-03 | Incident response plan, tabletop record, post-incident reviews | Wiki, ticketing | Annual | | |
| OPS-04 | Capacity and uptime dashboards | Monitoring | Quarterly | | |
| OPS-05 | Backup configuration, restore test record | AWS Backup, ticketing | Annual | | |
| OPS-06 | BC/DR plan and exercise record | Wiki | Annual | | |
| CHG-01 | Branch protection settings, sample PRs with review + CI, emergency change log | GitHub, ticketing | Quarterly sample | | |
| CHG-02 | Account structure diagram, IaC repo, drift detection output | Wiki, GitHub, IaC tool | Quarterly | | |
| NET-01 | Security group export, WAF configuration | AWS | Quarterly | | |

## Sampling notes

- For per-event controls (access requests, changes, leavers) auditors typically sample 25 items across the period, or all items if fewer than 25 occurred. Keep the full population list so a sample can be drawn.
- Screenshots need a visible date and system identifier. Exports are better than screenshots.
- A control with no events in the period (for example, no incidents) is evidenced by the population list showing zero, not by the absence of evidence.
