# AWS evidence collection — account 123456789012-SAMPLE, region us-east-1

Collected 2026-09-02 03:05 UTC · PASS 3 · FAIL 8 · WARN 0 · NOT TESTED 0

| Result | Control | SOC 2 | Test | Population | Notes |
|---|---|---|---|---|---|
| FAIL | ACC-01 | CC6.1 | Root account has MFA enabled | 1 |  |
| FAIL | ACC-01 | CC6.1 | Every IAM user with console access has an MFA device | 3 | Users without MFA: ['bob'] |
| FAIL | ACC-01 | CC6.1 | Account password policy exists and meets baseline | 1 | No password policy set |
| FAIL | DAT-01 | CC6.1, CC6.7 | Every bucket has default server-side encryption | 2 | Unencrypted: ['bad-bucket'] |
| FAIL | NET-01 | CC6.6 | Every bucket blocks all public access | 2 | Not fully blocked: ['bad-bucket'] |
| FAIL | DAT-01 | CC6.1 | EBS encryption by default is enabled in the region | 1 |  |
| FAIL | OPS-02 | CC7.2, CC7.3 | At least one multi-region trail is logging with log file validation | 0 |  |
| FAIL | CHG-02 | CC7.1, CC5.2 | AWS Config recorder is recording | 0 |  |
| PASS | ACC-01 | CC6.1, CC6.2 | Root account has no access keys | 1 |  |
| PASS | ACC-03 | CC6.3 | No active access key unused for more than 90 days | 3 |  |
| PASS | OPS-02 | CC7.2 | GuardDuty detector enabled in the region | 1 |  |

Raw evidence: `SAMPLE_mock-account_us-east-1.json`. Access key IDs are masked to their last four characters.
