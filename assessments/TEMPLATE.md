# Third-party risk assessment: <Vendor>

| | |
|---|---|
| **Vendor** | |
| **Service assessed** | |
| **Requesting team** | |
| **Assessor** | |
| **Assessment date** | |
| **Method** | Public-source review / questionnaire / SOC 2 report read (state which) |
| **Related control** | RSK-02 Vendor risk management (SOC 2 CC9.2, CC2.3) |

## 1. Scope and inherent risk

What the vendor does for us. Data classes it touches (Restricted / Confidential / Internal / Public). Inherent risk factors: data sensitivity, access to our environment, business criticality, substitutability, regulatory exposure. Assign a tier:

- **Tier 1 (critical):** confidential data or production access, or product-down if vendor is down. Full review, SOC 2 report read, annual re-review.
- **Tier 2 (important):** internal data or limited access. Questionnaire or public review, re-review every two years.
- **Tier 3 (low):** public data, no access. Inventory only.

## 2. Control review

Domains: governance and attestations; data protection; identity and access; platform and application security; availability and resilience; security incident history; contract terms; fourth parties. Rate each item **Meets / Partial / Not evidenced / Gap** and cite the evidence.

## 3. Findings

| ID | Finding | Severity | Basis |
|---|---|---|---|

## 4. Residual risk and recommendation

Residual risk (Low / Medium / High). Recommendation: Approve / Approve with conditions / Reject. Conditions in priority order, each tied to a finding.

## 5. Ongoing monitoring

Triggers, actions, owners.

## 6. Sources

URLs with retrieval date.
