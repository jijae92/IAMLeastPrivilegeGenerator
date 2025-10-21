# Compliance Mapping

IAM Least-Privilege Generator automates detection and enforcement workflows that align with multiple security frameworks. The tables below summarise where the project supports each control and how generated outputs should embed compliance labels.

## U.S. NIST SP 800-53 (Rev. 5)

| Control | Description | Project Alignment |
| --- | --- | --- |
| AC-6 Least Privilege | Limit system access to authorized users and the minimum necessary permissions. | Policy generator (`core/policy/generator.py`) compresses allowed actions into service/resource-aware statements, with CLI `generate` emitting `Compliance: AC-6` in policy headers. |
| AU-6 Audit Review, Analysis, and Reporting | Review audit records for inappropriate activity. | Parser + aggregator pipeline ingests CloudTrail (`parse`, `aggregate` commands) and can annotate reports with `Compliance: AU-6` meta tags. |
| CM-3 Configuration Change Control | Manage configuration changes through formal processes. | GitHub Actions + SAM deployment and diff reports document IAM policy modifications; include `Compliance: CM-3` in diff headers. |
| SI-10 Information Input Validation | Check inputs for validity before processing. | Normalizer validation and CLI parameter checks mark generated reports with `Compliance: SI-10` to highlight automated input hygiene. |

## ISO/IEC 27001:2013 Annex A

| Control | Description | Project Alignment |
| --- | --- | --- |
| A.9 Access Control | Ensure users have appropriate access rights. | Least-privilege policies and simulator outputs attach `Compliance: ISO27001-A.9`. |
| A.12.6 Technical Vulnerability Management | Identify and remediate vulnerabilities. | Diff reports highlight over-privileged actions, assisting with vulnerability remediation workflows (`Compliance: ISO27001-A.12.6`). |
| A.12.1.2 Change Management | Control changes to information processing facilities and systems. | SAM/CI workflows and policy diffs document change approvals; label reports with `Compliance: ISO27001-A.12.1.2`. |

## AWS Well-Architected Framework — Security Pillar

| Domain | Alignment |
| --- | --- |
| Identity and Access Management | Generator reduces IAM blast radius; prefix policy outputs with `Compliance: AWS-WA-Sec-IAM`. |
| Data Protection | Resource-level policies guard data assets; include `Compliance: AWS-WA-Sec-Data`. |
| Infrastructure Protection / Network Control | Aggregation surfaces services requiring tighter network controls; annotate summaries with `Compliance: AWS-WA-Sec-Net`. |
| Detection, Response & Change Management | Diff + simulator workflows support continuous monitoring; mark reports as `Compliance: AWS-WA-Sec-Change`. |

## Reporting Guidance

- **Policies:** Prefix each JSON document with a `metadata` object containing `"compliance": ["AC-6", "ISO27001-A.9", "AWS-WA-Sec-IAM"]` so downstream reviewers know the control coverage.
- **CLI Diff Reports:** When emitting Markdown or JSON, inject a header block such as `Compliance: [AC-6, AU-6, ISO27001-A.12.1.2, AWS-WA-Sec-Change]`.
- **UI:** Surface the same labels within the dashboard or exported artifacts to keep audit references intact.

Keep this mapping updated whenever new functionality targets additional controls or frameworks.
