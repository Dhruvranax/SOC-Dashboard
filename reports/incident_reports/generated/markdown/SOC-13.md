# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | SOC-13 |
| Incident ID | 13 |
| Severity | Critical |
| Risk Score | 100 |
| Priority | P1 - Urgent |
| Generated At | 2026-11-22T15:42:59.714108+00:00 |
| Disposition | Pending analyst review |

## 2. Executive Summary

A security incident was flagged by the rule-based detection system.

The incident received a **Critical** severity classification and a
heuristic prioritization score of **100**.

This report is intended to support analyst investigation.
It does not establish that an attack was successful.

## 3. Incident Timeline

- First Seen: 2024-06-06T09:32:36Z
- Last Seen: 2024-06-06T22:43:06Z

## 4. Detection Statistics

- Matched Records: 10340
- Unique Alerts: 68

## 5. Detection Categories

- CredentialAccess
- InitialAccess

## 6. Matched Detection Rules

- Credential Access Activity
- Initial Access Activity
- Password Guessing
- Phishing Activity
- Spearphishing Link

## 7. MITRE ATT&CK Techniques

- T1110.001
- T1566
- T1566.002

## 8. Affected Entities

### Entity Types
- CloudApplication
- File
- Ip
- MailCluster
- MailMessage
- Mailbox
- Url
- User

### Evidence Roles
- Impacted
- Related

## 9. Source References

- Alert Title IDs: 1, 22, 23, 389, 48
- Detector IDs: 1, 33, 35, 377, 66
- Alert title IDs are numeric identifiers and have not been mapped to names.

## 10. Recommended Analyst Investigation

- Review authentication activity for affected accounts.
- Investigate unusual login patterns and authentication failures.
- Review the initial access evidence and related authentication activity.
- Identify potentially affected users and devices.
- Inspect repeated authentication failures.
- Check whether any subsequent authentication succeeded.
- Review related email and message evidence.
- Inspect URLs, attachments and affected users.
- Review the associated URL and message evidence.
- Determine whether affected users interacted with the link.

## 11. Investigation Conclusion

**Status: Pending analyst review.**

No conclusion about confirmed compromise, attacker identity,
or data loss can be made from this automated report alone.

## 12. Report Limitations

- Detection output is rule-based.
- RiskScore is not a probability of compromise.
- Alert title values are numeric IDs without verified names.
- Recommended actions require analyst validation.

- Risk score is a prioritization score, not a probability of compromise.
- Numeric source identifiers are not mapped to descriptive names.
- Automated detection does not replace manual investigation.
