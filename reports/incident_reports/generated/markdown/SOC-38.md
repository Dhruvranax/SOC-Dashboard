# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | SOC-38 |
| Incident ID | 38 |
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

- First Seen: 2024-06-08T06:42:30Z
- Last Seen: 2024-06-08T17:19:57Z

## 4. Detection Statistics

- Matched Records: 10005
- Unique Alerts: 2950

## 5. Detection Categories

- CommandAndControl
- CredentialAccess
- InitialAccess

## 6. Matched Detection Rules

- Cloud Account Abuse
- Command and Control Activity
- Credential Access Activity
- Initial Access Activity
- Password Guessing
- Password Spraying

## 7. MITRE ATT&CK Techniques

- T1078.004
- T1110.001
- T1110.003

## 8. Affected Entities

### Entity Types
- CloudApplication
- CloudLogonRequest
- CloudLogonSession
- Ip
- Machine
- Process
- Url
- User

### Evidence Roles
- Impacted
- Related

## 9. Source References

- Alert Title IDs: 0, 12, 15, 2, 3, 330, 6
- Detector IDs: 0, 14, 19, 2, 331, 4, 7
- Alert title IDs are numeric identifiers and have not been mapped to names.

## 10. Recommended Analyst Investigation

- Review network evidence associated with the detection.
- Investigate affected devices and communication destinations.
- Review authentication activity for affected accounts.
- Investigate unusual login patterns and authentication failures.
- Review the initial access evidence and related authentication activity.
- Identify potentially affected users and devices.
- Inspect repeated authentication failures.
- Check whether any subsequent authentication succeeded.
- Review authentication attempts across affected accounts.
- Identify source IPs and unusual login patterns.

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
