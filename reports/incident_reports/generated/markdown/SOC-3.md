# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | SOC-3 |
| Incident ID | 3 |
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

- First Seen: 2024-06-03T21:53:10Z
- Last Seen: 2024-06-14T12:54:12Z

## 4. Detection Statistics

- Matched Records: 19154
- Unique Alerts: 1755

## 5. Detection Categories

- CredentialAccess
- DefenseEvasion
- Discovery
- Execution
- Exfiltration
- InitialAccess
- Malware
- Persistence

## 6. Matched Detection Rules

- Credential Access Activity
- Defense Evasion Activity
- Execution Activity
- Ingress Tool Transfer
- Initial Access Activity
- Malware-Related Activity
- Obfuscated Files or Information
- Persistence Activity
- Possible Data Exfiltration
- Spearphishing Attachment

## 7. MITRE ATT&CK Techniques

- T1027
- T1105
- T1566.001

## 8. Affected Entities

### Entity Types
- File
- Ip
- Machine
- MailMessage
- Process
- RegistryKey
- RegistryValue
- User

### Evidence Roles
- Impacted
- Related

## 9. Source References

- Alert Title IDs: 1014, 119, 12232, 12846, 13840, 15330, 15478, 161, 1673, 1693, 1742, 1880, 190, 1918, 1967, 2156, 22505, 2361, 2547, 262, 264, 265, 275, 28, 288, 2925, 2952, 3320, 356, 3687, 40, 41136, 429, 441, 46, 46003, 51495, 534, 53836, 5402, 553, 557, 5580, 5818, 63, 6456, 7002, 70532, 70614, 7504, 887, 904, 925, 946, 9946
- Detector IDs: 1011, 1065, 1079, 1104, 1242, 138, 1430, 1439, 1568, 160, 166, 1673, 190, 211, 2171, 2297, 2361, 273, 274, 275, 282, 293, 3088, 31, 3334, 347, 394, 405, 415, 43, 492, 515, 518, 56, 5763, 62, 660, 673, 706, 740, 85, 996
- Alert title IDs are numeric identifiers and have not been mapped to names.

## 10. Recommended Analyst Investigation

- Review authentication activity for affected accounts.
- Investigate unusual login patterns and authentication failures.
- Review evidence associated with possible security-control evasion.
- Inspect related process and device activity.
- Review process and file evidence.
- Investigate the execution context on affected devices.
- Review the initial access evidence and related authentication activity.
- Identify potentially affected users and devices.
- Review file and process evidence.
- Investigate affected devices for related suspicious activity.
- Review available persistence-related evidence.
- Investigate relevant registry, file and process activity.
- Review evidence related to suspected outbound data transfers.
- Identify affected files, accounts and destinations.
- Check whether the observed transfer was authorized.
- Inspect attachment evidence and affected devices.
- Review related file and process activity.

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
