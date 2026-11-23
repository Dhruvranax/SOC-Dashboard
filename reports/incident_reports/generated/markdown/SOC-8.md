# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | SOC-8 |
| Incident ID | 8 |
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

- First Seen: 2024-06-08T17:11:27Z
- Last Seen: 2024-06-11T20:02:55Z

## 4. Detection Statistics

- Matched Records: 11199
- Unique Alerts: 768

## 5. Detection Categories

- CredentialAccess
- DefenseEvasion
- Discovery
- Execution
- Exfiltration
- InitialAccess
- LateralMovement
- Malware
- Persistence
- Ransomware

## 6. Matched Detection Rules

- Credential Access Activity
- Defense Evasion Activity
- Execution Activity
- Ingress Tool Transfer
- Initial Access Activity
- Lateral Movement Activity
- Malware-Related Activity
- Obfuscated Files or Information
- Persistence Activity
- Possible Data Exfiltration
- Ransomware-Related Activity
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

- Alert Title IDs: 1014, 12524, 12846, 13840, 14349, 1459, 1483, 15478, 161, 1673, 16843, 1742, 190, 1967, 21715, 229, 2350, 2386, 262, 264, 265, 275, 28, 2832, 2844, 288, 2925, 31020, 356, 37, 40, 441, 4449, 445, 46, 4628, 5284, 5402, 554, 557, 5818, 6079, 63, 6456, 7002, 7182, 72145, 84503, 887, 904, 925, 9945, 9946
- Detector IDs: 1011, 1104, 126, 135, 1400, 1430, 160, 166, 190, 211, 2171, 2297, 239, 273, 274, 275, 282, 293, 31, 3334, 347, 415, 418, 43, 44, 518, 55, 56, 62, 660, 673, 740, 85
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
- Review authentication and network activity between devices.
- Identify potentially affected accounts and machines.
- Review file and process evidence.
- Investigate affected devices for related suspicious activity.
- Review available persistence-related evidence.
- Investigate relevant registry, file and process activity.
- Review evidence related to suspected outbound data transfers.
- Identify affected files, accounts and destinations.
- Check whether the observed transfer was authorized.
- Investigate affected devices and file activity.
- Check for evidence of unauthorized file modification.
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
