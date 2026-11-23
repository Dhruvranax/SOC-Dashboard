# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | SOC-57 |
| Incident ID | 57 |
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

- First Seen: 2024-05-22T06:51:57Z
- Last Seen: 2024-06-13T23:06:52Z

## 4. Detection Statistics

- Matched Records: 10004
- Unique Alerts: 26

## 5. Detection Categories

- Execution
- Impact
- InitialAccess
- Malware

## 6. Matched Detection Rules

- Execution Activity
- Impact Activity
- Initial Access Activity
- Malware-Related Activity
- Obfuscated Files or Information
- Phishing Activity

## 7. MITRE ATT&CK Techniques

- T1027
- T1566

## 8. Affected Entities

### Entity Types
- File
- Ip
- Machine
- MailCluster
- MailMessage
- Mailbox
- Process
- User

### Evidence Roles
- Impacted
- Related

## 9. Source References

- Alert Title IDs: 1121, 130, 161, 178, 2120, 227, 249, 28, 394, 494, 5, 51, 541, 634, 67, 680, 685, 70, 703, 723, 735, 807, 824
- Detector IDs: 1155, 12, 190, 43, 6
- Alert title IDs are numeric identifiers and have not been mapped to names.

## 10. Recommended Analyst Investigation

- Review process and file evidence.
- Investigate the execution context on affected devices.
- Investigate affected systems and available impact evidence.
- Check for service disruption or unauthorized changes.
- Review the initial access evidence and related authentication activity.
- Identify potentially affected users and devices.
- Review file and process evidence.
- Investigate affected devices for related suspicious activity.
- Review related email and message evidence.
- Inspect URLs, attachments and affected users.

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
