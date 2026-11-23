
import json
import csv
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = BASE_DIR / "reports" / "soc_alerts" / "soc_alerts.jsonl"
OUTPUT_DIR = BASE_DIR / "reports" / "incident_reports" / "generated"
REPORT_DIR = OUTPUT_DIR / "markdown"

SUMMARY_FILE = OUTPUT_DIR / "incident_reports_summary.csv"

# Generate only a small sample of detailed reports.
MAX_REPORTS = 10

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def clean_list(value):
    if isinstance(value, list):
        return value
    return []


def get_priority(severity):
    mapping = {
        "Critical": "P1 - Urgent",
        "High": "P2 - High",
        "Medium": "P3 - Medium",
        "Low": "P4 - Low"
    }
    return mapping.get(severity, "Unclassified")


def generate_report(alert, generated_at):
    alert_id = str(alert.get("AlertID", "Unknown"))
    incident_id = str(alert.get("IncidentID", "Unknown"))

    risk = alert.get("RiskAssessment", {})
    timeline = alert.get("IncidentTimeline", {})
    detection = alert.get("DetectionSummary", {})
    entities = alert.get("AffectedEntities", {})
    sources = alert.get("SourceReferences", {})
    investigation = alert.get("AnalystInvestigation", {})
    limitations = alert.get("Limitations", [])

    severity = risk.get("Severity", "Unknown")
    score = risk.get("RiskScore", "Unknown")
    priority = get_priority(severity)

    categories = clean_list(detection.get("Categories"))
    rules = clean_list(detection.get("DetectionRules"))
    techniques = clean_list(detection.get("MITRETechniques"))
    entity_types = clean_list(entities.get("EntityTypes"))
    evidence_roles = clean_list(entities.get("EvidenceRoles"))
    recommended_actions = clean_list(
        investigation.get("RecommendedActions")
    )
    alert_titles = clean_list(sources.get("AlertTitleIDs"))
    detector_ids = clean_list(sources.get("DetectorIDs"))

    report = f"""# SOC Incident Investigation Report

## 1. Report Information

| Field | Value |
|---|---|
| Alert ID | {alert_id} |
| Incident ID | {incident_id} |
| Severity | {severity} |
| Risk Score | {score} |
| Priority | {priority} |
| Generated At | {generated_at} |
| Disposition | Pending analyst review |

## 2. Executive Summary

A security incident was flagged by the rule-based detection system.

The incident received a **{severity}** severity classification and a
heuristic prioritization score of **{score}**.

This report is intended to support analyst investigation.
It does not establish that an attack was successful.

## 3. Incident Timeline

- First Seen: {timeline.get("FirstSeen", "Unknown")}
- Last Seen: {timeline.get("LastSeen", "Unknown")}

## 4. Detection Statistics

- Matched Records: {detection.get("MatchedRecords", 0)}
- Unique Alerts: {detection.get("UniqueAlerts", 0)}

## 5. Detection Categories

{chr(10).join("- " + str(x) for x in categories) or "- No category data available"}

## 6. Matched Detection Rules

{chr(10).join("- " + str(x) for x in rules) or "- No rule data available"}

## 7. MITRE ATT&CK Techniques

{chr(10).join("- " + str(x) for x in techniques) or "- No MITRE technique data recorded"}

## 8. Affected Entities

### Entity Types
{chr(10).join("- " + str(x) for x in entity_types) or "- No entity data available"}

### Evidence Roles
{chr(10).join("- " + str(x) for x in evidence_roles) or "- No evidence role data available"}

## 9. Source References

- Alert Title IDs: {", ".join(map(str, alert_titles)) or "None"}
- Detector IDs: {", ".join(map(str, detector_ids)) or "None"}
- Alert title IDs are numeric identifiers and have not been mapped to names.

## 10. Recommended Analyst Investigation

{chr(10).join("- " + str(x) for x in recommended_actions) or "- Review the alert evidence and validate the detection"}

## 11. Investigation Conclusion

**Status: Pending analyst review.**

No conclusion about confirmed compromise, attacker identity,
or data loss can be made from this automated report alone.

## 12. Report Limitations

{chr(10).join("- " + str(x) for x in limitations) or "- Rule-based detection; analyst validation is required"}

- Risk score is a prioritization score, not a probability of compromise.
- Numeric source identifiers are not mapped to descriptive names.
- Automated detection does not replace manual investigation.
"""

    return report


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    generated_at = datetime.now(timezone.utc).isoformat()

    summary_rows = []
    selected_alerts = []
    severity_counts = {}

    print("Reading alerts and creating summary...")

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            alert = json.loads(line)

            risk = alert.get("RiskAssessment", {})
            severity = risk.get("Severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            summary_rows.append({
                "AlertID": alert.get("AlertID"),
                "IncidentID": alert.get("IncidentID"),
                "Severity": severity,
                "RiskScore": risk.get("RiskScore"),
                "Priority": get_priority(severity),
                "FirstSeen": alert.get("IncidentTimeline", {}).get("FirstSeen"),
                "LastSeen": alert.get("IncidentTimeline", {}).get("LastSeen"),
                "MatchedRecords": alert.get("DetectionSummary", {}).get("MatchedRecords"),
                "Disposition": alert.get("AnalystInvestigation", {}).get(
                    "Disposition", "Pending analyst review"
                )
            })

            # Keep at most a few examples per severity.
            if len(selected_alerts) < MAX_REPORTS:
                selected_alerts.append(alert)

    # Write one summary CSV for all incidents.
    if summary_rows:
        with SUMMARY_FILE.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(summary_rows[0].keys())
            )
            writer.writeheader()
            writer.writerows(summary_rows)

    # Create only 10 detailed Markdown reports.
    print("Generating representative incident reports...")

    for alert in selected_alerts:
        alert_id = str(alert.get("AlertID", "Unknown"))
        report = generate_report(alert, generated_at)

        output_file = REPORT_DIR / f"{alert_id}.md"
        output_file.write_text(report, encoding="utf-8")

    print("\nIncident report generation completed.")
    print(f"Total incidents in summary: {len(summary_rows)}")
    print(f"Detailed Markdown reports: {len(selected_alerts)}")
    print(f"Summary CSV: {SUMMARY_FILE}")
    print(f"Detailed reports: {REPORT_DIR}")
    print(f"Severity counts: {severity_counts}")


if __name__ == "__main__":
    main()
