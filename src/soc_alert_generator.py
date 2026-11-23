
import json
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# PATHS
# --------------------------------------------------

INPUT_FILE = Path(
    "reports/incident_reports/incident_detection_summary.csv"
)

OUTPUT_DIR = Path("reports/soc_alerts")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# ANALYST INVESTIGATION GUIDANCE
# --------------------------------------------------

RULE_GUIDANCE = {
    "Possible Data Exfiltration": [
        "Review evidence related to suspected outbound data transfers.",
        "Identify affected files, accounts and destinations.",
        "Check whether the observed transfer was authorized."
    ],
    "Credential Access Activity": [
        "Review authentication activity for affected accounts.",
        "Investigate unusual login patterns and authentication failures."
    ],
    "Password Spraying": [
        "Review authentication attempts across affected accounts.",
        "Identify source IPs and unusual login patterns."
    ],
    "Password Guessing": [
        "Inspect repeated authentication failures.",
        "Check whether any subsequent authentication succeeded."
    ],
    "Command and Control Activity": [
        "Review network evidence associated with the detection.",
        "Investigate affected devices and communication destinations."
    ],
    "Phishing Activity": [
        "Review related email and message evidence.",
        "Inspect URLs, attachments and affected users."
    ],
    "Spearphishing Link": [
        "Review the associated URL and message evidence.",
        "Determine whether affected users interacted with the link."
    ],
    "Spearphishing Attachment": [
        "Inspect attachment evidence and affected devices.",
        "Review related file and process activity."
    ],
    "Malware-Related Activity": [
        "Review file and process evidence.",
        "Investigate affected devices for related suspicious activity."
    ],
    "Ransomware-Related Activity": [
        "Investigate affected devices and file activity.",
        "Check for evidence of unauthorized file modification."
    ],
    "Lateral Movement Activity": [
        "Review authentication and network activity between devices.",
        "Identify potentially affected accounts and machines."
    ],
    "Persistence Activity": [
        "Review available persistence-related evidence.",
        "Investigate relevant registry, file and process activity."
    ],
    "Defense Evasion Activity": [
        "Review evidence associated with possible security-control evasion.",
        "Inspect related process and device activity."
    ],
    "Execution Activity": [
        "Review process and file evidence.",
        "Investigate the execution context on affected devices."
    ],
    "Initial Access Activity": [
        "Review the initial access evidence and related authentication activity.",
        "Identify potentially affected users and devices."
    ],
    "Impact Activity": [
        "Investigate affected systems and available impact evidence.",
        "Check for service disruption or unauthorized changes."
    ]
}

DEFAULT_GUIDANCE = [
    "Review the matched detection evidence.",
    "Identify affected entities and examine the incident timeline.",
    "Validate the activity before determining incident disposition."
]


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def split_values(value):
    """Convert semicolon-separated values into a clean list."""

    if pd.isna(value):
        return []

    return [
        item.strip()
        for item in str(value).split(";")
        if item.strip()
    ]


def safe_number(value):
    """Convert numeric values safely."""

    if pd.isna(value):
        return 0

    return int(value)


def generate_recommendations(rules):
    """Generate investigation guidance from matched rule names."""

    recommendations = []

    for rule in rules:
        recommendations.extend(
            RULE_GUIDANCE.get(rule, [])
        )

    if not recommendations:
        recommendations = DEFAULT_GUIDANCE.copy()

    # Remove duplicate recommendations while preserving order.
    return list(dict.fromkeys(recommendations))


# --------------------------------------------------
# ALERT GENERATION
# --------------------------------------------------

def generate_alert(row):

    rules = split_values(row["DetectionRules"])
    categories = split_values(row["Categories"])
    techniques = split_values(row["MITRETechniques"])
    entity_types = split_values(row["EntityTypes"])
    evidence_roles = split_values(row["EvidenceRoles"])
    alert_titles = split_values(row["AlertTitles"])
    detector_ids = split_values(row["DetectorIds"])

    incident_id = str(row["IncidentId"])

    alert = {
        "AlertID": f"SOC-{incident_id}",
        "IncidentID": incident_id,

        "RiskAssessment": {
            "Severity": str(row["Severity"]),
            "RiskScore": safe_number(row["RiskScore"]),
            "ScoreType": "Heuristic prioritization score"
        },

        "IncidentTimeline": {
            "FirstSeen": str(row["FirstSeen"]),
            "LastSeen": str(row["LastSeen"])
        },

        "DetectionSummary": {
            "MatchedRecords": safe_number(row["MatchedRecords"]),
            "UniqueAlerts": safe_number(row["UniqueAlerts"]),
            "Categories": categories,
            "DetectionRules": rules,
            "MITRETechniques": techniques
        },

        "AffectedEntities": {
            "EntityTypes": entity_types,
            "EvidenceRoles": evidence_roles
        },

        "SourceReferences": {
            "AlertTitleIDs": alert_titles,
            "DetectorIDs": detector_ids,
            "AlertTitleIDsAreMapped": False
        },

        "AnalystInvestigation": {
            "RecommendedActions": generate_recommendations(rules),
            "Disposition": "Pending analyst review"
        },

        "Limitations": [
            "Detection output is rule-based.",
            "RiskScore is not a probability of compromise.",
            "Alert title values are numeric IDs without verified names.",
            "Recommended actions require analyst validation."
        ]
    }

    return alert


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    print("SOC ALERT GENERATION STARTED")

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Detection summary not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    required_columns = [
        "IncidentId",
        "Severity",
        "RiskScore",
        "MatchedRecords",
        "UniqueAlerts",
        "Categories",
        "DetectionRules",
        "MITRETechniques",
        "FirstSeen",
        "LastSeen",
        "EntityTypes",
        "EvidenceRoles",
        "AlertTitles",
        "DetectorIds"
    ]

    missing = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    print(f"Incidents loaded: {len(df):,}")

    csv_rows = []
    jsonl_path = OUTPUT_DIR / "soc_alerts.jsonl"

    severity_counts = {}

    with jsonl_path.open("w", encoding="utf-8") as json_file:

        for _, row in df.iterrows():

            alert = generate_alert(row)

            json_file.write(
                json.dumps(alert, ensure_ascii=False) + "\n"
            )

            risk = alert["RiskAssessment"]
            detection = alert["DetectionSummary"]
            entities = alert["AffectedEntities"]
            sources = alert["SourceReferences"]

            severity = risk["Severity"]

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

            csv_rows.append({
                "AlertID": alert["AlertID"],
                "IncidentID": alert["IncidentID"],
                "Severity": severity,
                "RiskScore": risk["RiskScore"],
                "MatchedRecords": detection["MatchedRecords"],
                "UniqueAlerts": detection["UniqueAlerts"],
                "FirstSeen": alert["IncidentTimeline"]["FirstSeen"],
                "LastSeen": alert["IncidentTimeline"]["LastSeen"],
                "DetectionRules": "; ".join(
                    detection["DetectionRules"]
                ),
                "Categories": "; ".join(
                    detection["Categories"]
                ),
                "MITRETechniques": "; ".join(
                    detection["MITRETechniques"]
                ),
                "EntityTypes": "; ".join(
                    entities["EntityTypes"]
                ),
                "EvidenceRoles": "; ".join(
                    entities["EvidenceRoles"]
                ),
                "AlertTitleIDs": "; ".join(
                    sources["AlertTitleIDs"]
                ),
                "DetectorIDs": "; ".join(
                    sources["DetectorIDs"]
                ),
                "RecommendedActions": " | ".join(
                    alert["AnalystInvestigation"]["RecommendedActions"]
                ),
                "Disposition": "Pending analyst review"
            })

    alerts_df = pd.DataFrame(csv_rows)

    csv_path = OUTPUT_DIR / "soc_alerts.csv"
    alerts_df.to_csv(csv_path, index=False)

    summary = {
        "TotalAlertsGenerated": len(alerts_df),
        "SeverityDistribution": severity_counts,
        "OutputFiles": [
            "soc_alerts.csv",
            "soc_alerts.jsonl"
        ],
        "RiskScoreMeaning": (
            "Heuristic prioritization score, not probability of compromise"
        ),
        "Status": "Generated - pending analyst review"
    }

    summary_path = OUTPUT_DIR / "alert_generation_summary.json"

    with summary_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4)

    print("\nSOC ALERT GENERATION COMPLETED")
    print(f"Total alerts: {len(alerts_df):,}")
    print("\nSeverity distribution:")

    for severity, count in sorted(severity_counts.items()):
        print(f"{severity}: {count:,}")

    print("\nOUTPUT FILES")
    print(csv_path)
    print(jsonl_path)
    print(summary_path)


if __name__ == "__main__":
    main()
