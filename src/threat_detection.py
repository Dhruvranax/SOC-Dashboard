
"""
Microsoft SOC Dataset - Threat Detection Engineering

Purpose:
    Prioritize existing security alerts using transparent detection rules.
    Aggregate suspicious records into incident-level summaries.

Important:
    IncidentGrade is intentionally excluded from detection logic.
    This is rule-based alert prioritization, not proof of an attack.
"""

from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
import json
import re

import pandas as pd


# ---------------------------------------------------------
# 1. PROJECT CONFIGURATION
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "processed"
    / "GUIDE_Test_cleaned_v2.csv"
)

OUTPUT_DIR = PROJECT_ROOT / "reports" / "incident_reports"

CHUNK_SIZE = 100_000

# Limit the number of detailed JSON reports generated.
MAX_DETAILED_REPORTS = 50


# ---------------------------------------------------------
# 2. DETECTION RULES
# ---------------------------------------------------------

# Category-based alert prioritization.
CATEGORY_RULES = {
    "InitialAccess": {
        "rule": "Initial Access Activity",
        "score": 50,
        "description": "Alert associated with an initial access technique.",
    },
    "CredentialAccess": {
        "rule": "Credential Access Activity",
        "score": 80,
        "description": "Alert associated with credential access.",
    },
    "CommandAndControl": {
        "rule": "Command and Control Activity",
        "score": 90,
        "description": "Alert associated with command and control.",
    },
    "Exfiltration": {
        "rule": "Possible Data Exfiltration",
        "score": 90,
        "description": "Alert associated with data exfiltration.",
    },
    "Impact": {
        "rule": "Impact Activity",
        "score": 90,
        "description": "Alert associated with potential impact activity.",
    },
    "Persistence": {
        "rule": "Persistence Activity",
        "score": 70,
        "description": "Alert associated with persistence.",
    },
    "DefenseEvasion": {
        "rule": "Defense Evasion Activity",
        "score": 75,
        "description": "Alert associated with defense evasion.",
    },
    "LateralMovement": {
        "rule": "Lateral Movement Activity",
        "score": 80,
        "description": "Alert associated with lateral movement.",
    },
    "Execution": {
        "rule": "Execution Activity",
        "score": 60,
        "description": "Alert associated with execution.",
    },
    "Malware": {
        "rule": "Malware-Related Activity",
        "score": 85,
        "description": "Alert categorized as malware-related.",
    },
    "Ransomware": {
        "rule": "Ransomware-Related Activity",
        "score": 100,
        "description": "Alert categorized as ransomware-related.",
    },
}


# MITRE ATT&CK technique-based rules.
MITRE_RULES = {
    "T1078": {
        "rule": "Valid Accounts Activity",
        "score": 65,
        "description": "Activity associated with valid account abuse.",
    },
    "T1078.004": {
        "rule": "Cloud Account Abuse",
        "score": 75,
        "description": "Activity associated with cloud account abuse.",
    },
    "T1566": {
        "rule": "Phishing Activity",
        "score": 75,
        "description": "Activity associated with phishing.",
    },
    "T1566.001": {
        "rule": "Spearphishing Attachment",
        "score": 80,
        "description": "Activity associated with spearphishing attachments.",
    },
    "T1566.002": {
        "rule": "Spearphishing Link",
        "score": 80,
        "description": "Activity associated with spearphishing links.",
    },
    "T1133": {
        "rule": "External Remote Services",
        "score": 70,
        "description": "Activity associated with external remote services.",
    },
    "T1110": {
        "rule": "Brute Force Activity",
        "score": 85,
        "description": "Activity associated with brute force.",
    },
    "T1110.001": {
        "rule": "Password Guessing",
        "score": 85,
        "description": "Activity associated with password guessing.",
    },
    "T1110.003": {
        "rule": "Password Spraying",
        "score": 90,
        "description": "Activity associated with password spraying.",
    },
    "T1071": {
        "rule": "Application Layer Protocol",
        "score": 75,
        "description": "Activity associated with application-layer communications.",
    },
    "T1046": {
        "rule": "Network Service Discovery",
        "score": 65,
        "description": "Activity associated with network service discovery.",
    },
    "T1105": {
        "rule": "Ingress Tool Transfer",
        "score": 80,
        "description": "Activity associated with ingress tool transfer.",
    },
    "T1027": {
        "rule": "Obfuscated Files or Information",
        "score": 75,
        "description": "Activity associated with obfuscation.",
    },
    "T1059.005": {
        "rule": "Visual Basic Script Execution",
        "score": 70,
        "description": "Activity associated with Visual Basic script execution.",
    },
    "T1030": {
        "rule": "Data Transfer Size Limits",
        "score": 70,
        "description": "Activity associated with data transfer size limits.",
    },
}


# ---------------------------------------------------------
# 3. HELPER FUNCTIONS
# ---------------------------------------------------------

def clean_value(value):
    """Convert pandas values into safe strings."""
    if pd.isna(value):
        return None

    return str(value)


def get_severity(score):
    """Convert numerical score into severity."""
    if score >= 90:
        return "Critical"
    elif score >= 70:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"


def parse_techniques(value):
    """Extract MITRE technique IDs from semicolon-separated values."""
    if pd.isna(value):
        return []

    return [
        item.strip()
        for item in str(value).split(";")
        if item.strip()
    ]



def get_matching_techniques(techniques):
    """
    Match MITRE techniques while avoiding duplicate
    parent and sub-technique signals.

    If a matching sub-technique exists, do not also
    count its matching parent technique.
    """
    matched = [
        technique
        for technique in techniques
        if technique in MITRE_RULES
    ]

    matched_set = set(matched)

    filtered = []

    for technique in matched:
        parts = technique.split(".")

        # Skip parent if a matching sub-technique exists.
        if len(parts) == 1:
            has_matching_subtechnique = any(
                item.startswith(technique + ".")
                for item in matched_set
            )

            if has_matching_subtechnique:
                continue

        filtered.append(technique)

    return filtered



def calculate_incident_score(max_score, rules, techniques):
    """
    Calculate an incident-level score.

    The strongest individual signal is used as the base.
    Additional distinct rules and techniques add limited points.
    """
    rule_bonus = min(30, max(0, len(rules) - 1) * 10)
    technique_bonus = min(
        20,
        max(0, len(techniques) - 1) * 5
    )

    return min(100, max_score + rule_bonus + technique_bonus)


# ---------------------------------------------------------
# 4. INCIDENT AGGREGATION
# ---------------------------------------------------------

incidents = defaultdict(
    lambda: {
        "record_count": 0,
        "alert_ids": set(),
        "categories": set(),
        "rules": set(),
        "techniques": set(),
        "descriptions": set(),
        "alert_titles": set(),
        "entity_types": set(),
        "evidence_roles": set(),
        "detectors": set(),
        "first_seen": None,
        "last_seen": None,
        "max_score": 0,
    }
)


# ---------------------------------------------------------
# 5. PROCESS DATASET IN CHUNKS
# ---------------------------------------------------------

def process_dataset():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}"
        )

    print("=" * 65)
    print("MICROSOFT SOC - THREAT DETECTION ENGINE")
    print("=" * 65)

    # Read the CSV header first.
    available_columns = pd.read_csv(
        INPUT_FILE,
        nrows=0
    ).columns.tolist()

    required_columns = [
        "IncidentId",
        "Category",
        "MitreTechniques",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in available_columns
    ]

    if missing_columns:
        raise ValueError(
            f"Required columns missing: {missing_columns}"
        )

    optional_columns = [
        "AlertId",
        "Timestamp",
        "AlertTitle",
        "EntityType",
        "EvidenceRole",
        "DetectorId",
    ]

    use_columns = required_columns + [
        column
        for column in optional_columns
        if column in available_columns
    ]

    total_rows = 0
    detected_rows = 0

    reader = pd.read_csv(
        INPUT_FILE,
        usecols=use_columns,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    )

    for chunk_number, chunk in enumerate(reader, start=1):

        total_rows += len(chunk)

        # Normalize categories.
        chunk["Category"] = (
            chunk["Category"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        # Extract MITRE techniques.
        chunk["_techniques"] = (
            chunk["MitreTechniques"]
            .apply(parse_techniques)
        )

        # Category-based signals.
        chunk["_category_rule"] = (
            chunk["Category"].map(CATEGORY_RULES)
        )

        chunk["_category_score"] = (
            chunk["_category_rule"]
            .apply(
                lambda value: (
                    value["score"]
                    if isinstance(value, dict)
                    else 0
                )
            )
        )

        # MITRE-based signals.
        chunk["_matching_techniques"] = (
            chunk["_techniques"]
            .apply(get_matching_techniques)
        )

        chunk["_mitre_rules"] = (
            chunk["_matching_techniques"]
            .apply(
                lambda techniques: [
                    MITRE_RULES[technique]["rule"]
                    for technique in techniques
                ]
            )
        )

        chunk["_mitre_score"] = (
            chunk["_matching_techniques"]
            .apply(
                lambda techniques: max(
                    (
                        MITRE_RULES[technique]["score"]
                        for technique in techniques
                    ),
                    default=0,
                )
            )
        )

        # Combine rule matches.
        chunk["_rules"] = chunk.apply(
            lambda row: (
                (
                    [row["_category_rule"]["rule"]]
                    if isinstance(row["_category_rule"], dict)
                    else []
                )
                + row["_mitre_rules"]
            ),
            axis=1,
        )

        chunk["_score"] = chunk[
            ["_category_score", "_mitre_score"]
        ].max(axis=1)

        # Keep only records matching at least one rule.
        detected = chunk[chunk["_score"] > 0].copy()

        detected_rows += len(detected)

        # Aggregate evidence by incident.
       
        for _, row in detected.iterrows():

            incident_id = clean_value(row["IncidentId"])

            if incident_id is None:
                incident_id = "UNKNOWN_INCIDENT"

            incident = incidents[incident_id]

            incident["record_count"] += 1

            incident["max_score"] = max(
                incident["max_score"],
                int(row["_score"]),
            )

            category = clean_value(row["Category"])
            if category:
                incident["categories"].add(category)

            for rule in row["_rules"]:
                incident["rules"].add(rule)

            for technique in row["_matching_techniques"]:
                incident["techniques"].add(technique)

            alert_id = clean_value(row.get("AlertId"))
            if alert_id:
                incident["alert_ids"].add(alert_id)

            for column, target in [
                ("AlertTitle", "alert_titles"),
                ("EntityType", "entity_types"),
                ("EvidenceRole", "evidence_roles"),
                ("DetectorId", "detectors"),
            ]:
                value = clean_value(row.get(column))
                if value:
                    incident[target].add(value)

            timestamp = clean_value(row.get("Timestamp"))

            if timestamp:
                if incident["first_seen"] is None:
                    incident["first_seen"] = timestamp

                if (
                    incident["last_seen"] is None
                    or timestamp > incident["last_seen"]
                ):
                    incident["last_seen"] = timestamp

            for rule in row["_rules"]:

                for config in CATEGORY_RULES.values():
                    if config["rule"] == rule:
                        incident["descriptions"].add(
                            config["description"]
                        )

                for config in MITRE_RULES.values():
                    if config["rule"] == rule:
                        incident["descriptions"].add(
                            config["description"]
                        )


        print(
            f"Chunk {chunk_number}: "
            f"{len(chunk):,} records processed | "
            f"{len(detected):,} matched records"
        )

    print("-" * 65)
    print(f"Total records processed: {total_rows:,}")
    print(f"Records matching rules: {detected_rows:,}")
    print(f"Unique incidents detected: {len(incidents):,}")

    return total_rows, detected_rows


# ---------------------------------------------------------
# 6. GENERATE INCIDENT SUMMARY
# ---------------------------------------------------------

def generate_incident_summary():

    results = []

    for incident_id, data in incidents.items():

        rules = sorted(data["rules"])
        techniques = sorted(data["techniques"])

        score = calculate_incident_score(
            data["max_score"],
            rules,
            techniques,
        )

        results.append({
            "IncidentId": incident_id,
            "Severity": get_severity(score),
            "RiskScore": score,
            "MatchedRecords": data["record_count"],
            "UniqueAlerts": len(data["alert_ids"]),
            "Categories": "; ".join(sorted(data["categories"])),
            "DetectionRules": "; ".join(rules),
            "MITRETechniques": "; ".join(techniques),
            "FirstSeen": data["first_seen"],
            "LastSeen": data["last_seen"],
            "EntityTypes": "; ".join(sorted(data["entity_types"])),
            "EvidenceRoles": "; ".join(sorted(data["evidence_roles"])),
            "AlertTitles": "; ".join(sorted(data["alert_titles"])),
            "DetectorIds": "; ".join(sorted(data["detectors"])),
        })

    summary = pd.DataFrame(results)

    if not summary.empty:
        summary = summary.sort_values(
            by=["RiskScore", "MatchedRecords"],
            ascending=[False, False],
        )

    return summary


# ---------------------------------------------------------
# 7. GENERATE DETAILED JSON INCIDENT REPORTS
# ---------------------------------------------------------

def generate_json_reports(summary):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_count = min(
        MAX_DETAILED_REPORTS,
        len(summary)
    )

    for _, row in summary.head(report_count).iterrows():

        incident_id = row["IncidentId"]
        data = incidents[incident_id]

        report = {
            "report_generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "incident_id": incident_id,

            "severity": row["Severity"],

            "risk_score": int(row["RiskScore"]),

            "status": "Requires analyst investigation",

            "summary": {
                "matched_records": int(data["record_count"]),
                "unique_alerts": len(data["alert_ids"]),
                "categories": sorted(data["categories"]),
                "detection_rules": sorted(data["rules"]),
                "mitre_techniques": sorted(data["techniques"]),
            },

            "timeline": {
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            },

            "evidence": {
                "alert_titles": sorted(data["alert_titles"]),
                "entity_types": sorted(data["entity_types"]),
                "evidence_roles": sorted(data["evidence_roles"]),
                "detector_ids": sorted(data["detectors"]),
                "alert_ids": sorted(data["alert_ids"])[:100],
            },

            "rule_descriptions": sorted(data["descriptions"]),

            "analyst_recommendation": (
                "Review the associated alerts and supporting evidence. "
                "Validate the affected entities, timestamps, and MITRE "
                "techniques before confirming malicious activity."
            ),
        }

        # Use a safe filename.
        safe_id = re.sub(
            r"[^A-Za-z0-9_-]",
            "_",
            str(incident_id)
        )

        output_file = (
            OUTPUT_DIR
            / f"incident_{safe_id}.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False,
            )

    print(
        f"Detailed JSON reports generated: {report_count}"
    )


# ---------------------------------------------------------
# 8. MAIN EXECUTION
# ---------------------------------------------------------

def main():

    try:

        process_dataset()

        summary = generate_incident_summary()

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        summary_file = (
            OUTPUT_DIR
            / "incident_detection_summary.csv"
        )

        summary.to_csv(
            summary_file,
            index=False,
            encoding="utf-8",
        )

        generate_json_reports(summary)

        print("\n" + "=" * 65)
        print("THREAT DETECTION COMPLETED SUCCESSFULLY")
        print("=" * 65)

        print(
            f"\nIncident summary:\n{summary_file}"
        )

        print(
            f"\nDetailed reports directory:\n{OUTPUT_DIR}"
        )

        print("\nSeverity distribution:")

        if not summary.empty:
            print(
                summary["Severity"]
                .value_counts()
                .to_string()
            )
        else:
            print("No records matched the configured rules.")

    except Exception as error:

        print("\nERROR DURING THREAT DETECTION")
        print(str(error))

        raise


if __name__ == "__main__":
    main()
