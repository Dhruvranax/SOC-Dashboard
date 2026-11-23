
"""
Microsoft SOC Dataset - Rule Diagnostics

Purpose:
    Investigate detection rule behavior and identify
    opportunities for evidence-based rule optimization.

IncidentGrade is used only for post-detection evaluation.
"""

from pathlib import Path
from collections import Counter
import pandas as pd

# --------------------------------------------------
# 1. CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORT_DIR = PROJECT_ROOT / "reports" / "incident_reports"

DETECTION_FILE = REPORT_DIR / "incident_detection_summary.csv"
LABEL_FILE = REPORT_DIR / "consistent_incident_labels.csv"

# --------------------------------------------------
# 2. LOAD DATA
# --------------------------------------------------

def load_data():

    detection = pd.read_csv(
        DETECTION_FILE,
        dtype={"IncidentId": "string"}
    )

    labels = pd.read_csv(
        LABEL_FILE,
        dtype={"IncidentId": "string"}
    )

    required_detection = [
        "IncidentId",
        "DetectionRules",
        "Categories",
        "MITRETechniques",
        "AlertTitles",
        "EntityTypes"
    ]

    required_labels = [
        "IncidentId",
        "IncidentGrade"
    ]

    for column in required_detection:
        if column not in detection.columns:
            raise ValueError(
                f"Missing detection column: {column}"
            )

    for column in required_labels:
        if column not in labels.columns:
            raise ValueError(
                f"Missing label column: {column}"
            )

    df = detection.merge(
        labels[required_labels],
        on="IncidentId",
        how="inner",
        validate="one_to_one"
    )

    print("DATA LOADED")
    print(f"Detected incidents: {len(detection):,}")
    print(f"Matched labelled incidents: {len(df):,}")

    return df


# --------------------------------------------------
# 3. RULE PERFORMANCE BY ALL THREE LABELS
# --------------------------------------------------

def analyze_rules(df):

    rows = []

    for _, row in df.iterrows():

        rules = str(row["DetectionRules"]).split(";")

        for rule in rules:

            rule = rule.strip()

            if not rule:
                continue

            rows.append({
                "Rule": rule,
                "IncidentGrade": row["IncidentGrade"]
            })

    rule_data = pd.DataFrame(rows)

    result = pd.crosstab(
        rule_data["Rule"],
        rule_data["IncidentGrade"]
    )

    result = result.reindex(
        columns=[
            "TruePositive",
            "FalsePositive",
            "BenignPositive"
        ],
        fill_value=0
    )

    result["Total"] = result.sum(axis=1)

    result["TruePositiveRate"] = (
        result["TruePositive"] / result["Total"]
    )

    result = result.sort_values(
        "TruePositiveRate",
        ascending=False
    )

    result.to_csv(
        REPORT_DIR / "rule_label_diagnostics.csv"
    )

    print("\nRULE PERFORMANCE BY LABEL")
    print(result.to_string())

    return result


# --------------------------------------------------
# 4. CATEGORY AND TECHNIQUE ANALYSIS
# --------------------------------------------------

def analyze_evidence(df):

    category_counts = Counter()
    technique_counts = Counter()

    for _, row in df.iterrows():

        categories = str(row["Categories"]).split(";")
        techniques = (
                        str(row["MITRETechniques"]).split(";")
                        if pd.notna(row["MITRETechniques"])
                            else []
                    )

        for item in categories:
            item = item.strip()

            if item:
                category_counts[item] += 1

        for item in techniques:
            item = item.strip()

            if item:
                technique_counts[item] += 1

    category_df = pd.DataFrame(
        category_counts.items(),
        columns=["Category", "IncidentCount"]
    ).sort_values(
        "IncidentCount",
        ascending=False
    )

    technique_df = pd.DataFrame(
        technique_counts.items(),
        columns=["Technique", "IncidentCount"]
    ).sort_values(
        "IncidentCount",
        ascending=False
    )

    category_df.to_csv(
        REPORT_DIR / "diagnostic_categories.csv",
        index=False
    )

    technique_df.to_csv(
        REPORT_DIR / "diagnostic_techniques.csv",
        index=False
    )

    print("\nTOP 15 CATEGORIES")
    print(category_df.head(15).to_string(index=False))

    print("\nTOP 15 MITRE TECHNIQUES")
    print(technique_df.head(15).to_string(index=False))


# --------------------------------------------------
# 5. ALERT TITLE AND ENTITY ANALYSIS
# --------------------------------------------------

def analyze_alerts(df):

    alert_counts = Counter()
    entity_counts = Counter()

    for _, row in df.iterrows():

        titles = str(row["AlertTitles"]).split(";")
        entities = str(row["EntityTypes"]).split(";")

        for title in titles:
            title = title.strip()

            if title:
                alert_counts[title] += 1

        for entity in entities:
            entity = entity.strip()

            if entity:
                entity_counts[entity] += 1

    alert_df = pd.DataFrame(
        alert_counts.items(),
        columns=["AlertTitle", "IncidentCount"]
    ).sort_values(
        "IncidentCount",
        ascending=False
    )

    entity_df = pd.DataFrame(
        entity_counts.items(),
        columns=["EntityType", "IncidentCount"]
    ).sort_values(
        "IncidentCount",
        ascending=False
    )

    alert_df.to_csv(
        REPORT_DIR / "diagnostic_alert_titles.csv",
        index=False
    )

    entity_df.to_csv(
        REPORT_DIR / "diagnostic_entity_types.csv",
        index=False
    )

    print("\nTOP 15 ALERT TITLES")
    print(alert_df.head(15).to_string(index=False))

    print("\nENTITY TYPE DISTRIBUTION")
    print(entity_df.head(15).to_string(index=False))


# --------------------------------------------------
# 6. RULE CO-OCCURRENCE ANALYSIS
# --------------------------------------------------

def analyze_rule_combinations(df):

    combinations = Counter()

    for rules in df["DetectionRules"].fillna(""):

        rule_list = sorted({
            item.strip()
            for item in rules.split(";")
            if item.strip()
        })

        for i in range(len(rule_list)):
            for j in range(i + 1, len(rule_list)):
                combinations[
                    (rule_list[i], rule_list[j])
                ] += 1

    result = pd.DataFrame(
        [
            {
                "Rule1": pair[0],
                "Rule2": pair[1],
                "IncidentCount": count
            }
            for pair, count in combinations.most_common(30)
        ]
    )

    result.to_csv(
        REPORT_DIR / "rule_cooccurrence.csv",
        index=False
    )

    print("\nTOP 30 RULE COMBINATIONS")
    print(result.to_string(index=False))


# --------------------------------------------------
# 7. MAIN
# --------------------------------------------------

def main():

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    df = load_data()

    analyze_rules(df)
    analyze_evidence(df)
    analyze_alerts(df)
    analyze_rule_combinations(df)

    print("\n" + "=" * 55)
    print("RULE DIAGNOSTICS COMPLETED")
    print("=" * 55)

    print(f"Reports saved in: {REPORT_DIR}")


if __name__ == "__main__":
    main()
