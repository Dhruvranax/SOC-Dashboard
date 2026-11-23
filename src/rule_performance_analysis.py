
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LABEL_FILE = (
    ROOT / "reports" / "incident_reports"
    / "consistent_incident_labels.csv"
)

DETECTION_FILE = (
    ROOT / "reports" / "incident_reports"
    / "incident_detection_summary.csv"
)

OUTPUT_DIR = ROOT / "reports" / "incident_reports"

labels = pd.read_csv(LABEL_FILE)

detections = pd.read_csv(
    DETECTION_FILE,
    usecols=["IncidentId", "RiskScore", "DetectionRules"]
)

# Include all consistent-label incidents.
df = labels.merge(
    detections,
    on="IncidentId",
    how="left",
    validate="one_to_one"
)

df["RiskScore"] = df["RiskScore"].fillna(0)

df["DetectionRules"] = (
    df["DetectionRules"].fillna("")
)

df["Actual"] = (
    df["IncidentGrade"] == "TruePositive"
).astype(int)

# ------------------------------------------------
# 1. INDIVIDUAL RULE PERFORMANCE
# ------------------------------------------------

rule_records = []

for _, row in df.iterrows():

    rules = [
        rule.strip()
        for rule in row["DetectionRules"].split(";")
        if rule.strip()
    ]

    for rule in set(rules):

        rule_records.append({
            "Rule": rule,
            "Actual": row["Actual"]
        })

rule_df = pd.DataFrame(rule_records)

if not rule_df.empty:

    rule_performance = (
        rule_df.groupby("Rule")
        .agg(
            MatchedIncidents=("Actual", "count"),
            TruePositives=("Actual", "sum")
        )
        .reset_index()
    )

    rule_performance["TruePositiveRate"] = (
        rule_performance["TruePositives"]
        / rule_performance["MatchedIncidents"]
    )

    rule_performance = rule_performance.sort_values(
        "MatchedIncidents",
        ascending=False
    )

    print("\nRULE PERFORMANCE:")
    print(rule_performance.to_string(index=False))

    rule_performance.to_csv(
        OUTPUT_DIR / "rule_performance.csv",
        index=False
    )

# ------------------------------------------------
# 2. RISK SCORE THRESHOLD ANALYSIS
# ------------------------------------------------

print("\nRISK SCORE THRESHOLD ANALYSIS")

threshold_results = []

for threshold in [50, 60, 70, 80, 90, 100]:

    predicted = (
        df["RiskScore"] >= threshold
    ).astype(int)

    actual = df["Actual"]

    tp = ((actual == 1) & (predicted == 1)).sum()
    fp = ((actual == 0) & (predicted == 1)).sum()
    tn = ((actual == 0) & (predicted == 0)).sum()
    fn = ((actual == 1) & (predicted == 0)).sum()

    precision = (
        tp / (tp + fp)
        if tp + fp else 0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    threshold_results.append({
        "Threshold": threshold,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1Score": round(f1, 4),
    })

threshold_df = pd.DataFrame(threshold_results)

print(threshold_df.to_string(index=False))

threshold_df.to_csv(
    OUTPUT_DIR / "threshold_analysis.csv",
    index=False
)

print("\nReports saved successfully.")
