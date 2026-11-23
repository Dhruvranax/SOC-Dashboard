
import pandas as pd
from pathlib import Path

INPUT = "Dataset/processed/GUIDE_Test_cleaned_v2.csv"
OUTPUT = Path("reports/exfiltration_investigation")
OUTPUT.mkdir(parents=True, exist_ok=True)

columns = ["IncidentId", "Category", "IncidentGrade", "AlertTitle"]

parts = []

for chunk in pd.read_csv(INPUT, usecols=columns, chunksize=100_000):
    data = chunk[chunk["Category"] == "Exfiltration"].copy()
    parts.append(data)

df = pd.concat(parts, ignore_index=True)
df = df.dropna(subset=["IncidentId"])

# Determine which incidents have consistent labels
labels = (
    df.dropna(subset=["IncidentGrade"])
      .groupby("IncidentId")["IncidentGrade"]
      .agg(lambda x: set(x.astype(str)))
)

consistent = {
    incident_id: next(iter(grades))
    for incident_id, grades in labels.items()
    if len(grades) == 1
}

# Exclude conflicting and missing labels
df["IncidentLevelGrade"] = df["IncidentId"].map(consistent)
df = df.dropna(subset=["IncidentLevelGrade", "AlertTitle"])

# Count unique incidents for each alert title and label
counts = (
    df.groupby(["AlertTitle", "IncidentLevelGrade"])["IncidentId"]
      .nunique()
      .unstack(fill_value=0)
)

for grade in ["TruePositive", "FalsePositive", "BenignPositive"]:
    if grade not in counts.columns:
        counts[grade] = 0

counts["TotalIncidents"] = counts[
    ["TruePositive", "FalsePositive", "BenignPositive"]
].sum(axis=1)

counts["TPFraction"] = (
    counts["TruePositive"] / counts["TotalIncidents"]
)

counts["FalsePositiveFraction"] = (
    counts["FalsePositive"] / counts["TotalIncidents"]
)

counts["BenignFraction"] = (
    counts["BenignPositive"] / counts["TotalIncidents"]
)

# Calculate the overall TruePositive prevalence in this subset
overall_tp = (
    df[["IncidentId", "IncidentLevelGrade"]]
    .drop_duplicates()["IncidentLevelGrade"]
    .eq("TruePositive")
    .mean()
)

counts = counts.sort_values(
    ["TotalIncidents", "TPFraction"],
    ascending=[False, False]
)

counts.reset_index().to_csv(
    OUTPUT / "exfiltration_alert_title_performance.csv",
    index=False
)

print("\nOVERALL EXFILTRATION TRUE-POSITIVE PREVALENCE")
print(f"{overall_tp:.2%}")

print("\nTOP 25 ALERT TITLES BY INCIDENT COUNT")
print(counts.head(25).round(4).to_string())

print("\nTOP ALERT TITLES BY TP FRACTION")
# Minimum sample size prevents tiny groups dominating the ranking
eligible = counts[counts["TotalIncidents"] >= 20]

print(
    eligible.sort_values("TPFraction", ascending=False)
            .head(20)
            .round(4)
            .to_string()
)

print("\nReport saved:", OUTPUT)
