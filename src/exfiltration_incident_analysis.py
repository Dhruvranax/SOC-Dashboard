
import pandas as pd
from pathlib import Path

INPUT = "Dataset/processed/GUIDE_Test_cleaned_v2.csv"
OUTPUT = Path("reports/exfiltration_investigation")
OUTPUT.mkdir(parents=True, exist_ok=True)

columns = ["IncidentId", "Category", "IncidentGrade", "AlertTitle"]

# Load only Exfiltration records
parts = []

for chunk in pd.read_csv(INPUT, usecols=columns, chunksize=100_000):
    data = chunk.loc[chunk["Category"] == "Exfiltration"].copy()
    parts.append(data)

df = pd.concat(parts, ignore_index=True)

# Remove records without an incident ID
df = df.dropna(subset=["IncidentId"])

# Incident-level label consistency
incident_labels = (
    df.dropna(subset=["IncidentGrade"])
      .groupby("IncidentId")["IncidentGrade"]
      .agg(lambda x: sorted(set(x.astype(str))))
)

label_counts = {
    "Consistent": 0,
    "ConflictingLabels": 0,
    "MissingLabel": 0
}

for incident_id in df["IncidentId"].unique():
    labels = incident_labels.get(incident_id, [])

    if len(labels) == 0:
        label_counts["MissingLabel"] += 1
    elif len(labels) == 1:
        label_counts["Consistent"] += 1
    else:
        label_counts["ConflictingLabels"] += 1

print("\nINCIDENT-LEVEL LABEL QUALITY")
for label, count in label_counts.items():
    print(f"{label}: {count}")

# Build incident-level label mapping
consistent_labels = {
    incident_id: labels[0]
    for incident_id, labels in incident_labels.items()
    if len(labels) == 1
}

df["IncidentLevelGrade"] = df["IncidentId"].map(consistent_labels)

# Alert title analysis by consistent incident label
valid = df.dropna(subset=["IncidentLevelGrade", "AlertTitle"])

title_report = (
    valid.groupby(["AlertTitle", "IncidentLevelGrade"])["IncidentId"]
         .nunique()
         .reset_index(name="UniqueIncidents")
         .sort_values(
             ["IncidentLevelGrade", "UniqueIncidents"],
             ascending=[True, False]
         )
)

title_report.to_csv(
    OUTPUT / "exfiltration_alert_titles_by_grade.csv",
    index=False
)

print("\nTOP ALERT TITLES BY INCIDENT LABEL")

for grade in ["TruePositive", "FalsePositive", "BenignPositive"]:
    subset = title_report[
        title_report["IncidentLevelGrade"] == grade
    ].head(15)

    print(f"\n{grade}")
    print(subset.to_string(index=False))

print("\nReport saved:", OUTPUT)
