
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    ROOT / "Dataset" / "processed"
    / "GUIDE_Test_cleaned_v2.csv"
)

OUTPUT_DIR = ROOT / "reports" / "incident_reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(
    INPUT_FILE,
    usecols=["IncidentId", "IncidentGrade"]
)

# Count distinct labels for every incident.
label_counts = (
    df.groupby("IncidentId")["IncidentGrade"]
    .nunique()
)

# Keep incidents having exactly one distinct label.
consistent_ids = label_counts[label_counts == 1].index

consistent = df[df["IncidentId"].isin(consistent_ids)]

# Generate one label per consistent incident.
consistent_labels = (
    consistent.groupby("IncidentId")["IncidentGrade"]
    .first()
    .reset_index()
)

# Export consistent incident labels.
consistent_labels.to_csv(
    OUTPUT_DIR / "consistent_incident_labels.csv",
    index=False
)

# Export conflicting incident IDs.
conflicting_ids = label_counts[label_counts > 1]

conflicting_ids.rename(
    "DistinctLabelCount"
).reset_index().to_csv(
    OUTPUT_DIR / "conflicting_incidents.csv",
    index=False
)

print("=" * 55)
print("INCIDENT LABEL QUALITY REPORT")
print("=" * 55)

print("Total incidents:", len(label_counts))
print("Consistent incidents:", len(consistent_ids))
print("Conflicting incidents:", len(conflicting_ids))

print("\nConsistent label distribution:")
print(consistent_labels["IncidentGrade"].value_counts())

print("\nReports saved successfully.")
