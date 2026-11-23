
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "processed"
    / "GUIDE_Test_cleaned_v2.csv"
)

print("Checking incident label consistency...")

df = pd.read_csv(
    DATASET_FILE,
    usecols=["IncidentId", "IncidentGrade"]
)

# Count distinct labels for every incident.
label_counts = (
    df.groupby("IncidentId")["IncidentGrade"]
    .nunique()
)

print("\nTotal unique incidents:", len(label_counts))

print(
    "Incidents with one consistent label:",
    (label_counts == 1).sum()
)

print(
    "Incidents with multiple labels:",
    (label_counts > 1).sum()
)

print("\nNumber of distinct labels per incident:")
print(label_counts.value_counts().sort_index())

# Show examples of incidents with conflicting labels.
conflicting_ids = label_counts[label_counts > 1].index

examples = (
    df[df["IncidentId"].isin(conflicting_ids[:10])]
    .groupby("IncidentId")["IncidentGrade"]
    .unique()
)

print("\nExample incidents with conflicting labels:")
print(examples.to_string())
