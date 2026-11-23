
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "processed"
    / "GUIDE_Test_cleaned_v2.csv"
)

DETECTION_FILE = (
    PROJECT_ROOT
    / "reports"
    / "incident_reports"
    / "incident_detection_summary.csv"
)

# Load detected incidents.
detections = pd.read_csv(
    DETECTION_FILE,
    usecols=["IncidentId", "Severity", "RiskScore"]
)

# Read only the columns needed for evaluation.
labels = pd.read_csv(
    DATASET_FILE,
    usecols=["IncidentId", "IncidentGrade"]
)

# Aggregate existing labels at incident level.
label_summary = (
    labels.groupby("IncidentId")["IncidentGrade"]
    .agg(lambda values: values.mode().iloc[0] if not values.mode().empty else "Unknown")
    .reset_index()
)

# Merge detection results with ground-truth labels.
evaluation = detections.merge(
    label_summary,
    on="IncidentId",
    how="left",
    validate="one_to_one"
)

print("=" * 60)
print("SOC DETECTION EVALUATION")
print("=" * 60)

print("\nDetected incidents by existing IncidentGrade:")
print(
    evaluation["IncidentGrade"]
    .value_counts(dropna=False)
)

print("\nSeverity vs IncidentGrade:")
print(
    pd.crosstab(
        evaluation["Severity"],
        evaluation["IncidentGrade"],
        margins=True
    )
)

print("\nAverage risk score by IncidentGrade:")
print(
    evaluation.groupby("IncidentGrade")["RiskScore"]
    .agg(["count", "mean", "median"])
    .round(2)
)

# Save evaluation output.
output_file = (
    PROJECT_ROOT
    / "reports"
    / "incident_reports"
    / "detection_evaluation.csv"
)

evaluation.to_csv(output_file, index=False)

print("\nEvaluation saved to:")
print(output_file)
