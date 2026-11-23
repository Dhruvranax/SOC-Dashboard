
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
    usecols=["IncidentId"]
)

# Exclude incidents with conflicting labels.
evaluation = labels.merge(
    detections.assign(Detected=1),
    on="IncidentId",
    how="left",
    validate="one_to_one"
)

evaluation["Detected"] = (
    evaluation["Detected"].fillna(0).astype(int)
)

# TruePositive is the positive class.
evaluation["Actual"] = (
    evaluation["IncidentGrade"] == "TruePositive"
).astype(int)

evaluation["Predicted"] = evaluation["Detected"]

tp = (
    (evaluation["Actual"] == 1)
    & (evaluation["Predicted"] == 1)
).sum()

tn = (
    (evaluation["Actual"] == 0)
    & (evaluation["Predicted"] == 0)
).sum()

fp = (
    (evaluation["Actual"] == 0)
    & (evaluation["Predicted"] == 1)
).sum()

fn = (
    (evaluation["Actual"] == 1)
    & (evaluation["Predicted"] == 0)
).sum()

precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0

f1 = (
    2 * precision * recall / (precision + recall)
    if precision + recall else 0
)

accuracy = (
    (tp + tn) / len(evaluation)
    if len(evaluation) else 0
)

coverage = evaluation["Predicted"].mean()

print("=" * 55)
print("SOC DETECTION PERFORMANCE")
print("=" * 55)

print(f"True Positives:  {tp:,}")
print(f"True Negatives:  {tn:,}")
print(f"False Positives: {fp:,}")
print(f"False Negatives: {fn:,}")

print(f"\nPrecision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-score:  {f1:.4f}")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Coverage:  {coverage:.4f}")

print("\nConfusion Matrix:")
print(
    pd.crosstab(
        evaluation["Actual"],
        evaluation["Predicted"],
        rownames=["Actual"],
        colnames=["Predicted"]
    )
)

output_file = OUTPUT_DIR / "detection_metrics.csv"

evaluation.to_csv(output_file, index=False)

print("\nEvaluation saved:", output_file)
