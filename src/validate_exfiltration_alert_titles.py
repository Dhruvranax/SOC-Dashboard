
import pandas as pd
from pathlib import Path

INPUT = "Dataset/processed/GUIDE_Test_cleaned_v2.csv"
OUTPUT = Path("reports/exfiltration_investigation")
OUTPUT.mkdir(parents=True, exist_ok=True)

columns = ["IncidentId", "Category", "IncidentGrade", "AlertTitle", "Timestamp"]

parts = []

for chunk in pd.read_csv(INPUT, usecols=columns, chunksize=100_000):
    data = chunk[chunk["Category"] == "Exfiltration"].copy()
    parts.append(data)

df = pd.concat(parts, ignore_index=True)
df = df.dropna(subset=["IncidentId"])

df["Timestamp"] = pd.to_datetime(df["Timestamp"], utc=True, errors="coerce")

# One label and one closure timestamp per incident
incident = (
    df.groupby("IncidentId")
      .agg(
          labels=("IncidentGrade", lambda x: set(x.dropna().astype(str))),
          split_time=("Timestamp", "max")
      )
      .reset_index()
)

incident["Grade"] = incident["labels"].apply(
    lambda x: next(iter(x)) if len(x) == 1 else None
)

incident = incident.dropna(subset=["Grade", "split_time"]).copy()

# Assign each incident to exactly one time partition
cutoff = incident["split_time"].quantile(0.80)

incident["Split"] = incident["split_time"].apply(
    lambda x: "Development" if x <= cutoff else "Holdout"
)

# Map each incident to its consistent grade
grade_map = incident.set_index("IncidentId")["Grade"].to_dict()
split_map = incident.set_index("IncidentId")["Split"].to_dict()

# Unique incident/title combinations
title_data = df.dropna(subset=["AlertTitle"])[
    ["IncidentId", "AlertTitle"]
].drop_duplicates()

title_data["Grade"] = title_data["IncidentId"].map(grade_map)
title_data["Split"] = title_data["IncidentId"].map(split_map)

title_data = title_data.dropna(subset=["Grade", "Split"])

development = title_data[title_data["Split"] == "Development"]
holdout = title_data[title_data["Split"] == "Holdout"]

dev_baseline = (
    incident[incident["Split"] == "Development"]["Grade"]
    .eq("TruePositive").mean()
)

holdout_baseline = (
    incident[incident["Split"] == "Holdout"]["Grade"]
    .eq("TruePositive").mean()
)

# Discover candidates using development data only
dev_counts = (
    development.groupby(["AlertTitle", "Grade"])["IncidentId"]
    .nunique()
    .unstack(fill_value=0)
)

for grade in ["TruePositive", "FalsePositive", "BenignPositive"]:
    if grade not in dev_counts.columns:
        dev_counts[grade] = 0

dev_counts["Total"] = dev_counts[
    ["TruePositive", "FalsePositive", "BenignPositive"]
].sum(axis=1)

dev_counts["TPFraction"] = dev_counts["TruePositive"] / dev_counts["Total"]

candidates = dev_counts[
    (dev_counts["Total"] >= 20) &
    (dev_counts["TPFraction"] > dev_baseline)
].index

# Evaluate fixed candidates on unseen incidents
test = (
    holdout[holdout["AlertTitle"].isin(candidates)]
    .groupby(["AlertTitle", "Grade"])["IncidentId"]
    .nunique()
    .unstack(fill_value=0)
)

for grade in ["TruePositive", "FalsePositive", "BenignPositive"]:
    if grade not in test.columns:
        test[grade] = 0

test["Total"] = test[
    ["TruePositive", "FalsePositive", "BenignPositive"]
].sum(axis=1)

test["TPFraction"] = test["TruePositive"] / test["Total"].replace(0, pd.NA)

test = test.reset_index()

test.to_csv(
    OUTPUT / "exfiltration_alert_title_holdout_results.csv",
    index=False
)

print("\nTEMPORAL HOLDOUT VALIDATION")
print("Cutoff:", cutoff)
print("Development incidents:", (incident["Split"] == "Development").sum())
print("Holdout incidents:", (incident["Split"] == "Holdout").sum())
print(f"Development TP baseline: {dev_baseline:.2%}")
print(f"Holdout TP baseline: {holdout_baseline:.2%}")
print("Candidates selected:", len(candidates))

print("\nHOLDOUT RESULTS")
print(test.sort_values("Total", ascending=False).round(4).to_string(index=False))

print("\nSaved:", OUTPUT / "exfiltration_alert_title_holdout_results.csv")
