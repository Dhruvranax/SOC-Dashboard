
import pandas as pd
from collections import Counter, defaultdict
from pathlib import Path

INPUT = "Dataset/processed/GUIDE_Test_cleaned_v2.csv"
OUTPUT_DIR = Path("reports/exfiltration_investigation")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

COLUMNS = [
    "IncidentId",
    "Category",
    "MitreTechniques",
    "AlertTitle",
    "EntityType",
    "EvidenceRole",
    "LastVerdict",
    "IncidentGrade",
]

row_counts = {
    col: Counter()
    for col in COLUMNS
    if col not in ["IncidentId", "Category", "MitreTechniques"]
}

incident_sets = {
    col: defaultdict(set)
    for col in row_counts
}

technique_counts = Counter()
technique_incidents = defaultdict(set)

total_rows = 0
all_incidents = set()

for chunk in pd.read_csv(INPUT, usecols=COLUMNS, chunksize=100_000):

    data = chunk[chunk["Category"] == "Exfiltration"]

    if data.empty:
        continue

    total_rows += len(data)
    all_incidents.update(data["IncidentId"].dropna().unique())

    for col in row_counts:
        valid = data.dropna(subset=[col])

        counts = valid[col].astype(str).value_counts()
        row_counts[col].update(counts.to_dict())

        for value, group in valid.groupby(col):
            incident_sets[col][str(value)].update(
                group["IncidentId"].dropna().unique()
            )

    for _, row in data.iterrows():
        if pd.notna(row["MitreTechniques"]):
            techniques = set(
                str(row["MitreTechniques"]).split(";")
            )

            for technique in techniques:
                technique_counts[technique] += 1
                if pd.notna(row["IncidentId"]):
                    technique_incidents[technique].add(
                        row["IncidentId"]
                    )

print("\nEXFILTRATION DATASET PROFILE")
print("Total matching records:", total_rows)
print("Unique incidents:", len(all_incidents))

for col in row_counts:
    result = pd.DataFrame([
        {
            "Value": value,
            "RecordCount": count,
            "UniqueIncidents": len(incident_sets[col][value]),
        }
        for value, count in row_counts[col].most_common(30)
    ])

    result.to_csv(
        OUTPUT_DIR / f"exfiltration_{col.lower()}.csv",
        index=False
    )

    print(f"\nTOP VALUES: {col}")
    print(result.head(15).to_string(index=False))

technique_result = pd.DataFrame([
    {
        "Technique": technique,
        "RecordCount": count,
        "UniqueIncidents": len(technique_incidents[technique]),
    }
    for technique, count in technique_counts.most_common(30)
])

technique_result.to_csv(
    OUTPUT_DIR / "exfiltration_mitre_techniques.csv",
    index=False
)

print("\nTOP MITRE TECHNIQUES")
print(technique_result.head(20).to_string(index=False))

print("\nReports saved in:", OUTPUT_DIR)
