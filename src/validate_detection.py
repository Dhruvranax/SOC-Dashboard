import pandas as pd

path = "reports/incident_reports/incident_detection_summary.csv"

df = pd.read_csv(path)

print("Total incidents:", len(df))
print("Duplicate incident IDs:", df["IncidentId"].duplicated().sum())
print("Missing incident IDs:", df["IncidentId"].isna().sum())

print("\nRisk score statistics:")
print(df["RiskScore"].describe())

print("\nSeverity distribution:")
print(df["Severity"].value_counts())

print("\nTop 10 highest-risk incidents:")
print(
    df[
        [
            "IncidentId",
            "Severity",
            "RiskScore",
            "MatchedRecords",
            "DetectionRules",
            "MITRETechniques",
        ]
    ].head(10).to_string(index=False)
)

print("\nRisk score above 100:", (df["RiskScore"] > 100).sum())