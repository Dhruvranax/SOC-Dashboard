# Phase 4 --- Exploratory Data Analysis Report

**Project:** Microsoft SOC Dataset\
**Dataset:** `Dataset/processed/GUIDE_Test_cleaned_v2.csv`\
**Records:** 4,147,992 \| **Columns:** 46\
**Analysis period:** 2024-01-23 to 2024-06-17 (UTC)

## 1. Executive summary

Phase 4 examined incident-grade labels, alert categories, daily record
volume, MITRE ATT&CK technique IDs, entity types, evidence roles, and
encoded geographic fields.

Key findings: - `BenignPositive`: 1,752,940 records (42.26%);
`TruePositive`: 1,492,354 (35.98%); `FalsePositive`: 902,698 (21.76%). -
`InitialAccess` was the most common category: 1,952,969 records
(47.08%). The five largest categories represented approximately
88.55%. - The dataset spans 152 calendar days. The highest daily count
was 398,093 on 2024-06-04. - The four highest-volume days in the top-ten
list were 2024-06-03 through 2024-06-06. - 1,840,888 records contained
MITRE technique data (44.38%); 400 distinct technique IDs were
counted. - `Ip` and `User` were the most frequent entity types. -
`Related` evidence represented 55.17% of records; `Impacted` represented
44.83%.

These are descriptive record-level findings. They do not independently
prove successful attacks, unique incidents, compromised assets, or the
cause of an alert-volume spike.

## 2. Dataset and methodology

The cleaned CSV was used for the analysis. Large scans were processed in
chunks. Timestamp values were parsed as UTC and grouped by calendar
date. The four consecutive peak days were compared by incident grade and
category. The `MitreTechniques` field was split on semicolons; each
technique ID was counted at most once per record. Parent techniques and
sub-techniques were retained as separate IDs. Entity and evidence counts
were aggregated across the full dataset.

A 10,000- or 20,000-row sample was used for initial field inspection
where noted. Major distributions and the full entity/evidence counts
below were calculated using the full dataset or the cleaning audit
report.

## 3. Incident grade distribution

  Incident grade           Records    Percentage
  ---------------- --------------- -------------
  BenignPositive         1,752,940        42.26%
  TruePositive           1,492,354        35.98%
  FalsePositive            902,698        21.76%
  **Total**          **4,147,992**   **100.00%**

`BenignPositive` was the largest class. These are dataset label
proportions, not model precision, recall, or accuracy.

**Figure:** `reports/figures/incident_grade_distribution.png`

## 4. Security alert category distribution

  Category                 Records   Percentage
  -------------------- ----------- ------------
  InitialAccess          1,952,969       47.08%
  Exfiltration             615,284       14.83%
  SuspiciousActivity       440,093       10.61%
  CommandAndControl        357,179        8.61%
  Impact                   307,810        7.42%
  CredentialAccess         130,196        3.14%
  Execution                115,658        2.79%
  Malware                   71,593        1.73%
  Discovery                 63,633        1.53%
  Persistence               29,075        0.70%
  DefenseEvasion            21,611        0.52%
  LateralMovement           19,426        0.47%
  UnwantedSoftware           7,496        0.18%
  Collection                 6,272        0.15%
  Ransomware                 5,605        0.14%

The five largest categories accounted for approximately 88.55% of
records. Category labels do not by themselves confirm attack success.

**Figure:** `reports/figures/top_security_categories.png`

## 5. Time-based alert analysis

  Metric                     Result
  ----------------------- ---------
  Calendar days                 152
  Average daily records      27,289
  Maximum daily records     398,093
  Minimum daily records           1

### Top ten days

  Date (UTC)     Records
  ------------ ---------
  2024-06-04     398,093
  2024-06-03     391,810
  2024-06-06     381,800
  2024-06-05     334,913
  2024-06-13     300,012
  2024-06-07     299,801
  2024-06-11     297,850
  2024-06-10     278,150
  2024-06-12     271,428
  2024-06-08     211,577

The maximum daily count was approximately 14.6 times the reported daily
average. These are record counts, not necessarily unique incidents.

**Figure:** `reports/figures/daily_alert_trend.png`

## 6. Peak-day investigation: 2024-06-03 to 2024-06-06

### Incident grades

  Date           BenignPositive   FalsePositive   TruePositive     Total
  ------------ ---------------- --------------- -------------- ---------
  2024-06-03            165,663          68,990        157,157   391,810
  2024-06-04            150,778          74,528        172,787   398,093
  2024-06-05            149,626          63,632        121,655   334,913
  2024-06-06            151,189          74,807        155,804   381,800

### Top five categories per day

  Date         Category               Records
  ------------ -------------------- ---------
  2024-06-03   InitialAccess          204,792
  2024-06-03   Exfiltration            44,002
  2024-06-03   SuspiciousActivity      38,796
  2024-06-03   CommandAndControl       35,414
  2024-06-03   Malware                 18,521
  2024-06-04   InitialAccess          206,095
  2024-06-04   Exfiltration            67,091
  2024-06-04   SuspiciousActivity      43,850
  2024-06-04   CommandAndControl       37,153
  2024-06-04   CredentialAccess        11,993
  2024-06-05   InitialAccess          147,782
  2024-06-05   Exfiltration            73,949
  2024-06-05   SuspiciousActivity      40,395
  2024-06-05   CommandAndControl       28,837
  2024-06-05   CredentialAccess        12,199
  2024-06-06   InitialAccess          185,182
  2024-06-06   Exfiltration            81,372
  2024-06-06   SuspiciousActivity      41,977
  2024-06-06   CommandAndControl       31,861
  2024-06-06   CredentialAccess        12,237

`InitialAccess` led on all four days. `Exfiltration`,
`SuspiciousActivity`, and `CommandAndControl` also appeared in the top
four each day. June 4 had the highest total volume and the largest
`TruePositive` count among these four days. The grade mix varied by day.
The analysis does not establish the spike's root cause.

**Figure:** `reports/figures/peak_days_incident_grades.png`

## 7. MITRE ATT&CK technique analysis

### Coverage

  Metric                                Result
  -------------------------------- -----------
  Total records                      4,147,992
  Records with technique data        1,840,888
  Records without technique data     2,307,104
  Technique data coverage               44.38%
  Distinct technique IDs                   400

### Top 20 technique IDs

  Technique ID     Record count
  -------------- --------------
  T1078                 659,606
  T1078.004             617,374
  T1566.002             360,219
  T1566                 277,038
  T1133                 119,289
  T1110                  91,296
  T1566.001              61,600
  T1110.003              56,980
  T1110.001              56,374
  T1087                  47,866
  T1071                  41,821
  T1087.002              37,839
  T1046                  35,082
  T1204.002              26,517
  T1105                  26,411
  T1027                  25,096
  T1027.002              21,594
  T1027.005              21,591
  T1059.005              20,561
  T1030                  19,497

`T1078` and `T1078.004` were the most frequently recorded IDs. Parent
and sub-technique IDs were counted separately and can co-occur in one
record. Counts are not unique attacks or confirmed compromises.

**Figure:** `reports/figures/top_20_mitre_techniques.png`

## 8. Entity and evidence analysis

### Top 15 entity types

  Entity type           Records
  ------------------- ---------
  Ip                    929,684
  User                  831,162
  MailMessage           479,227
  Machine               348,147
  CloudLogonRequest     298,656
  Url                   294,913
  File                  290,887
  Mailbox               205,624
  Process               165,178
  MailCluster            96,901
  CloudLogonSession      94,462
  CloudApplication       94,332
  RegistryValue           6,771
  AzureResource           3,363
  RegistryKey             2,925

`Ip` and `User` were the two most common entity types and together
represented approximately 42.5% of records.

### Evidence roles

  Evidence role           Records    Percentage
  --------------- --------------- -------------
  Related               2,288,528        55.17%
  Impacted              1,859,464        44.83%
  **Total**         **4,147,992**   **100.00%**

`Related` evidence was more common than `Impacted` evidence. Evidence
role is not a severity score.

**Figures:** - `reports/figures/top_10_entity_types.png` -
`reports/figures/evidence_role_distribution.png`

## 9. Geographic identifier analysis

The geographic fields were represented as numeric IDs. No verified
ID-to-name lookup was used.

  Field           Most frequent ID     Records   Percentage of dataset
  ------------- ------------------ ----------- -----------------------
  CountryCode                  242   3,795,038                  91.49%
  State                       1445   3,851,530                  92.86%
  City                       10630   3,851,080                  92.85%

These values must not be translated into country, state, or city names
without a verified mapping.

## 10. Limitations and analyst cautions

1.  Most reported values count records, not distinct incidents, users,
    devices, or attacks.
2.  Dataset labels do not independently prove successful malicious
    activity.
3.  Sparse fields should not automatically be interpreted as evidence
    that an event or entity did not exist.
4.  MITRE technique data was present in 44.38% of records; the technique
    analysis describes that populated subset.
5.  Parent techniques and sub-techniques can co-occur and are not
    mutually exclusive.
6.  Geographic IDs were not mapped to verified names.
7.  The root cause of the June 3--6 alert-volume spike was not
    established.
8.  Sample-based inspection was used only for initial field review; the
    major distributions and full entity/evidence counts were based on
    full-dataset analysis or the audit report.

## 11. Phase 4 conclusion

Phase 4 established a descriptive baseline of the dataset, analyzed
incident-grade and category distributions, identified daily volume
peaks, investigated the June 3--6 period, counted MITRE technique IDs,
and summarized entity and evidence-role distributions. The findings
identify areas for deeper SOC investigation, especially the
concentration of `InitialAccess` records, the peak-period activity, and
frequently represented MITRE technique IDs.

**Phase 4 status:** Analysis and visualizations completed; findings
documented. Verify the report against the saved notebook and figure
files before committing or presenting it externally.

## Appendix A --- Figure inventory

Expected files in `reports/figures/`:

``` text
incident_grade_distribution.png
top_security_categories.png
daily_alert_trend.png
peak_days_incident_grades.png
top_20_mitre_techniques.png
top_10_entity_types.png
evidence_role_distribution.png
```

## Appendix B --- Reproducibility

-   Notebook: `notebooks/03_exploratory_analysis.ipynb`
-   Cleaned dataset: `Dataset/processed/GUIDE_Test_cleaned_v2.csv`
-   Cleaning audit report: `Dataset/processed/cleaning_report_v2.json`
