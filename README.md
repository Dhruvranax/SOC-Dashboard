# Microsoft SOC Threat Detection & Incident Analysis

A Python-based Security Operations Center (SOC) analytics project that processes Microsoft security incident data, applies rule-based threat detection, generates SOC alerts, and produces structured incident investigation reports.

## Project Overview

This project demonstrates an end-to-end security analytics workflow using the Microsoft GUIDE dataset.

The objective is to simulate selected SOC analyst activities:

- Understand and prepare security incident data.
- Explore incident trends, categories, entities, and MITRE ATT&CK techniques.
- Develop rule-based threat detection logic.
- Evaluate detection results against available incident labels.
- Generate structured SOC alerts.
- Produce incident investigation reports.

**Project type:** Cybersecurity / SOC Analytics  
**Language:** Python  
**Environment:** Jupyter Notebook, VS Code  
**Dataset:** Microsoft GUIDE Test dataset

## Architecture

```text
Microsoft GUIDE Dataset
          |
          v
    Data Understanding
          |
          v
      Data Cleaning
          |
          v
 Exploratory Data Analysis
          |
          v
   Threat Detection Rules
          |
          v
 Detection Evaluation
          |
          v
    SOC Alert Generation
          |
          v
 Incident Report Generation
          |
          v
       Final Reports
```

## Technology Stack

- Python
- Pandas and NumPy
- Matplotlib and Seaborn
- Jupyter Notebook
- JSON, CSV, and Markdown
- MITRE ATT&CK framework

## Project Structure

```text
Microsoft-SOC-Project/
├── Dataset/
│   ├── raw/
│   └── processed/
├── notebooks/
│   ├── 01_data_understanding.ipynb
│   ├── 02_data_cleaning.ipynb
│   ├── 03_exploratory_analysis.ipynb
│   └── 04_threat_detection.ipynb
├── src/
│   ├── data_cleaning.py
│   ├── threat_detection.py
│   ├── evaluate_detection.py
│   ├── soc_alert_generator.py
│   ├── incident_report_generator.py
│   └── ...
├── reports/
│   ├── figures/
│   ├── soc_alerts/
│   ├── incident_reports/
│   ├── exfiltration_investigation/
│   ├── Phase_4_EDA_Report.md
│   └── Phase_5_Threat_Detection_Report.md
├── dashboard/
├── requirements.txt
└── README.md
```

## Implementation Phases

| Phase | Work |
|---|---|
| 1 | Dataset understanding |
| 2 | Data quality analysis |
| 3 | Data cleaning |
| 4 | Exploratory data analysis |
| 5 | Rule-based threat detection |
| 6 | SOC alert generation |
| 7 | Incident report generation |
| 8 | End-to-end validation and repository preparation |

## Dataset Analysis

The cleaned dataset contains:

- 4,147,992 records
- 46 columns
- Data spanning November 22, 2023 to June 17, 2024
- Zero invalid timestamps after cleaning

The EDA examined incident grades, security categories, daily activity, MITRE ATT&CK techniques, entity types, and evidence roles.

## Threat Detection

The detection engine processes the cleaned dataset in chunks and applies category-based and MITRE ATT&CK-related rules.

Detected incidents are aggregated and assigned heuristic risk scores.

Severity levels:

- Critical
- High
- Medium
- Low

The risk score is a prioritization score, not a probability of compromise.

The detection logic does not use `IncidentGrade` as an input feature. Incident labels are reserved for evaluation.

## SOC Alert Generation

The alert-generation pipeline produces:

- Structured CSV alerts
- JSONL alerts
- Alert-generation summary
- Risk assessment
- Incident timeline
- Detection summary
- Affected entities
- Source references
- Analyst investigation guidance
- Limitations

**Alerts generated:** 193,613

## Incident Reports

The report-generation pipeline produces:

- A summary CSV covering 193,613 detected incidents.
- 10 detailed Markdown incident reports for representative incidents.

The reports are intended to support analyst investigation. They do not establish that an incident represents a confirmed attack or data loss.

## Detection Evaluation

Evaluation on the consistent-label subset produced the following results:

| Metric | Result |
|---|---:|
| Precision | 16.22% |
| Recall | 63.75% |
| F1-score | 25.86% |
| Accuracy | 26.22% |
| Detection coverage | 79.33% |
| Baseline positive prevalence | 20.18% |

### Important Limitations

- Precision is below the baseline positive prevalence.
- The dataset contains incidents with conflicting labels.
- Risk scores do not reliably distinguish all incident grades.
- Some alert-title identifiers do not have an available name mapping.
- The results do not establish production readiness or generalization to unseen environments.
- A full temporal holdout evaluation of the detection engine has not been established.

These findings identify areas for future rule refinement and validation.

## Installation

Clone the repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Microsoft-SOC-Project
```

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Execution

Run the pipeline scripts from the project root in the appropriate order:

```powershell
python src/data_cleaning.py
python src/threat_detection.py
python src/evaluate_detection.py
python src/soc_alert_generator.py
python src/incident_report_generator.py
```

The raw Microsoft GUIDE dataset is not included in this repository. Obtain the dataset separately and place it in `Dataset/raw/` before running the pipeline.

The notebooks provide additional analysis and visualization.

## Future Improvements

- Build an interactive SOC dashboard.
- Improve detection precision through rule refinement.
- Add temporal holdout evaluation.
- Investigate false positives and conflicting labels.
- Add analyst-oriented filtering and alert prioritization.
- Improve automated testing and documentation.

## Disclaimer

This is an educational cybersecurity portfolio project. Its rule-based detections are experimental and should not be treated as a production security monitoring or incident response system.