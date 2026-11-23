from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
st.set_page_config(
    page_title="SOC | Incident Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PIPELINE_PATH = SRC / "upload_pipeline.py"

NAVY = "#101827"
PANEL = "#172235"
BORDER = "#2B3A50"
TEXT = "#E7EDF5"
MUTED = "#91A0B5"
COLORS = {
    "Critical": "#E05A5A",
    "High": "#E3A548",
    "Medium": "#4D9DE0",
    "Low": "#6BBA91",
}

st.markdown("""
<style>
.stApp { background: #101827; color: #E7EDF5; }
[data-testid="stSidebar"] { background: #141F2E; border-right: 1px solid #2B3A50; }
[data-testid="stSidebar"] * { color: #DCE5F1; }
.block-container { max-width: 1600px; padding-top: 1.35rem; padding-bottom: 2rem; }
h1,h2,h3 { color: #F1F5F9 !important; letter-spacing: -.25px; }
p, label { color: #C1CDDC; }
[data-testid="stMetric"] { background: #172235; border: 1px solid #2B3A50; border-radius: 8px; padding: 14px 16px; }
[data-testid="stMetricLabel"] { color: #91A0B5 !important; font-size: 11px; letter-spacing: .7px; }
[data-testid="stMetricValue"] { color: #F1F5F9 !important; font-size: 26px; font-weight: 650; }
div[data-baseweb="select"] > div, div[data-baseweb="input"] > div { background: #172235; border-color: #35445A; }
.stButton button, .stDownloadButton button { border-radius: 6px; font-weight: 600; }
[data-testid="stDataFrame"] { border: 1px solid #2B3A50; border-radius: 7px; }
hr { border-color: #2B3A50 !important; }
.soc-header { background: #172235; border: 1px solid #2B3A50; border-radius: 9px; padding: 18px 22px; margin-bottom: 18px; }
.soc-eyebrow { color: #91A0B5; font-size: 10px; letter-spacing: 1.6px; font-weight: 700; }
.soc-title { color: #F1F5F9; font-size: 25px; font-weight: 750; margin-top: 5px; }
.soc-subtitle { color: #91A0B5; font-size: 12px; margin-top: 4px; }
.muted { color: #91A0B5; font-size: 12px; }
</style>
""", unsafe_allow_html=True)


def header(title: str, subtitle: str):
    st.markdown(
        f'<div class="soc-header"><div class="soc-eyebrow">SECURITY OPERATIONS / THREAT MONITORING</div>'
        f'<div class="soc-title">{title}</div><div class="soc-subtitle">{subtitle}</div></div>',
        unsafe_allow_html=True,
    )


def load_pipeline():
    import importlib.util
    spec = importlib.util.spec_from_file_location("soc_upload_pipeline", PIPELINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load upload pipeline: {PIPELINE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_alerts(path: str) -> pd.DataFrame:
    frame = pd.read_csv(path, low_memory=False)
    for col in ("FirstSeen", "LastSeen"):
        if col in frame:
            frame[col] = pd.to_datetime(frame[col], utc=True, errors="coerce")
    for col in ("RiskScore", "MatchedRecords", "UniqueAlerts"):
        if col in frame:
            frame[col] = pd.to_numeric(frame[col], errors="coerce")
    return frame


def show_upload_page():
    header("Dataset Ingestion", "Upload Microsoft GUIDE-compatible telemetry and execute the detection pipeline.")
    st.markdown("### 01 / Select source data")
    st.caption("Supported input: UTF-8 CSV containing IncidentId, Category, and MitreTechniques.")
    upload = st.file_uploader("Upload security telemetry CSV", type=["csv"], accept_multiple_files=False)

    if upload is None:
        st.info("Select a CSV file to begin schema validation.")
        with st.expander("Required input schema"):
            st.code("IncidentId, Category, MitreTechniques\n1001, InitialAccess, T1078\n1002, Exfiltration, T1041", language="csv")
            st.caption("Timestamp is optional. IncidentGrade is not used by the detection rules.")
        return

    # Store a stable copy for this Streamlit session.
    signature = (upload.name, upload.size)
    if st.session_state.get("upload_signature") != signature:
        workdir = Path(tempfile.mkdtemp(prefix="soc_upload_"))
        input_path = workdir / Path(upload.name).name
        with input_path.open("wb") as handle:
            handle.write(upload.getbuffer())
        st.session_state["upload_signature"] = signature
        st.session_state["upload_path"] = str(input_path)
        st.session_state["workdir"] = str(workdir)
        st.session_state.pop("pipeline_result", None)
        st.session_state.pop("alerts_frame", None)

    input_path = Path(st.session_state["upload_path"])
    st.markdown("### 02 / Schema validation")
    c1, c2, c3 = st.columns(3)
    c1.metric("FILE", upload.name)
    c2.metric("SIZE", f"{upload.size / (1024 * 1024):.1f} MB")
    c3.metric("FORMAT", "CSV")

    try:
        pipeline = load_pipeline()
        schema = pipeline.inspect_csv(input_path)
        st.success("Schema validation passed. Required detection fields are present.")
        st.write(f"**Columns detected:** {schema['column_count']}")
        st.write("**Required fields:** " + ", ".join(schema["required_columns"]))
        st.write("**Timestamp field:** " + ("Available" if schema["timestamp_available"] else "Not present (timeline may be limited)"))
        with st.expander("View detected columns"):
            st.write(schema["columns"])
    except Exception as exc:
        st.error(f"Schema validation failed: {exc}")
        st.warning("Upload a compatible Microsoft GUIDE CSV. Analysis is disabled until validation passes.")
        return

    st.markdown("### 03 / Execute analysis")
    st.caption("Processing runs in chunks. Results are isolated to this upload session and do not overwrite the project's existing reports.")
    if st.button("Run SOC Analysis", type="primary", use_container_width=True):
        progress = st.progress(0, text="Preparing analysis...")
        status = st.empty()

        def update_progress(stage: str, rows: int):
            labels = {
                "normalizing": "Normalizing uploaded records",
                "detecting": "Applying rule-based detections",
                "generating_alerts": "Generating SOC alerts",
                "complete": "Analysis complete",
            }
            values = {
                "normalizing": 0.25,
                "detecting": 0.55,
                "generating_alerts": 0.85,
                "complete": 1.0,
            }
            progress.progress(values.get(stage, 0.1), text=labels.get(stage, stage))
            if rows:
                status.caption(f"{labels.get(stage, stage)} · {rows:,} records")

        try:
            result = pipeline.run_upload_pipeline(
                csv_path=input_path,
                output_dir=Path(st.session_state["workdir"]) / "results",
                project_root=ROOT,
                progress_callback=update_progress,
            )
            st.session_state["pipeline_result"] = result
            st.session_state["alerts_frame"] = read_alerts(result["alerts_csv"])
            progress.progress(1.0, text="Analysis complete")
            st.success("SOC analysis completed. Open the Incident Dashboard to investigate the generated alerts.")
        except Exception as exc:
            progress.empty()
            st.error(f"Analysis failed: {exc}")
            st.exception(exc)

    result = st.session_state.get("pipeline_result")
    if result:
        st.divider()
        st.markdown("### Latest run")
        a, b, c, d = st.columns(4)
        a.metric("ROWS PROCESSED", f"{result['rows_processed']:,}")
        b.metric("MATCHED ROWS", f"{result['matched_rows']:,}")
        c.metric("INCIDENTS DETECTED", f"{result['incidents_detected']:,}")
        d.metric("SOC ALERTS", f"{result['alerts_generated']:,}")
        st.caption(f"Invalid timestamps: {result['invalid_timestamps']:,} · Detection: {result['detection_type']}")


def show_dashboard():
    result = st.session_state.get("pipeline_result")
    if not result:
        header("Incident Dashboard", "No uploaded dataset has been analyzed in this session.")
        st.info("Go to Dataset Ingestion, upload a compatible CSV, and run SOC Analysis. The dashboard will then display those newly generated alerts.")
        return

    alerts = st.session_state.get("alerts_frame")
    if alerts is None or alerts.empty:
        st.warning("The current run did not generate any SOC alerts.")
        return

    header("Security Incident Command Center", f"Analysis results · {result['input_file']} · Rule-based detection")
    st.caption("All alerts require analyst review. Risk scores are heuristic prioritization scores, not probabilities of compromise.")

    st.sidebar.markdown("## SOC CONTROL")
    st.sidebar.caption("CURRENT ANALYSIS")
    st.sidebar.code(result["input_file"])
    st.sidebar.caption(f"{len(alerts):,} generated alerts")

    severity_values = [s for s in ["Critical", "High", "Medium", "Low"] if s in alerts["Severity"].dropna().unique()]
    selected_severity = st.sidebar.multiselect("Severity", severity_values, default=severity_values)
    min_risk = st.sidebar.slider("Minimum risk score", 0, 100, 0)
    search = st.sidebar.text_input("Search alert / incident ID", placeholder="SOC-1001")

    dates = alerts["FirstSeen"].dropna() if "FirstSeen" in alerts else pd.Series(dtype="datetime64[ns, UTC]")
    if not dates.empty:
        min_date, max_date = dates.min().date(), dates.max().date()
        date_range = st.sidebar.date_input("First seen (UTC)", value=(min_date, max_date), min_value=min_date, max_value=max_date)
    else:
        date_range = None

    filtered = alerts[alerts["Severity"].isin(selected_severity) & (alerts["RiskScore"].fillna(0) >= min_risk)].copy()
    if date_range and len(date_range) == 2 and "FirstSeen" in filtered:
        filtered = filtered[filtered["FirstSeen"].dt.date.between(date_range[0], date_range[1])]
    if search.strip():
        q = search.strip().lower()
        filtered = filtered[
            filtered["AlertID"].astype(str).str.lower().str.contains(q, na=False)
            | filtered["IncidentID"].astype(str).str.lower().str.contains(q, na=False)
        ]

    total = len(filtered)
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("TOTAL ALERTS", f"{total:,}")
    for col, severity in zip((k2, k3, k4), ("Critical", "High", "Medium")):
        col.metric(severity.upper(), f"{int((filtered['Severity'] == severity).sum()):,}")
    avg = filtered["RiskScore"].mean()
    k5.metric("AVG RISK SCORE", f"{avg:.1f}" if pd.notna(avg) else "N/A")

    if filtered.empty:
        st.warning("No alerts match the current filters.")
        return

    st.divider()
    st.markdown("### Incident monitoring")
    left, right = st.columns(2)
    with left:
        severity_data = filtered["Severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).rename_axis("Severity").reset_index(name="Alerts")
        fig = px.bar(severity_data, x="Severity", y="Alerts", color="Severity", color_discrete_map=COLORS)
        fig.update_layout(paper_bgcolor=PANEL, plot_bgcolor=PANEL, font_color=TEXT, showlegend=False, height=300, margin=dict(l=10,r=10,t=20,b=10))
        st.plotly_chart(fig, use_container_width=True)
    with right:
        timeline = filtered.dropna(subset=["FirstSeen"]).copy()
        if not timeline.empty:
            timeline["Date"] = timeline["FirstSeen"].dt.floor("D")
            daily = timeline.groupby(["Date", "Severity"]).size().reset_index(name="Alerts")
            fig = px.line(daily, x="Date", y="Alerts", color="Severity", color_discrete_map=COLORS)
            fig.update_layout(paper_bgcolor=PANEL, plot_bgcolor=PANEL, font_color=TEXT, height=300, margin=dict(l=10,r=10,t=20,b=10), xaxis_title="UTC date")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No valid timestamps were available for a timeline.")

    st.divider()
    st.markdown("### Incident queue")
    queue = filtered.sort_values(["RiskScore", "FirstSeen"], ascending=[False, False], na_position="last")
    columns = [c for c in ["AlertID", "IncidentID", "Severity", "RiskScore", "MatchedRecords", "FirstSeen", "Disposition"] if c in queue.columns]
    st.dataframe(queue[columns].head(300), use_container_width=True, hide_index=True, height=390)
    st.caption(f"Showing {min(len(queue), 300):,} of {len(queue):,} filtered alerts.")
    st.download_button("Export filtered alerts", queue.to_csv(index=False).encode("utf-8"), "soc_alerts_filtered.csv", "text/csv")

    st.divider()
    st.markdown("### Analyst investigation")
    options = queue["AlertID"].dropna().astype(str).tolist()
    selected = st.selectbox("Select alert", options)
    incident = queue[queue["AlertID"].astype(str) == selected].iloc[0]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("ALERT ID", str(incident["AlertID"]))
    m2.metric("SEVERITY", str(incident["Severity"]))
    m3.metric("RISK SCORE", f"{incident['RiskScore']:.0f}")
    m4.metric("INCIDENT ID", str(incident["IncidentID"]))

    overview, evidence, entities, actions = st.tabs(["Overview", "Detection evidence", "Entities & timeline", "Analyst actions"])
    with overview:
        x, y = st.columns(2)
        x.write("**Disposition**")
        x.write(incident.get("Disposition", "Pending analyst review"))
        x.write("**Matched records**")
        x.write(incident.get("MatchedRecords", "N/A"))
        y.write("**First seen (UTC)**")
        y.write(str(incident.get("FirstSeen", "N/A")))
        y.write("**Last seen (UTC)**")
        y.write(str(incident.get("LastSeen", "N/A")))
    with evidence:
        for label in ["DetectionRules", "Categories", "MITRETechniques"]:
            st.markdown(f"**{label}**")
            st.write(incident.get(label, "Not available"))
    with entities:
        for label in ["EntityTypes", "EvidenceRoles", "AlertTitleIDs", "DetectorIDs"]:
            st.markdown(f"**{label}**")
            st.write(incident.get(label, "Not available"))
    with actions:
        st.markdown("**Recommended analyst actions**")
        for item in str(incident.get("RecommendedActions", "")).split("|"):
            if item.strip():
                st.markdown(f"- {item.strip()}")
        st.info(str(incident.get("Disposition", "Pending analyst review")))

    st.divider()
    st.markdown("### Detection intelligence")
    t1, t2, t3 = st.tabs(["Detection rules", "Categories", "MITRE ATT&CK"])
    for tab, field, label in [
        (t1, "DetectionRules", "Detection rule"),
        (t2, "Categories", "Category"),
        (t3, "MITRETechniques", "Technique"),
    ]:
        with tab:
            values = alerts[field].dropna().astype(str).str.split(";").explode().str.strip()
            values = values[(values != "") & (values.str.lower() != "nan")]
            counts = values.value_counts().head(15).rename_axis(label).reset_index(name="Alert count")
            if not counts.empty:
                fig = px.bar(counts.sort_values("Alert count"), x="Alert count", y=label, orientation="h")
                fig.update_layout(paper_bgcolor=PANEL, plot_bgcolor=PANEL, font_color=TEXT, height=430)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.caption("No values available for this field.")

    st.divider()
    st.markdown("### Run metadata")
    st.json({
        "input_file": result["input_file"],
        "rows_processed": result["rows_processed"],
        "matched_rows": result["matched_rows"],
        "incidents_detected": result["incidents_detected"],
        "alerts_generated": result["alerts_generated"],
        "invalid_timestamps": result["invalid_timestamps"],
        "detection_type": result["detection_type"],
        "score_interpretation": result["score_interpretation"],
    })


# ------------------------------------------------------------
# Navigation
# ------------------------------------------------------------
st.sidebar.markdown("## NAVIGATION")
page = st.sidebar.radio("Workspace", ["Dataset Ingestion", "Incident Dashboard"], label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.caption("SUPPORTED SOURCE")
st.sidebar.caption("Microsoft GUIDE-compatible CSV")
st.sidebar.caption("No machine-learning model training is performed.")

if not PIPELINE_PATH.exists():
    st.error(f"Upload pipeline not found: {PIPELINE_PATH}. Place upload_pipeline.py in src/.")
    st.stop()

if page == "Dataset Ingestion":
    show_upload_page()
else:
    show_dashboard()
