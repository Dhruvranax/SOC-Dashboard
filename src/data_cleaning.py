
import json
import pandas as pd

from pathlib import Path


# ============================================================
# 1. PROJECT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_PATH = (
    PROJECT_ROOT
    / "Dataset"
    / "raw"
    / "GUIDE_Test.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "Dataset"
    / "processed"
)

CLEAN_PATH = OUTPUT_DIR / "GUIDE_Test_cleaned_v2.csv"
TEMP_PATH = OUTPUT_DIR / "GUIDE_Test_cleaned_v2.tmp.csv"

REPORT_PATH = OUTPUT_DIR / "cleaning_report_v2.json"
TEMP_REPORT_PATH = OUTPUT_DIR / "cleaning_report_v2.tmp.json"

CHUNK_SIZE = 100_000


# ============================================================
# 2. DATA CLEANING FUNCTION
# ============================================================

def clean_chunk(chunk):
    """
    Clean one chunk of the dataset.

    Operations:
    - Remove leading and trailing whitespace.
    - Convert empty strings into missing values.
    - Standardize valid timestamps to UTC.
    - Preserve invalid original timestamp values.
    """

    # Clean text columns
    text_columns = chunk.select_dtypes(
        include=["object", "string"]
    ).columns

    for col in text_columns:
        chunk[col] = chunk[col].str.strip()
        chunk[col] = chunk[col].replace("", pd.NA)

    # Preserve original timestamp values
    original_timestamp = chunk["Timestamp"].copy()

    # Parse timestamps as UTC
    parsed_timestamp = pd.to_datetime(
        chunk["Timestamp"],
        errors="coerce",
        utc=True
    )

    # Count invalid or missing timestamps
    invalid_count = int(parsed_timestamp.isna().sum())

    # Standardize valid timestamps
    standardized_timestamp = parsed_timestamp.dt.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # Keep original values when timestamp parsing fails
    chunk["Timestamp"] = standardized_timestamp.fillna(
        original_timestamp
    )

    return chunk, invalid_count, parsed_timestamp


# ============================================================
# 3. HELPER FUNCTION FOR CATEGORY STATISTICS
# ============================================================

def update_value_counts(target, series):
    """
    Update a dictionary with value counts from a Series.
    Missing values are recorded as <MISSING>.
    """

    counts = series.value_counts(dropna=False)

    for label, count in counts.items():

        key = (
            "<MISSING>"
            if pd.isna(label)
            else str(label)
        )

        target[key] = target.get(key, 0) + int(count)


# ============================================================
# 4. MAIN CLEANING PIPELINE
# ============================================================

def run_cleaning():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Check source dataset
    if not RAW_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {RAW_PATH}"
        )

    # Protect original dataset
    if RAW_PATH.resolve() == CLEAN_PATH.resolve():
        raise ValueError(
            "Input and output files must be different."
        )

    # Remove stale temporary files from previous attempts
    for path in [TEMP_PATH, TEMP_REPORT_PATH]:

        if path.exists():
            path.unlink()

    # Initialize audit metrics
    metrics = {
        "source_file": str(RAW_PATH),
        "output_file": str(CLEAN_PATH),
        "chunk_size": CHUNK_SIZE,
        "total_rows": 0,
        "total_columns": 0,
        "invalid_timestamps": 0,
        "timestamp_min_utc": None,
        "timestamp_max_utc": None,
        "missing_values": {},
        "missing_value_report": {},
        "incident_grades": {},
        "categories": {},
        "columns": []
    }

    first_chunk = True

    print("=" * 60)
    print("MICROSOFT SOC DATASET - CLEANING PIPELINE")
    print("=" * 60)

    print("Source:", RAW_PATH)
    print("Output:", CLEAN_PATH)
    print("Chunk size:", CHUNK_SIZE)

    try:

        # Read dataset in chunks
        for chunk in pd.read_csv(
            RAW_PATH,
            chunksize=CHUNK_SIZE,
            dtype="string",
            low_memory=False
        ):

            # Capture schema from first chunk
            if first_chunk:

                metrics["total_columns"] = len(chunk.columns)
                metrics["columns"] = chunk.columns.tolist()

                # Validate required columns
                required_columns = [
                    "Timestamp",
                    "IncidentGrade",
                    "Category"
                ]

                missing_columns = [
                    col
                    for col in required_columns
                    if col not in chunk.columns
                ]

                if missing_columns:
                    raise ValueError(
                        f"Required columns missing: {missing_columns}"
                    )

            # ------------------------------------------------
            # Clean current chunk
            # ------------------------------------------------

            chunk, invalid_count, parsed_ts = clean_chunk(chunk)

            metrics["invalid_timestamps"] += invalid_count

            # ------------------------------------------------
            # Timestamp range statistics
            # ------------------------------------------------

            valid_ts = parsed_ts.dropna()

            if not valid_ts.empty:

                batch_min = valid_ts.min()
                batch_max = valid_ts.max()

                if (
                    metrics["timestamp_min_utc"] is None
                    or batch_min < pd.Timestamp(
                        metrics["timestamp_min_utc"]
                    )
                ):
                    metrics["timestamp_min_utc"] = (
                        batch_min.isoformat()
                    )

                if (
                    metrics["timestamp_max_utc"] is None
                    or batch_max > pd.Timestamp(
                        metrics["timestamp_max_utc"]
                    )
                ):
                    metrics["timestamp_max_utc"] = (
                        batch_max.isoformat()
                    )

            # ------------------------------------------------
            # Missing-value statistics
            # ------------------------------------------------

            missing_counts = chunk.isna().sum()

            for col, count in missing_counts.items():

                metrics["missing_values"][col] = (
                    metrics["missing_values"].get(col, 0)
                    + int(count)
                )

            # ------------------------------------------------
            # Incident grade statistics
            # ------------------------------------------------

            update_value_counts(
                metrics["incident_grades"],
                chunk["IncidentGrade"]
            )

            # ------------------------------------------------
            # Security category statistics
            # ------------------------------------------------

            update_value_counts(
                metrics["categories"],
                chunk["Category"]
            )

            # ------------------------------------------------
            # Update total row count
            # ------------------------------------------------

            metrics["total_rows"] += len(chunk)

            # ------------------------------------------------
            # Write chunk to temporary CSV
            # ------------------------------------------------

            chunk.to_csv(
                TEMP_PATH,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False,
                na_rep=""
            )

            first_chunk = False

            print(
                f"Processed {metrics['total_rows']:,} records"
            )

        # Ensure that the dataset was not empty
        if metrics["total_rows"] == 0:
            raise ValueError(
                "The source dataset contains no data rows."
            )

        # ----------------------------------------------------
        # Calculate missing-value percentages
        # ----------------------------------------------------

        for col, count in metrics["missing_values"].items():

            percentage = (
                count / metrics["total_rows"]
            ) * 100

            metrics["missing_value_report"][col] = {
                "count": count,
                "percentage": round(percentage, 2)
            }

        # ----------------------------------------------------
        # Save audit report to temporary JSON
        # ----------------------------------------------------

        with open(
            TEMP_REPORT_PATH,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                metrics,
                file,
                indent=4,
                ensure_ascii=False
            )

        # ----------------------------------------------------
        # Publish final files only after successful processing
        # ----------------------------------------------------

        TEMP_PATH.replace(CLEAN_PATH)
        TEMP_REPORT_PATH.replace(REPORT_PATH)

    except BaseException:

        # Remove incomplete temporary outputs
        for path in [TEMP_PATH, TEMP_REPORT_PATH]:

            if path.exists():
                path.unlink()

        raise

    # ========================================================
    # 5. FINAL SUMMARY
    # ========================================================

    print("\n" + "=" * 60)
    print("CLEANING COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print(f"Total records: {metrics['total_rows']:,}")
    print(f"Total columns: {metrics['total_columns']}")
    print(
        f"Invalid timestamps: "
        f"{metrics['invalid_timestamps']:,}"
    )

    print("\nOutput files:")
    print("Cleaned dataset:", CLEAN_PATH)
    print("Audit report:", REPORT_PATH)

    print("=" * 60)

    return metrics


# ============================================================
# 6. SCRIPT EXECUTION
# ============================================================

if __name__ == "__main__":

    run_cleaning()
