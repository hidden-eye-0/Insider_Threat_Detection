"""Data ingestion, validation, normalisation and quality reporting."""
from __future__ import annotations

import hashlib
import io
from typing import Any

import pandas as pd

from .config import (CANONICAL_EVENT_TYPES, EVENT_COLUMNS, EVENT_TYPE_ALIASES, MAX_UPLOAD_MB,
                      MAX_UPLOAD_ROWS, OPTIONAL_COLUMNS, REQUIRED_COLUMNS)

HASH_FIELDS = EVENT_COLUMNS  # fields that make up the original record fingerprint


class IngestError(ValueError):
    """Raised when an input file cannot be used at all."""


def record_hash(row: dict[str, Any]) -> str:
    """SHA-256 over the canonical string form of the original record fields."""
    parts = []
    for f in HASH_FIELDS:
        v = row.get(f)
        if v is None or v is pd.NA or v is pd.NaT or (isinstance(v, float) and pd.isna(v)):
            v = ""
        parts.append(f"{f}={v}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def read_csv_safely(data: bytes | str | io.IOBase) -> pd.DataFrame:
    """Read an uploaded CSV with size/row limits. ``data`` is bytes, a path, or a file-like."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
            raise IngestError(f"File is larger than the {MAX_UPLOAD_MB} MB limit.")
        buf: Any = io.BytesIO(data)
    else:
        buf = data
    try:
        df = pd.read_csv(buf, dtype=str, keep_default_na=False, na_values=[""], nrows=MAX_UPLOAD_ROWS + 1)
    except Exception as exc:  # pandas raises several parser error types
        raise IngestError(f"Could not parse file as CSV: {exc}") from exc
    if len(df) > MAX_UPLOAD_ROWS:
        raise IngestError(f"File has more than {MAX_UPLOAD_ROWS:,} rows.")
    return df


def normalise_event_type(value: Any) -> str | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    v = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    return EVENT_TYPE_ALIASES.get(v, v)


def validate_and_clean(df_raw: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Validate, normalise and de-duplicate raw events.

    Returns ``(clean_df, report)``. ``report`` lists missing columns, rejected rows with
    reasons, duplicates, missing-value counts and unsupported event types.
    Raises :class:`IngestError` if required columns are absent.
    """
    df = df_raw.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise IngestError(
            f"Missing required column(s): {', '.join(missing)}. Required: {', '.join(REQUIRED_COLUMNS)}. "
            f"Optional: {', '.join(OPTIONAL_COLUMNS)}.")
    absent_optional = [c for c in OPTIONAL_COLUMNS if c not in df.columns]
    for c in absent_optional:
        df[c] = pd.NA
    df = df[EVENT_COLUMNS].copy()
    n_in = len(df)
    for c in df.columns:
        df[c] = df[c].astype("string").str.strip()
        df.loc[df[c] == "", c] = pd.NA

    rejected: list[dict] = []

    def reject(mask: pd.Series, reason: str) -> None:
        nonlocal df
        for idx in df.index[mask]:
            rejected.append({"row": int(idx) + 2, "event_id": df.at[idx, "event_id"], "reason": reason})
        df = df[~mask]

    reject(df["event_id"].isna(), "missing event_id")
    reject(df["employee_id"].isna(), "missing employee_id")
    reject(df["event_type"].isna(), "missing event_type")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    reject(ts.isna(), "unparseable timestamp")
    df["timestamp"] = ts[~ts.isna()].dt.tz_convert("UTC").dt.tz_localize(None)

    df["event_type"] = df["event_type"].map(normalise_event_type)
    for c in ("volume_mb", "record_count"):
        num = pd.to_numeric(df[c].astype(object), errors="coerce").astype("float64")
        bad = (df[c].notna() & num.isna()).fillna(False).astype(bool)
        reject(bad, f"non-numeric {c}")
        df[c] = num[~bad]
    reject(((df["volume_mb"] < 0) | (df["record_count"] < 0)).fillna(False), "negative volume/record_count")

    # exact duplicates (identical in every field) -> keep first
    dup_exact = df.duplicated(keep="first")
    n_exact = int(dup_exact.sum())
    df = df[~dup_exact]
    # conflicting duplicates (same event_id, different content) -> reject later copies
    dup_id = df.duplicated(subset=["event_id"], keep="first")
    reject(dup_id, "duplicate event_id with conflicting content")

    df["outcome"] = df["outcome"].str.lower()
    df["role"] = df["role"].fillna("unknown")
    df["source_ref"] = df["source_ref"].fillna(pd.Series([f"upload:row{int(i) + 2}" for i in df.index], index=df.index))
    df = df.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    df["record_hash"] = [record_hash(r) for r in df[EVENT_COLUMNS].to_dict("records")]

    unknown_types = sorted(set(df["event_type"].dropna()) - set(CANONICAL_EVENT_TYPES))
    missing_counts = {c: int(df[c].isna().sum()) for c in OPTIONAL_COLUMNS}
    report = {
        "rows_in": n_in, "rows_accepted": len(df), "rows_rejected": len(rejected),
        "exact_duplicates_removed": n_exact,
        "rejected_rows": rejected[:200],
        "absent_optional_columns": absent_optional,
        "missing_value_counts": missing_counts,
        "unrecognised_event_types": unknown_types,
        "employees": int(df["employee_id"].nunique()),
        "time_range": [str(df["timestamp"].min()), str(df["timestamp"].max())] if len(df) else [None, None],
        "limitations": _limitations(absent_optional, df),
    }
    return df, report


def _limitations(absent: list[str], df: pd.DataFrame) -> list[str]:
    notes = []
    mapping = {
        "customer_id": "customer_id absent/empty: account-access rules R03/R04 are skipped.",
        "volume_mb": "volume_mb absent/empty: download-size rule R07 is skipped.",
        "device_id": "device_id absent/empty: device novelty (R09) is skipped.",
        "location": "location absent/empty: location novelty (R09) is skipped.",
        "resource": "resource absent/empty: resource rules R05/R10 are skipped.",
    }
    for col, msg in mapping.items():
        if col in absent or (len(df) and df[col].isna().all()):
            notes.append(msg)
    if len(df) and df["context_tag"].isna().all():
        notes.append("No context_tag values: approved-activity context discount cannot be applied.")
    return notes
