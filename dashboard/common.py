"""Shared dashboard data access (cached on workspace file mtime) and small helpers."""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from insider import db, forensics

PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"]


def db_path() -> Path:
    return db.workspace_path(db.get_active_workspace())


def _mtime(path: Path) -> float:
    return path.stat().st_mtime if path.exists() else 0.0


def connect():
    return db.connect(db_path())


@st.cache_data(show_spinner=False)
def _q(path: str, mtime: float, sql: str, params: tuple = ()) -> pd.DataFrame:
    con = db.connect(path)
    try:
        return pd.read_sql_query(sql, con, params=params)
    finally:
        con.close()


def query(sql: str, params: tuple = ()) -> pd.DataFrame:
    p = db_path()
    return _q(str(p), _mtime(p), sql, params)


@st.cache_data(show_spinner=False)
def _j(path: str, mtime: float, name: str):
    con = db.connect(path)
    try:
        return db.get_json(con, name)
    finally:
        con.close()


def json_store(name: str):
    p = db_path()
    return _j(str(p), _mtime(p), name)


@st.cache_data(show_spinner=False)
def _alerts(path: str, mtime: float) -> pd.DataFrame:
    con = db.connect(path)
    try:
        df = forensics.alerts_df(con)
    finally:
        con.close()
    df["ts_detect"] = pd.to_datetime(df["ts_detect"])
    return df


def alerts() -> pd.DataFrame:
    p = db_path()
    return _alerts(str(p), _mtime(p))


def has_data() -> bool:
    return not query("SELECT 1 FROM events LIMIT 1").empty


def flash(message: str, icon: str = ":material/check_circle:") -> None:
    """Queue a toast to show after the next rerun."""
    st.session_state.setdefault("_flash", []).append((message, icon))
