"""Central configuration: paths, rule thresholds, ML settings, risk weights.

All detection thresholds live here (or in an optional JSON override file at
``config/detection_config.json``) so analysts can inspect and tune them.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SYNTH_DIR = DATA_DIR / "synthetic"
WORKSPACE_DIR = DATA_DIR / "workspaces"
MODEL_DIR = ROOT / "models"
OUTPUT_DIR = ROOT / "outputs"
CONFIG_OVERRIDE = ROOT / "config" / "detection_config.json"
ACTIVE_WORKSPACE_FILE = DATA_DIR / "active_workspace.txt"

SEED = 42
MAX_UPLOAD_MB = 20
MAX_UPLOAD_ROWS = 500_000
DEFAULT_WORKSPACE = "demo"

# --------------------------------------------------------------------------
# Event schema
# --------------------------------------------------------------------------
REQUIRED_COLUMNS = ["event_id", "timestamp", "employee_id", "event_type"]
OPTIONAL_COLUMNS = ["role", "resource", "customer_id", "device_id", "location",
                    "volume_mb", "record_count", "outcome", "context_tag", "source_ref"]
EVENT_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS

CANONICAL_EVENT_TYPES = [
    "login_success", "login_failed", "account_access", "sensitive_search",
    "transaction_view", "bulk_download", "data_transfer", "privileged_op",
    "resource_access",
]
EVENT_TYPE_ALIASES = {
    "login": "login_success", "logon": "login_success", "auth_success": "login_success",
    "login_ok": "login_success", "login_fail": "login_failed", "failed_login": "login_failed",
    "logon_failed": "login_failed", "auth_failure": "login_failed",
    "view_account": "account_access", "customer_access": "account_access",
    "account_view": "account_access", "search": "sensitive_search",
    "sensitive_record_search": "sensitive_search", "transaction_access": "transaction_view",
    "txn_view": "transaction_view", "download": "bulk_download", "bulk_export": "bulk_download",
    "export": "bulk_download", "transfer": "data_transfer", "file_transfer": "data_transfer",
    "admin_action": "privileged_op", "privileged": "privileged_op", "priv_op": "privileged_op",
    "resource": "resource_access",
}

# Which event types count as "sensitive" and their weight for the sensitivity signal.
SENSITIVITY_WEIGHT = {
    "login_success": 0.1, "login_failed": 0.1, "account_access": 0.3, "transaction_view": 0.3,
    "resource_access": 0.4, "sensitive_search": 0.5, "privileged_op": 0.7,
    "bulk_download": 0.8, "data_transfer": 1.0,
}

# --------------------------------------------------------------------------
# Detection configuration
# --------------------------------------------------------------------------
DEFAULT_CONFIG: dict = {
    "baseline": {
        "min_history_days": 7,          # fewer active days -> baseline "insufficient"
        "hour_margin": 1.0,             # hours of tolerance around the observed hour range
        "robust_k": 3.0,                # median + k * 1.4826 * MAD upper fence
        "exclude_tagged_days": True,    # exception-tagged days excluded (anti-contamination)
    },
    "severity_weight": {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0},
    "rules": {
        "R01": {"name": "Login outside usual working pattern", "severity": "medium",
                "enabled": True, "params": {}},
        "R02": {"name": "Repeated failed logins followed by sensitive activity", "severity": "high",
                "enabled": True,
                "params": {"min_failed": 4, "fail_window_min": 15, "follow_window_min": 60}},
        "R03": {"name": "Unusually many distinct customer accounts in a day", "severity": "medium",
                "enabled": True, "params": {"abs_min": 35, "k_mad": 3.0}},
        "R04": {"name": "Access to unfamiliar customer accounts", "severity": "medium",
                "enabled": True, "params": {"min_count": 8, "min_ratio": 0.5}},
        "R05": {"name": "Access to unfamiliar resources", "severity": "high",
                "enabled": True, "params": {"min_count": 1}},
        "R06": {"name": "Burst of sensitive searches", "severity": "medium",
                "enabled": True, "params": {"abs_min": 10, "window_min": 30, "hist_mult": 1.5}},
        "R07": {"name": "Unusually large download", "severity": "high",
                "enabled": True, "params": {"abs_min_mb": 200.0, "p95_mult": 3.0}},
        "R08": {"name": "Unusual privileged operation", "severity": "high",
                "enabled": True, "params": {"abs_min_daily": 8, "p95_mult": 2.0}},
        "R09": {"name": "New device or location", "severity": "medium",
                "enabled": True, "params": {}},
        "R10": {"name": "Data transfer to external destination", "severity": "high",
                "enabled": True, "params": {"prefix": "external:"}},
    },
    "correlation": {
        "max_gap_min": 90,              # max gap between consecutive signal events in one group
        "max_span_hours": 12,           # max duration of one correlated group
    },
    "ml": {
        "n_estimators": 300,
        "threshold_quantile_candidates": [0.95, 0.97, 0.98, 0.99],
        "default_threshold_quantile": 0.98,
        "min_train_rows": 100,
        "z_cap": 8.0,
    },
    "risk": {
        "weights": {"rules": 0.30, "ml": 0.20, "deviation": 0.15,
                    "correlation": 0.20, "sensitivity": 0.15},
        "context_discount": 0.40,       # max score reduction for approved-context activity
        "alert_min_score": 30.0,        # groups below this are not raised as alerts
        "priority_thresholds": {"Medium": 30.0, "High": 50.0, "Critical": 75.0},
        "dev_z_cap": 8.0,
    },
    "split": {"train_frac": 0.58, "val_frac": 0.17},  # used when dataset has no explicit split
}


def load_config() -> dict:
    """Return the default config merged with the optional JSON override file."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if CONFIG_OVERRIDE.exists():
        with open(CONFIG_OVERRIDE, encoding="utf-8") as fh:
            _merge(cfg, json.load(fh))
    return cfg


def _merge(base: dict, override: dict) -> None:
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            _merge(base[key], val)
        else:
            base[key] = val


def priority_for(score: float, cfg: dict) -> str:
    """Map a 0-100 risk score to a review priority label."""
    t = cfg["risk"]["priority_thresholds"]
    if score >= t["Critical"]:
        return "Critical"
    if score >= t["High"]:
        return "High"
    if score >= t["Medium"]:
        return "Medium"
    return "Low"
