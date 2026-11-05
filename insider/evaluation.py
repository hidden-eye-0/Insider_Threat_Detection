"""Evaluation: confusion-matrix metrics and method comparison from actual predictions."""
from __future__ import annotations

import numpy as np
import pandas as pd


def confusion_metrics(y_true, y_pred) -> dict:
    """Compute TP/FP/TN/FN and derived metrics. Undefined ratios are reported as None."""
    yt, yp = np.asarray(y_true).astype(bool), np.asarray(y_pred).astype(bool)
    tp, fp = int((yt & yp).sum()), int((~yt & yp).sum())
    tn, fn = int((~yt & ~yp).sum()), int((yt & ~yp).sum())

    def div(a, b):
        return float(a / b) if b else None
    prec, rec = div(tp, tp + fp), div(tp, tp + fn)
    spec = div(tn, tn + fp)
    f1 = div(2 * prec * rec, prec + rec) if prec is not None and rec is not None and (prec + rec) else (0.0 if prec is not None and rec is not None else None)
    bal = (rec + spec) / 2 if rec is not None and spec is not None else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec, "f1": f1,
            "accuracy": div(tp + tn, tp + tn + fp + fn), "balanced_accuracy": bal, "specificity": spec,
            "n": int(len(yt)), "positives": int(yt.sum())}


def compare_methods(days: pd.DataFrame, methods: dict[str, str]) -> pd.DataFrame:
    """``days`` has a boolean ``label`` and one boolean column per method. Returns metrics table."""
    rows = []
    for name, col in methods.items():
        m = confusion_metrics(days["label"], days[col])
        m["method"] = name
        rows.append(m)
    cols = ["method", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy", "balanced_accuracy", "specificity", "n", "positives"]
    return pd.DataFrame(rows)[cols]
