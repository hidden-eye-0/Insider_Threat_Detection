"""Unsupervised ML anomaly detection (Isolation Forest primary, LOF comparison).

Score convention: ``anomaly_score`` is the negated scikit-learn ``score_samples`` value
(higher = more anomalous). It is NOT a probability of malicious intent. ``ml_norm`` is a
0-1 severity index: 0 at the training median score, 1 at the training 99.9th percentile
(clipped). An employee-day is ML-flagged when its anomaly_score is >= the threshold, a
configurable quantile of the training scores.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from .config import MODEL_DIR, SEED
from .features import FEATURE_COLUMNS


class InsufficientDataError(RuntimeError):
    """Not enough training rows to fit the anomaly model."""


@dataclass
class AnomalyModel:
    n_estimators: int = 300
    seed: int = SEED
    iforest: IsolationForest | None = None
    lof: LocalOutlierFactor | None = None
    scaler: StandardScaler | None = None
    q_hi: float = 1.0
    q_lo: float = 0.0
    threshold_quantile: float = 0.98
    threshold: float = 0.0
    lof_threshold: float = 0.0
    train_scores: np.ndarray = field(default_factory=lambda: np.array([]))
    info: dict = field(default_factory=dict)

    # -- training ------------------------------------------------------------
    def fit(self, feats: pd.DataFrame, min_rows: int = 100, quantile: float = 0.98) -> "AnomalyModel":
        if len(feats) < min_rows:
            raise InsufficientDataError(
                f"Need at least {min_rows} employee-day rows to train the anomaly model; got {len(feats)}.")
        X = feats[FEATURE_COLUMNS].astype(float).values
        self.iforest = IsolationForest(n_estimators=self.n_estimators, contamination="auto",
                                       random_state=self.seed, n_jobs=1).fit(X)
        self.scaler = StandardScaler().fit(np.log1p(np.clip(X, 0, None)))
        self.lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(self.scaler.transform(np.log1p(np.clip(X, 0, None))))
        self.train_scores = self._if_score(X)
        self.q_lo = float(np.quantile(self.train_scores, 0.5))
        self.q_hi = float(np.quantile(self.train_scores, 0.999))
        self.set_threshold_quantile(quantile)
        lof_train = self._lof_score(X)
        self._lof_train = lof_train
        self.lof_threshold = float(np.quantile(lof_train, quantile))
        self.info = {"model": "IsolationForest", "n_estimators": self.n_estimators, "seed": self.seed,
                     "n_train_rows": int(len(feats)), "n_features": len(FEATURE_COLUMNS),
                     "features": FEATURE_COLUMNS, "comparison_model": "LocalOutlierFactor(novelty=True, k=20)"}
        return self

    def set_threshold_quantile(self, q: float) -> None:
        self.threshold_quantile = q
        self.threshold = float(np.quantile(self.train_scores, q))
        if hasattr(self, "_lof_train"):
            self.lof_threshold = float(np.quantile(self._lof_train, q))

    # -- scoring ---------------------------------------------------------------
    def _if_score(self, X: np.ndarray) -> np.ndarray:
        return -self.iforest.score_samples(X)

    def _lof_score(self, X: np.ndarray) -> np.ndarray:
        return -self.lof.score_samples(self.scaler.transform(np.log1p(np.clip(X, 0, None))))

    def score(self, feats: pd.DataFrame) -> pd.DataFrame:
        """Return DataFrame with anomaly_score, ml_norm, ml_flag, lof_score, lof_flag."""
        if self.iforest is None:
            raise RuntimeError("Model is not trained.")
        X = feats[FEATURE_COLUMNS].astype(float).values
        s = self._if_score(X)
        l = self._lof_score(X)
        span = max(self.q_hi - self.q_lo, 1e-9)
        return pd.DataFrame({
            "anomaly_score": s, "ml_norm": np.clip((s - self.q_lo) / span, 0, 1), "ml_flag": s >= self.threshold,
            "lof_score": l, "lof_flag": l >= self.lof_threshold,
        }, index=feats.index)

    # -- persistence -----------------------------------------------------------
    def save(self, name: str) -> str:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        path = MODEL_DIR / f"{name}_iforest.joblib"
        joblib.dump(self, path)
        return str(path)

    @staticmethod
    def load(path: str) -> "AnomalyModel":
        return joblib.load(path)
