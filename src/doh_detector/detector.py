"""
detector.py
===========

Orchestrates detection across a capture:

  1. Rule-based scoring (scoring.py) for every flow -- explainable, works
     even on a single flow / small capture.
  2. Population-level outlier detection (Isolation Forest, scikit-learn)
     across all flows in the capture -- catches flows that don't trip any
     individual rule's threshold but are statistical outliers relative to
     the rest of the traffic on this network. Requires a minimum number of
     flows to fit meaningfully and degrades gracefully (skips itself) below
     that, since a handful of flows can't establish a baseline.

The two signals are combined: a flow's final risk score is its rule-based
score, boosted if the unsupervised model also flags it as an outlier. This
keeps the primary score explainable while still benefiting from population
statistics when there's enough data to compute them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .features import FlowFeatures
from .scoring import RiskScorer, RiskScore

MIN_FLOWS_FOR_ML = 15
ML_OUTLIER_BOOST = 15

_ML_FEATURE_ORDER = [
    "packets_per_sec", "size_mean", "size_stdev", "size_entropy",
    "upload_download_ratio", "iat_mean", "iat_cv", "duration_sec",
]


@dataclass
class Finding:
    flow: FlowFeatures
    risk: RiskScore
    ml_outlier: bool = False
    ml_outlier_score: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow.flow_id,
            "src_ip": self.flow.src_ip,
            "dst_ip": self.flow.dst_ip,
            "dst_port": self.flow.dst_port,
            "sni": self.flow.sni,
            "ja3": self.flow.ja3,
            "known_resolver": self.flow.known_resolver,
            "resolver_name": self.flow.resolver_name,
            "risk_score": self.risk.total,
            "severity": self.risk.severity,
            "ml_outlier": self.ml_outlier,
            "ml_outlier_score": self.ml_outlier_score,
            "reasons": [
                {"rule": c.rule, "points": c.points, "detail": c.detail}
                for c in self.risk.components
            ],
            "features": self.flow.as_dict(),
        }


class DoHDetector:
    def __init__(self, scorer: Optional[RiskScorer] = None, use_ml: bool = True):
        self.scorer = scorer or RiskScorer()
        self.use_ml = use_ml

    def analyze(self, flows: List[FlowFeatures]) -> List[Finding]:
        base_scores = [self.scorer.score(f) for f in flows]
        outlier_flags, outlier_scores = self._run_isolation_forest(flows)

        findings: List[Finding] = []
        for f, risk, is_outlier, oscore in zip(flows, base_scores, outlier_flags, outlier_scores):
            total = risk.total
            if is_outlier:
                total = min(total + ML_OUTLIER_BOOST, 100)
                risk = RiskScore(total=total, severity=RiskScorer._severity(total),
                                  components=risk.components)
            findings.append(Finding(flow=f, risk=risk, ml_outlier=is_outlier,
                                     ml_outlier_score=oscore))

        findings.sort(key=lambda x: x.risk.total, reverse=True)
        return findings

    def _run_isolation_forest(self, flows: List[FlowFeatures]):
        n = len(flows)
        if not self.use_ml or n < MIN_FLOWS_FOR_ML:
            return [False] * n, [None] * n

        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np
        except ImportError:
            return [False] * n, [None] * n

        matrix = np.array([[getattr(f, feat) for feat in _ML_FEATURE_ORDER] for f in flows])
        model = IsolationForest(contamination="auto", random_state=42, n_estimators=200)
        model.fit(matrix)
        raw_scores = model.decision_function(matrix)  # higher = more normal
        predictions = model.predict(matrix)            # -1 = outlier, 1 = inlier

        is_outlier = [bool(p == -1) for p in predictions]
        # Normalize decision_function output to a friendlier 0-1 "anomaly-ness"
        lo, hi = float(raw_scores.min()), float(raw_scores.max())
        span = (hi - lo) or 1.0
        anomaly_scores = [round(1.0 - ((s - lo) / span), 4) for s in raw_scores]
        return is_outlier, anomaly_scores
