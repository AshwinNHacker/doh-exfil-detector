"""
scoring.py
==========

Converts a FlowFeatures object into an explainable 0-100 risk score using
transparent, tunable heuristics grounded in published research on DoH
tunneling / covert-channel detection (e.g. beaconing/IAT regularity as a
C2 indicator; packet-size clustering as a padding/tunneling indicator;
volume outliers as an exfiltration indicator). Each rule contributes a
named, capped point value so a reviewer can see exactly why a flow was
flagged -- deliberately avoiding an opaque black-box score.

This is intentionally rule-based and human-readable at its core; detector.py
layers an optional unsupervised model (Isolation Forest) on top for flows
that don't trip any single rule but are statistical outliers relative to
the rest of the capture.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .features import FlowFeatures

# Tunable thresholds. Defaults are intentionally conservative starting
# points calibrated against the synthetic benign/malicious traffic in
# scripts/generate_sample_pcap.py -- retune against your own network's
# baseline before relying on this in production (see docs/DETECTION_METHODOLOGY.md).
THRESHOLDS = {
    "beacon_cv_low": 0.15,        # IAT coefficient of variation below this = suspiciously regular
    "beacon_min_packets": 8,      # need enough samples for CV to be meaningful
    "entropy_low_bits": 1.5,      # packet-size entropy below this = few distinct (padded) sizes
    "entropy_min_packets": 6,
    "upload_heavy_ratio": 3.0,    # bytes-out/bytes-in above this = possible exfil (upload-heavy)
    "high_query_rate_pps": 5.0,   # packets/sec above this sustained rate is atypical for DNS lookups
    "long_session_sec": 120.0,    # DoH lookups are normally sub-second transactions; long-lived
                                    # sessions carrying many packets look more like a tunnel
    "long_session_min_packets": 20,
}


@dataclass
class ScoreComponent:
    rule: str
    points: int
    detail: str


@dataclass
class RiskScore:
    total: int
    severity: str
    components: List[ScoreComponent]


class RiskScorer:
    def __init__(self, thresholds: dict = None):
        self.t = {**THRESHOLDS, **(thresholds or {})}

    def score(self, f: FlowFeatures) -> RiskScore:
        components: List[ScoreComponent] = []

        # 1. Beaconing: near-constant inter-arrival time is a hallmark of
        #    automated polling (C2/exfil) rather than human DNS lookups.
        if f.packet_count >= self.t["beacon_min_packets"] and f.iat_mean > 0:
            if f.iat_cv < self.t["beacon_cv_low"]:
                components.append(ScoreComponent(
                    "regular_beaconing", 30,
                    f"IAT coefficient of variation {f.iat_cv:.3f} < {self.t['beacon_cv_low']} "
                    f"(mean interval {f.iat_mean:.2f}s) -- traffic timing is machine-regular."
                ))

        # 2. Low packet-size entropy: real DoH answers vary in size with the
        #    DNS response; a channel padding everything to fixed block sizes
        #    (common in tunneling tools) collapses this variability.
        if f.packet_count >= self.t["entropy_min_packets"]:
            if f.size_entropy < self.t["entropy_low_bits"]:
                components.append(ScoreComponent(
                    "low_size_entropy", 20,
                    f"Packet-size entropy {f.size_entropy:.2f} bits < {self.t['entropy_low_bits']} "
                    f"-- traffic uses very few distinct packet sizes (possible fixed-size padding)."
                ))

        # 3. Upload-heavy flows: DNS is naturally download-heavy (small query,
        #    larger answer). A flow sending far more than it receives is
        #    shaped like data exfiltration rather than name resolution.
        if f.upload_download_ratio > self.t["upload_heavy_ratio"]:
            components.append(ScoreComponent(
                "upload_heavy", 20,
                f"Upload/download byte ratio {f.upload_download_ratio:.2f} > "
                f"{self.t['upload_heavy_ratio']} -- more data flowing to the resolver than back."
            ))

        # 4. Sustained high query rate.
        if f.packets_per_sec > self.t["high_query_rate_pps"]:
            components.append(ScoreComponent(
                "high_query_rate", 15,
                f"{f.packets_per_sec:.2f} packets/sec sustained -- far above typical interactive "
                f"DoH lookup cadence."
            ))

        # 5. Long-lived, high-volume session on a protocol whose normal unit
        #    of work is a single request/response pair.
        if (f.duration_sec > self.t["long_session_sec"]
                and f.packet_count > self.t["long_session_min_packets"]):
            components.append(ScoreComponent(
                "long_lived_session", 10,
                f"Flow lasted {f.duration_sec:.1f}s across {f.packet_count} packets -- "
                f"unusually long-lived for discrete DNS resolution."
            ))

        # 6. Fingerprint context: unknown SNI/IP is a mild signal on its own
        #    (many legitimate private/enterprise resolvers exist) but raises
        #    the bar if combined with the behavioral rules above.
        if not f.known_resolver:
            components.append(ScoreComponent(
                "unrecognized_resolver_endpoint", 10,
                f"Destination {f.sni or f.dst_ip} does not match any resolver in the known-DoH "
                f"fingerprint database -- confirm this is an authorized enterprise/private resolver."
            ))

        total = min(sum(c.points for c in components), 100)
        severity = self._severity(total)
        return RiskScore(total=total, severity=severity, components=components)

    @staticmethod
    def _severity(total: int) -> str:
        if total >= 60:
            return "high"
        if total >= 35:
            return "medium"
        if total >= 15:
            return "low"
        return "info"
