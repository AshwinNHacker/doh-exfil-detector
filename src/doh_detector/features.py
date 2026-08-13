"""
features.py
===========

Turns a reconstructed Flow into a fixed-width numeric feature vector using
only connection metadata: nothing here requires or performs decryption.

Feature groups
--------------
1. Volume / shape    -- packet counts, byte counts, up/down ratio
2. Packet-size stats  -- mean, stdev, and Shannon entropy of the on-wire
                          packet-size distribution (DoH tunneling payloads
                          are often padded to a small set of fixed sizes,
                          which collapses entropy versus organic browsing)
3. Timing stats       -- inter-arrival time (IAT) mean/stdev and the
                          coefficient of variation, which is the classic
                          "beaconing" signal: malware/C2 channels that poll
                          on a fixed interval have CoV close to 0, while
                          human-driven browsing has high, irregular CoV.
4. Session shape       -- flow duration, average query rate (packets/sec)
5. Fingerprint context -- whether the JA3/SNI matches a known DoH resolver
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, asdict
from typing import List, Optional

from .capture import Flow
from .fingerprint import ResolverFingerprintDB


@dataclass
class FlowFeatures:
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: Optional[str]
    ja3: Optional[str]

    packet_count: int
    byte_count: int
    duration_sec: float
    packets_per_sec: float

    size_mean: float
    size_stdev: float
    size_entropy: float          # bits; low = few distinct padded sizes
    upload_download_ratio: float  # bytes out / bytes in

    iat_mean: float
    iat_stdev: float
    iat_cv: float                 # coefficient of variation (stdev/mean)

    known_resolver: bool
    resolver_name: Optional[str]

    def as_dict(self) -> dict:
        return asdict(self)


def _shannon_entropy(values: List[int]) -> float:
    if not values:
        return 0.0
    counts: dict = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    n = len(values)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


class FlowFeatureExtractor:
    def __init__(self, fingerprint_db: Optional[ResolverFingerprintDB] = None):
        self.fingerprint_db = fingerprint_db or ResolverFingerprintDB()

    def transform(self, flows: List[Flow]) -> List[FlowFeatures]:
        return [self._extract_one(f) for f in flows]

    def _extract_one(self, flow: Flow) -> FlowFeatures:
        sizes = [p.length for p in flow.packets]
        out_bytes = sum(p.length for p in flow.packets if p.direction == "out")
        in_bytes = sum(p.length for p in flow.packets if p.direction == "in")

        # Beaconing is a *client polling* signal, so inter-arrival time is
        # measured between successive client->server packets only. Mixing in
        # server response latency (sub-second) would dilute a slow, regular
        # polling interval with fast, noisy handshake/response timing.
        out_timestamps = [p.timestamp for p in flow.packets if p.direction == "out"]
        iats = [t2 - t1 for t1, t2 in zip(out_timestamps, out_timestamps[1:]) if t2 >= t1]

        size_mean = statistics.fmean(sizes) if sizes else 0.0
        size_stdev = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
        size_entropy = _shannon_entropy(sizes)

        iat_mean = statistics.fmean(iats) if iats else 0.0
        iat_stdev = statistics.pstdev(iats) if len(iats) > 1 else 0.0
        iat_cv = (iat_stdev / iat_mean) if iat_mean > 0 else 0.0

        duration = flow.duration
        pps = (len(flow.packets) / duration) if duration > 0 else float(len(flow.packets))

        sni = flow.client_hello.sni if flow.client_hello else None
        ja3 = flow.client_hello.ja3 if flow.client_hello else None

        match = self.fingerprint_db.match(sni=sni, ja3=ja3, dst_ip=flow.dst_ip)

        return FlowFeatures(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            sni=sni,
            ja3=ja3,
            packet_count=len(flow.packets),
            byte_count=out_bytes + in_bytes,
            duration_sec=round(duration, 3),
            packets_per_sec=round(pps, 4),
            size_mean=round(size_mean, 2),
            size_stdev=round(size_stdev, 2),
            size_entropy=round(size_entropy, 3),
            upload_download_ratio=round((out_bytes / in_bytes) if in_bytes else float(out_bytes), 3),
            iat_mean=round(iat_mean, 4),
            iat_stdev=round(iat_stdev, 4),
            iat_cv=round(iat_cv, 4),
            known_resolver=match.matched,
            resolver_name=match.name,
        )
