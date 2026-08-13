"""
doh-exfil-detector
===================

Fingerprints anomalous DNS-over-HTTPS (DoH) query patterns from network
metadata alone -- packet sizes, inter-arrival timing, flow duration, TLS
ClientHello fingerprints (JA3) and destination SNI/IP -- WITHOUT decrypting
any TLS traffic.

The detector never inspects TLS application data. Every feature it uses is
available to any observer who can see packet headers on the wire (a switch
SPAN port, a NetFlow/IPFIX exporter, a firewall log). This is intentional:
DoH's entire purpose is to hide DNS query contents from network
intermediaries, so a detector that requires decryption would defeat the
protocol it is analyzing and would not work against it in practice anyway.

Public API:
    from doh_detector import PcapLoader, FlowFeatureExtractor, DoHDetector

    flows = PcapLoader("capture.pcap").extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    findings = DoHDetector().analyze(features)
"""

__version__ = "1.0.0"

from .capture import PcapLoader, Flow, Packet
from .features import FlowFeatureExtractor, FlowFeatures
from .fingerprint import ResolverFingerprintDB
from .detector import DoHDetector, Finding
from .scoring import RiskScorer

__all__ = [
    "PcapLoader",
    "Flow",
    "Packet",
    "FlowFeatureExtractor",
    "FlowFeatures",
    "ResolverFingerprintDB",
    "DoHDetector",
    "Finding",
    "RiskScorer",
]
