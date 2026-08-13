from doh_detector.capture import PcapLoader
from doh_detector.features import FlowFeatureExtractor
from doh_detector.detector import DoHDetector
from doh_detector.fingerprint import ResolverFingerprintDB


def test_detector_flags_malicious_flow_highest(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    findings = DoHDetector(use_ml=False).analyze(features)

    assert findings[0].flow.dst_ip == "203.0.113.77"
    assert findings[0].risk.total > findings[-1].risk.total


def test_findings_sorted_descending(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    findings = DoHDetector(use_ml=False).analyze(features)
    scores = [f.risk.total for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_finding_to_dict_has_expected_keys(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    findings = DoHDetector(use_ml=False).analyze(features)
    d = findings[0].to_dict()
    for key in ("flow_id", "risk_score", "severity", "reasons", "features"):
        assert key in d


def test_ml_disabled_never_sets_outlier_flag(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    findings = DoHDetector(use_ml=False).analyze(features)
    assert all(f.ml_outlier is False for f in findings)


def test_fingerprint_db_matches_known_sni():
    db = ResolverFingerprintDB()
    match = db.match(sni="cloudflare-dns.com")
    assert match.matched is True
    assert match.name == "Cloudflare"


def test_fingerprint_db_matches_known_ip():
    db = ResolverFingerprintDB()
    match = db.match(dst_ip="8.8.8.8")
    assert match.matched is True
    assert match.name == "Google Public DNS"


def test_fingerprint_db_no_match_for_unknown():
    db = ResolverFingerprintDB()
    match = db.match(sni="totally-unknown-resolver.example", dst_ip="203.0.113.1")
    assert match.matched is False
    assert match.name is None


def test_ml_outlier_detection_runs_with_enough_flows(sample_pcap_path):
    # Isolation Forest needs >= MIN_FLOWS_FOR_ML flows to activate; duplicate
    # the small sample's features to synthesize a large-enough population
    # purely for this unit test.
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows) * 4  # 20 flows total
    findings = DoHDetector(use_ml=True).analyze(features)
    assert any(f.ml_outlier_score is not None for f in findings)


def test_ml_disabled_below_min_flows_threshold(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)  # only 5 flows
    findings = DoHDetector(use_ml=True).analyze(features)
    assert all(f.ml_outlier_score is None for f in findings)
