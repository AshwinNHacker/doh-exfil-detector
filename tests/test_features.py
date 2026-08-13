from doh_detector.capture import PcapLoader
from doh_detector.features import FlowFeatureExtractor, _shannon_entropy


def _extract(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    return FlowFeatureExtractor().transform(flows)


def test_shannon_entropy_uniform_is_zero():
    assert _shannon_entropy([100, 100, 100, 100]) == 0.0


def test_shannon_entropy_varied_is_positive():
    assert _shannon_entropy([10, 20, 30, 40, 50, 60]) > 0.0


def test_malicious_flow_has_low_iat_cv(sample_pcap_path):
    features = _extract(sample_pcap_path)
    malicious = next(f for f in features if f.dst_ip == "203.0.113.77")
    assert malicious.iat_cv < 0.15


def test_malicious_flow_has_low_size_entropy(sample_pcap_path):
    features = _extract(sample_pcap_path)
    malicious = next(f for f in features if f.dst_ip == "203.0.113.77")
    assert malicious.size_entropy < 1.5


def test_malicious_flow_unrecognized_resolver(sample_pcap_path):
    features = _extract(sample_pcap_path)
    malicious = next(f for f in features if f.dst_ip == "203.0.113.77")
    assert malicious.known_resolver is False


def test_benign_flows_match_known_resolvers(sample_pcap_path):
    features = _extract(sample_pcap_path)
    benign = [f for f in features if f.dst_ip != "203.0.113.77"]
    assert all(f.known_resolver for f in benign)
    names = {f.resolver_name for f in benign}
    assert names == {"Cloudflare", "Google Public DNS", "Quad9"}


def test_feature_dict_roundtrip(sample_pcap_path):
    features = _extract(sample_pcap_path)
    d = features[0].as_dict()
    assert "flow_id" in d and "size_entropy" in d and "iat_cv" in d
