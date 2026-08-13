from doh_detector.features import FlowFeatures
from doh_detector.scoring import RiskScorer


def _features(**overrides) -> FlowFeatures:
    base = dict(
        flow_id="1.2.3.4:1->5.6.7.8:443", src_ip="1.2.3.4", dst_ip="5.6.7.8",
        dst_port=443, sni="example.com", ja3="deadbeef",
        packet_count=20, byte_count=4000, duration_sec=200.0, packets_per_sec=0.1,
        size_mean=512.0, size_stdev=0.0, size_entropy=0.0, upload_download_ratio=1.0,
        iat_mean=10.0, iat_stdev=0.01, iat_cv=0.001,
        known_resolver=False, resolver_name=None,
    )
    base.update(overrides)
    return FlowFeatures(**base)


def test_beaconing_flow_scores_high():
    scorer = RiskScorer()
    f = _features(packet_count=20, iat_cv=0.001, size_entropy=0.0,
                   upload_download_ratio=5.0, duration_sec=250.0)
    result = scorer.score(f)
    rules_hit = {c.rule for c in result.components}
    assert "regular_beaconing" in rules_hit
    assert "low_size_entropy" in rules_hit
    assert "upload_heavy" in rules_hit
    assert result.severity in ("medium", "high")


def test_normal_browsing_flow_scores_low():
    scorer = RiskScorer()
    f = _features(packet_count=6, iat_cv=1.8, size_entropy=2.9,
                   upload_download_ratio=0.4, duration_sec=1.2,
                   known_resolver=True, resolver_name="Cloudflare")
    result = scorer.score(f)
    assert result.severity == "info"
    assert result.total < 15


def test_severity_bucketing_boundaries():
    assert RiskScorer._severity(0) == "info"
    assert RiskScorer._severity(14) == "info"
    assert RiskScorer._severity(15) == "low"
    assert RiskScorer._severity(34) == "low"
    assert RiskScorer._severity(35) == "medium"
    assert RiskScorer._severity(59) == "medium"
    assert RiskScorer._severity(60) == "high"
    assert RiskScorer._severity(100) == "high"


def test_score_never_exceeds_100():
    scorer = RiskScorer()
    f = _features(packet_count=50, iat_cv=0.0, size_entropy=0.0,
                   upload_download_ratio=50.0, packets_per_sec=100.0,
                   duration_sec=999.0, known_resolver=False)
    result = scorer.score(f)
    assert result.total <= 100


def test_custom_thresholds_are_respected():
    scorer = RiskScorer(thresholds={"beacon_cv_low": 0.5})
    f = _features(packet_count=20, iat_cv=0.3)
    result = scorer.score(f)
    assert any(c.rule == "regular_beaconing" for c in result.components)
