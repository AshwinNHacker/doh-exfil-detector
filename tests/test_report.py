import json

from doh_detector.capture import PcapLoader
from doh_detector.features import FlowFeatureExtractor
from doh_detector.detector import DoHDetector
from doh_detector import report


def _findings(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    features = FlowFeatureExtractor().transform(flows)
    return DoHDetector(use_ml=False).analyze(features)


def test_json_report_is_valid_json(sample_pcap_path):
    findings = _findings(sample_pcap_path)
    output = report.to_json(findings, source="test.pcap")
    parsed = json.loads(output)
    assert parsed["flow_count"] == len(findings)
    assert parsed["source"] == "test.pcap"


def test_markdown_report_contains_table(sample_pcap_path):
    findings = _findings(sample_pcap_path)
    output = report.to_markdown(findings, source="test.pcap")
    assert "| Severity | Score |" in output
    assert "DoH Exfiltration Detection Report" in output


def test_html_report_is_well_formed(sample_pcap_path):
    findings = _findings(sample_pcap_path)
    output = report.to_html(findings, source="test.pcap")
    assert output.startswith("<!DOCTYPE html>")
    assert "<table>" in output and "</table>" in output
