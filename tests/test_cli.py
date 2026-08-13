import json

from doh_detector.cli import main


def test_cli_analyze_json_to_stdout(sample_pcap_path, capsys):
    # The synthetic sample contains one deliberately "high" severity
    # beaconing flow, so the CLI's exit code (2 = high-severity finding
    # present, used for CI/pipeline gating) should reflect that.
    rc = main(["analyze", "--pcap", sample_pcap_path, "--format", "json"])
    captured = capsys.readouterr()
    assert rc == 2
    parsed = json.loads(captured.out)
    assert parsed["flow_count"] == 5


def test_cli_analyze_writes_file(sample_pcap_path, tmp_path):
    out_file = tmp_path / "report.json"
    rc = main(["analyze", "--pcap", sample_pcap_path, "--format", "json", "--out", str(out_file)])
    assert rc == 2
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["tool"] == "doh-exfil-detector"


def test_cli_min_score_filters_findings(sample_pcap_path, capsys):
    main(["analyze", "--pcap", sample_pcap_path, "--format", "json", "--min-score", "100"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["findings"] == []


def test_cli_resolvers_lists_known_sni(capsys):
    rc = main(["resolvers"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "cloudflare-dns.com" in captured.out


def test_cli_no_ml_flag_disables_outlier_detection(sample_pcap_path, capsys):
    main(["analyze", "--pcap", sample_pcap_path, "--format", "json", "--no-ml"])
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert all(f["ml_outlier"] is False for f in parsed["findings"])
