from doh_detector.capture import PcapLoader


def test_extract_flows_finds_expected_count(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    # 4 benign flows + 1 malicious flow in the synthetic sample
    assert len(flows) == 5


def test_flow_has_client_hello_with_sni(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    slis = [f.client_hello.sni for f in flows if f.client_hello]
    assert "cloudflare-dns.com" in slis
    assert "cdn-edge-sync.example-bad.net" in slis


def test_flow_packets_sorted_by_time(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    for f in flows:
        timestamps = [p.timestamp for p in f.packets]
        assert timestamps == sorted(timestamps)


def test_custom_ports_filter_excludes_everything(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path, doh_ports=(9999,)).extract_flows()
    assert flows == []


def test_ja3_is_computed_when_client_hello_present(sample_pcap_path):
    flows = PcapLoader(sample_pcap_path).extract_flows()
    ja3s = [f.client_hello.ja3 for f in flows if f.client_hello]
    assert all(isinstance(j, str) and len(j) == 32 for j in ja3s)
