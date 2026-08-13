import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from generate_sample_pcap import generate  # noqa: E402


@pytest.fixture(scope="session")
def sample_pcap_path(tmp_path_factory):
    from scapy.all import wrpcap
    packets = generate(seed=1337)
    path = tmp_path_factory.mktemp("pcaps") / "sample.pcap"
    wrpcap(str(path), packets)
    return str(path)
