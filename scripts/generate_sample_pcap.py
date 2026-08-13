#!/usr/bin/env python3
"""
generate_sample_pcap.py
========================

Generates a fully synthetic pcap containing:
  1. "benign" flows -- irregular timing, variable packet sizes, short
     sessions, destined to well-known DoH resolvers (Cloudflare/Google) --
     modeling normal browser/OS DoH lookups.
  2. "malicious" flows -- near-perfectly-regular beaconing intervals,
     fixed/padded packet sizes, upload-heavy, long-lived, destined to an
     unrecognized IP -- modeling a DoH-based C2/exfil channel.

No real network traffic, hostnames, or third-party data are captured or
replayed; every packet is synthesized locally. This exists purely so the
detector has a small, safe, reproducible dataset to demo and test against.

Usage:
    python scripts/generate_sample_pcap.py --out examples/sample_traffic.pcap
"""

from __future__ import annotations

import argparse
import random
import struct

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def _tls_client_hello(sni: str) -> bytes:
    """Build a minimal-but-structurally-valid TLS 1.2 ClientHello record
    carrying the given SNI, so the detector's manual TLS parser has
    something realistic to parse (JA3 computation, SNI extraction)."""
    sni_bytes = sni.encode()
    server_name_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    server_name_list = struct.pack("!H", len(server_name_entry)) + server_name_entry
    sni_ext = struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list

    supported_versions_ext = struct.pack("!HH", 0x002b, 2) + b"\x03\x03"
    extensions = sni_ext + supported_versions_ext

    cipher_suites = struct.pack("!8H", 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009e)
    body = (
        b"\x03\x03" +                       # client_version TLS1.2
        random.randbytes(32) +              # random
        b"\x00" +                            # session_id length
        struct.pack("!H", len(cipher_suites)) + cipher_suites +
        b"\x01\x00" +                        # compression methods
        struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _make_flow(src_ip, dst_ip, src_port, dst_port, sni, start_time,
                n_exchanges, size_choices, interval_fn, base_len_padding=0,
                response_jitter=40):
    packets = []
    seq_c, seq_s = 1000, 5000
    t = start_time

    hello = _tls_client_hello(sni)
    pkt = (Ether() / IP(src=src_ip, dst=dst_ip) /
           TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq_c, ack=seq_s) / hello)
    pkt.time = t
    packets.append(pkt)
    seq_c += len(hello)

    for i in range(n_exchanges):
        t += interval_fn()
        req_len = random.choice(size_choices) + base_len_padding
        req_payload = bytes(req_len)
        req = (Ether() / IP(src=src_ip, dst=dst_ip) /
               TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq_c, ack=seq_s) / req_payload)
        req.time = t
        packets.append(req)
        seq_c += req_len

        t += 0.01 + random.random() * 0.02
        jitter = random.randint(0, response_jitter) if response_jitter else 0
        resp_len = random.choice(size_choices) + base_len_padding + jitter
        resp_payload = bytes(resp_len)
        resp = (Ether() / IP(src=dst_ip, dst=src_ip) /
                TCP(sport=dst_port, dport=src_port, flags="PA", seq=seq_s, ack=seq_c) / resp_payload)
        resp.time = t
        packets.append(resp)
        seq_s += resp_len

    return packets


def generate(seed: int = 1337) -> list:
    random.seed(seed)
    all_packets = []

    benign_targets = [
        ("10.0.0.21", "1.1.1.1", "cloudflare-dns.com"),
        ("10.0.0.22", "8.8.8.8", "dns.google"),
        ("10.0.0.23", "9.9.9.9", "dns.quad9.net"),
        ("10.0.0.21", "1.1.1.1", "cloudflare-dns.com"),
    ]
    for i, (src, dst, sni) in enumerate(benign_targets):
        all_packets += _make_flow(
            src_ip=src, dst_ip=dst, src_port=51000 + i, dst_port=443, sni=sni,
            start_time=1_700_000_000 + i * 40 + random.uniform(0, 10),
            n_exchanges=random.randint(2, 5),
            size_choices=[64, 96, 112, 140, 180, 210, 260],
            interval_fn=lambda: random.uniform(0.05, 4.0),
        )

    # Malicious: DoH-tunneled exfil beaconing to an unrecognized endpoint,
    # perfectly regular ~10s interval, fixed padded sizes, upload-heavy.
    all_packets += _make_flow(
        src_ip="10.0.0.55", dst_ip="203.0.113.77", src_port=52233, dst_port=443,
        sni="cdn-edge-sync.example-bad.net",
        start_time=1_700_000_050,
        n_exchanges=25,
        size_choices=[512],       # fixed padded block size -> low entropy
        interval_fn=lambda: 10.0 + random.uniform(-0.05, 0.05),  # near-zero CV -> beaconing
        base_len_padding=0,
        response_jitter=0,        # tunneling tools pad both directions to fixed block sizes
    )

    all_packets.sort(key=lambda p: p.time)
    return all_packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="examples/sample_traffic.pcap")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    packets = generate(seed=args.seed)
    wrpcap(args.out, packets)
    print(f"Wrote {len(packets)} synthetic packets to {args.out}")


if __name__ == "__main__":
    main()
