"""
capture.py
==========

Reads a pcap/pcapng file, reconstructs TCP flows on TLS-bearing ports
(443 by default, configurable for non-standard DoH deployments), and
extracts the metadata needed for detection:

    * per-packet timestamp and wire length (TLS record layer, not payload)
    * TLS ClientHello fields when present: SNI, JA3 fingerprint components
    * 5-tuple flow identity (src ip/port, dst ip/port, protocol)

No TLS application data is ever parsed or stored. The ClientHello is the
only TLS message we look inside, and it is unencrypted by design (it is
sent before the TLS handshake establishes keys), so this does not
constitute decryption of anything.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

# Default ports carrying DoH traffic. 443 covers the overwhelming majority
# (HTTP/2 and HTTP/3-over-QUIC both commonly reuse it); 8443 is included
# for resolvers / proxies that run DoH on an alternate port.
DEFAULT_DOH_PORTS = frozenset({443, 8443})

TLS_HANDSHAKE_CONTENT_TYPE = 22
TLS_CLIENT_HELLO_MSG_TYPE = 1

# Extension types whose presence/absence/order matters for JA3 but that
# should NOT themselves be treated as "GREASE" -- values reserved by
# RFC 8701 for GREASE and that must be filtered out of JA3 inputs.
GREASE_VALUES = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})


@dataclass
class Packet:
    """A single packet reduced to the metadata the detector is allowed to use."""
    timestamp: float
    length: int          # on-wire length (IP total length), NOT decrypted payload size
    direction: str        # "out" (client->server) or "in" (server->client)


@dataclass
class ClientHelloInfo:
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)


@dataclass
class Flow:
    """A reconstructed bidirectional TCP flow (a single DoH TLS session)."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    packets: List[Packet] = field(default_factory=list)
    client_hello: Optional[ClientHelloInfo] = None

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"

    @property
    def start_time(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def end_time(self) -> float:
        return self.packets[-1].timestamp if self.packets else 0.0

    @property
    def duration(self) -> float:
        return max(self.end_time - self.start_time, 0.0)


def _parse_tls_extensions(data: bytes, offset: int, end: int) -> Tuple[List[int], Optional[str]]:
    """Parse the TLS extensions block of a ClientHello, returning extension
    type IDs (GREASE filtered) and the SNI hostname if present."""
    ext_types: List[int] = []
    sni: Optional[str] = None
    while offset + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset + 4])
        ext_body_start = offset + 4
        ext_body_end = ext_body_start + ext_len
        if ext_type not in GREASE_VALUES:
            ext_types.append(ext_type)
        if ext_type == 0x0000 and ext_body_end <= end:  # server_name extension
            try:
                # server_name_list length (2) + type (1) + host_name length (2)
                sni_list_body = data[ext_body_start:ext_body_end]
                pos = 2  # skip server_name_list length
                name_type = sni_list_body[pos]
                pos += 1
                name_len = struct.unpack("!H", sni_list_body[pos:pos + 2])[0]
                pos += 2
                if name_type == 0:
                    sni = sni_list_body[pos:pos + name_len].decode("ascii", errors="ignore")
            except (IndexError, struct.error):
                pass
        offset = ext_body_end
    return ext_types, sni


def _parse_client_hello(payload: bytes) -> Optional[ClientHelloInfo]:
    """Manually parse a TLS record containing a ClientHello handshake message.

    We parse only the unencrypted handshake header fields (version, cipher
    suites, extensions, SNI) -- exactly what any passive network monitor or
    the JA3 project (Salesforce, 2017, open methodology) observes. No
    decryption of any kind is involved because the ClientHello is sent in
    the clear before key exchange completes.
    """
    try:
        if len(payload) < 6 or payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
            return None
        record_version = struct.unpack("!H", payload[1:3])[0]
        record_len = struct.unpack("!H", payload[3:5])[0]
        handshake = payload[5:5 + record_len]
        if len(handshake) < 4 or handshake[0] != TLS_CLIENT_HELLO_MSG_TYPE:
            return None

        pos = 4  # skip handshake type(1) + length(3)
        client_version = struct.unpack("!H", handshake[pos:pos + 2])[0]
        pos += 2
        pos += 32  # random
        session_id_len = handshake[pos]
        pos += 1 + session_id_len

        cipher_len = struct.unpack("!H", handshake[pos:pos + 2])[0]
        pos += 2
        cipher_bytes = handshake[pos:pos + cipher_len]
        pos += cipher_len
        cipher_suites = [
            struct.unpack("!H", cipher_bytes[i:i + 2])[0]
            for i in range(0, len(cipher_bytes) - 1, 2)
            if struct.unpack("!H", cipher_bytes[i:i + 2])[0] not in GREASE_VALUES
        ]

        comp_len = handshake[pos]
        pos += 1 + comp_len

        ext_types: List[int] = []
        sni: Optional[str] = None
        if pos + 2 <= len(handshake):
            ext_total_len = struct.unpack("!H", handshake[pos:pos + 2])[0]
            pos += 2
            ext_types, sni = _parse_tls_extensions(handshake, pos, pos + ext_total_len)

        ja3_string = "{ver},{ciphers},{exts},{ec},{ecpf}".format(
            ver=client_version,
            ciphers="-".join(str(c) for c in cipher_suites),
            exts="-".join(str(e) for e in ext_types),
            ec="",     # elliptic_curves / supported_groups omitted for brevity in this OSS build
            ecpf="",   # ec_point_formats omitted for brevity in this OSS build
        )
        ja3 = hashlib.md5(ja3_string.encode()).hexdigest()

        return ClientHelloInfo(
            sni=sni, ja3=ja3, ja3_string=ja3_string,
            cipher_suites=cipher_suites, extensions=ext_types,
        )
    except (struct.error, IndexError):
        return None


class PcapLoader:
    """Loads a pcap/pcapng file and reconstructs per-connection Flow objects
    restricted to candidate DoH ports."""

    def __init__(self, path: str, doh_ports: Optional[Tuple[int, ...]] = None):
        self.path = path
        self.doh_ports = frozenset(doh_ports) if doh_ports else DEFAULT_DOH_PORTS

    def extract_flows(self) -> List[Flow]:
        flows: Dict[Tuple, Flow] = {}
        client_addr: Dict[Tuple, Tuple[str, int]] = {}

        with PcapReader(self.path) as reader:
            for pkt in reader:
                ip_layer = None
                if IP in pkt:
                    ip_layer = pkt[IP]
                elif IPv6 in pkt:
                    ip_layer = pkt[IPv6]
                if ip_layer is None or TCP not in pkt:
                    continue

                tcp = pkt[TCP]
                if tcp.sport not in self.doh_ports and tcp.dport not in self.doh_ports:
                    continue

                server_port = tcp.dport if tcp.dport in self.doh_ports else tcp.sport
                is_client_to_server = tcp.dport == server_port

                if is_client_to_server:
                    key = (ip_layer.src, tcp.sport, ip_layer.dst, tcp.dport)
                else:
                    key = (ip_layer.dst, tcp.dport, ip_layer.src, tcp.sport)

                if key not in flows:
                    flows[key] = Flow(src_ip=key[0], src_port=key[1],
                                       dst_ip=key[2], dst_port=key[3])

                flow = flows[key]
                direction = "out" if is_client_to_server else "in"
                wire_len = len(pkt) if hasattr(pkt, "__len__") else int(getattr(ip_layer, "len", 0))
                ts = float(pkt.time)
                flow.packets.append(Packet(timestamp=ts, length=wire_len, direction=direction))

                if is_client_to_server and flow.client_hello is None and bytes(tcp.payload):
                    info = _parse_client_hello(bytes(tcp.payload))
                    if info is not None:
                        flow.client_hello = info

        # Only keep flows that actually completed a TLS handshake-looking
        # exchange (at least a few packets each direction) -- filters out
        # scans / resets / incomplete captures.
        result = [f for f in flows.values() if len(f.packets) >= 4]
        for f in result:
            f.packets.sort(key=lambda p: p.timestamp)
        return result
