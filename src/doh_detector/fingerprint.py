"""
fingerprint.py
==============

Matches a flow's SNI / destination IP / JA3 against a database of publicly
known DNS-over-HTTPS resolver endpoints. This is context, not a verdict:
traffic to an unknown resolver is not automatically malicious (it may be a
private/enterprise DoH resolver), and traffic to a known resolver is not
automatically benign (exfiltration tools frequently proxy through, or
directly abuse, well-known resolvers precisely because they're allow-listed
by firewalls). The detector therefore treats this as one signal of several
-- see scoring.py.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "known_doh_resolvers.json",
)


@dataclass
class FingerprintMatch:
    matched: bool
    name: Optional[str] = None
    matched_on: Optional[str] = None  # "sni" | "ip" | "ja3"


class ResolverFingerprintDB:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._sni_index: Dict[str, str] = {}
        self._ip_index: Dict[str, str] = {}
        self._benign_client_ja3: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.db_path):
            return
        with open(self.db_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for resolver in data.get("resolvers", []):
            name = resolver["name"]
            for sni in resolver.get("sni", []):
                self._sni_index[sni.lower()] = name
            for ip in resolver.get("ips", []):
                self._ip_index[ip] = name
        for ja3, label in data.get("resolver_client_ja3", {}).items():
            if ja3 != "_comment":
                self._benign_client_ja3[ja3] = label

    def match(self, sni: Optional[str] = None, ja3: Optional[str] = None,
              dst_ip: Optional[str] = None) -> FingerprintMatch:
        if sni:
            name = self._sni_index.get(sni.lower())
            if name:
                return FingerprintMatch(True, name, "sni")
        if dst_ip:
            name = self._ip_index.get(dst_ip)
            if name:
                return FingerprintMatch(True, name, "ip")
        if ja3 and ja3 in self._benign_client_ja3:
            return FingerprintMatch(True, self._benign_client_ja3[ja3], "ja3")
        return FingerprintMatch(False)

    def known_sni_suffixes(self) -> List[str]:
        return list(self._sni_index.keys())
