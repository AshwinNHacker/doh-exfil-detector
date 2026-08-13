"""
cli.py
======

Command-line interface.

    doh-detector analyze  --pcap capture.pcap [--format json|md|html] [--out report.json]
    doh-detector analyze  --pcap capture.pcap --ports 443,8443 --min-score 15
"""

from __future__ import annotations

import argparse
import sys

from .capture import PcapLoader
from .features import FlowFeatureExtractor
from .fingerprint import ResolverFingerprintDB
from .detector import DoHDetector
from . import report as report_mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="doh-detector",
        description="Fingerprint anomalous DNS-over-HTTPS traffic from packet "
                    "metadata alone, without decrypting TLS.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a pcap/pcapng file")
    analyze.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    analyze.add_argument("--ports", default="443,8443",
                          help="Comma-separated TCP ports to treat as candidate DoH (default: 443,8443)")
    analyze.add_argument("--format", choices=["json", "md", "html"], default="json")
    analyze.add_argument("--out", default=None, help="Output file path (default: stdout)")
    analyze.add_argument("--min-score", type=int, default=0,
                          help="Only include findings with risk score >= this value")
    analyze.add_argument("--no-ml", action="store_true",
                          help="Disable Isolation Forest population-level outlier detection")
    analyze.add_argument("--db", default=None,
                          help="Path to a custom known_doh_resolvers.json")

    sub.add_parser("resolvers", help="List known DoH resolver fingerprints")

    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    ports = tuple(int(p.strip()) for p in args.ports.split(",") if p.strip())

    print(f"[*] Loading {args.pcap} (ports: {ports}) ...", file=sys.stderr)
    flows = PcapLoader(args.pcap, doh_ports=ports).extract_flows()
    print(f"[*] Reconstructed {len(flows)} TLS flow(s)", file=sys.stderr)

    fp_db = ResolverFingerprintDB(db_path=args.db)
    features = FlowFeatureExtractor(fingerprint_db=fp_db).transform(flows)

    detector = DoHDetector(use_ml=not args.no_ml)
    findings = detector.analyze(features)

    if args.min_score:
        findings = [f for f in findings if f.risk.total >= args.min_score]

    if args.format == "json":
        output = report_mod.to_json(findings, source=args.pcap)
    elif args.format == "md":
        output = report_mod.to_markdown(findings, source=args.pcap)
    else:
        output = report_mod.to_html(findings, source=args.pcap)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[+] Report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    high = sum(1 for f in findings if f.risk.severity == "high")
    return 2 if high else 0


def cmd_resolvers(args: argparse.Namespace) -> int:
    db = ResolverFingerprintDB()
    for sni in sorted(db.known_sni_suffixes()):
        print(sni)
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "resolvers":
        return cmd_resolvers(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
