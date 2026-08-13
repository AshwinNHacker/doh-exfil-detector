# doh-exfil-detector

**Fingerprints anomalous DNS-over-HTTPS (DoH) query patterns from packet metadata alone — without decrypting TLS.**

[![CI](https://github.com/AshwinNHacker/doh-exfil-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/AshwinNHacker/doh-exfil-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

DoH (RFC 8484) hides DNS query contents from network intermediaries by
wrapping them in TLS. That's a genuine privacy win for legitimate use — and
exactly why it has become a favored channel for C2 and data exfiltration:
firewalls and IDS/IPS that traditionally alerted on plaintext DNS anomalies
are blind once the traffic is inside HTTPS.

This tool doesn't try to see through that encryption. Instead it treats DoH
the way any passive observer on the wire actually can: as a stream of
**timing, size, and handshake metadata**. Malicious use of DoH — C2
beaconing, tunneled exfiltration — has a *behavioral* signature even when
its *contents* are invisible: machine-regular polling intervals, padded
fixed-size packets, upload-heavy byte ratios, and endpoints that don't match
any known public resolver. This tool fingerprints that behavior.

## Why "without decryption" matters

A detector that requires decrypting DoH traffic to work would:
1. Defeat the privacy properties DoH exists to provide.
2. Require a TLS-terminating MITM position most defenders don't have (and
   attackers can pin certificates or use resolvers a corporate MITM proxy
   doesn't cover).
3. Not generalize to encrypted-SNI / ECH deployments.

Every feature this tool computes — packet lengths, inter-arrival times, TCP
5-tuples, and the TLS **ClientHello** (which is sent unencrypted, before key
exchange, by design) — is visible to a NetFlow exporter, a SPAN port, or a
firewall log. That's the point: this approach works in the deployments where
defenders actually are.

## How it works

```
pcap/pcapng
    │
    ▼
┌─────────────────┐   TCP 5-tuple reconstruction on candidate DoH ports
│  capture.py      │   (443/8443 by default). Parses only the unencrypted
│  PcapLoader      │   TLS ClientHello for SNI + JA3 — never TLS app data.
└────────┬─────────┘
         ▼
┌─────────────────┐   Per-flow metadata → fixed feature vector:
│  features.py     │   size mean/stdev/entropy, IAT mean/stdev/CV,
│  FlowFeature-    │   duration, packets/sec, upload:download ratio,
│  Extractor        │   known-resolver match.
└────────┬─────────┘
         ▼
┌─────────────────┐   Explainable rule-based scoring (beaconing regularity,
│  scoring.py      │   size entropy collapse, upload-heavy, long sessions,
│  detector.py     │   unrecognized endpoint) + optional Isolation Forest
│                  │   population-level outlier pass for larger captures.
└────────┬─────────┘
         ▼
┌─────────────────┐   JSON (SIEM-ready) / Markdown (tickets) / HTML
│  report.py       │   (analyst review) findings report.
└──────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module-level
design and [`docs/DETECTION_METHODOLOGY.md`](docs/DETECTION_METHODOLOGY.md)
for the reasoning and research behind each detection rule, its known
limitations, and tuning guidance.

## Installation

```bash
git clone https://github.com/AshwinNHacker/doh-exfil-detector.git
cd doh-exfil-detector
pip install -e .
```

Requires Python 3.9+. Dependencies: `scapy`, `scikit-learn`, `numpy`.

## Quick start

A fully synthetic sample capture ships in `examples/` (see
[`scripts/generate_sample_pcap.py`](scripts/generate_sample_pcap.py) — no
real traffic or third-party data is captured or replayed):

```bash
doh-detector analyze --pcap examples/sample_traffic.pcap --format md
```

```
| Severity | Score | Flow | SNI / Resolver | ML Outlier | Top Reason |
|---|---|---|---|---|---|
| high | 70 | 10.0.0.55:52233->203.0.113.77:443 | cdn-edge-sync.example-bad.net | no | regular_beaconing |
| info | 0  | 10.0.0.21:51000->1.1.1.1:443       | Cloudflare | no | - |
| info | 0  | 10.0.0.22:51001->8.8.8.8:443       | Google Public DNS | no | - |
```

The flagged flow polls its destination every 10.0s ± 50ms (IAT
coefficient-of-variation 0.003), pads every packet to a fixed size (packet-size
entropy 0.14 bits), and talks to an SNI that matches no known public DoH
resolver — three independent, explainable signals of a tunneled channel, none
of which required looking inside the TLS session.

Run it on your own capture:

```bash
doh-detector analyze --pcap capture.pcap --format json --out report.json
doh-detector analyze --pcap capture.pcap --format html --out report.html --min-score 15
```

List the built-in known-resolver fingerprint database:

```bash
doh-detector resolvers
```

### CLI reference

```
doh-detector analyze --pcap PATH [options]

  --ports PORTS       Comma-separated candidate DoH TCP ports (default: 443,8443)
  --format {json,md,html}   Output format (default: json)
  --out PATH           Write to file instead of stdout
  --min-score N         Only include findings scoring >= N
  --no-ml               Disable the Isolation Forest outlier pass
  --db PATH             Use a custom known_doh_resolvers.json

Exit codes: 0 = clean, 2 = at least one HIGH severity finding (useful for
CI/pipeline gating), 1 = usage/runtime error.
```

### Library usage

```python
from doh_detector import PcapLoader, FlowFeatureExtractor, DoHDetector
from doh_detector.report import to_json

flows = PcapLoader("capture.pcap").extract_flows()
features = FlowFeatureExtractor().transform(flows)
findings = DoHDetector().analyze(features)

for f in findings:
    if f.risk.severity in ("high", "medium"):
        print(f.flow.flow_id, f.risk.total, [c.rule for c in f.risk.components])

print(to_json(findings, source="capture.pcap"))
```

## Detection signals

| Signal | Rule | What it catches |
|---|---|---|
| Beaconing | `regular_beaconing` | Near-constant polling interval (IAT coefficient of variation < 0.15) — the classic C2/automated-exfil timing fingerprint, distinct from bursty/irregular human browsing. |
| Padding collapse | `low_size_entropy` | Packet-size Shannon entropy < 1.5 bits — tunneling tools frequently pad payloads to a small set of fixed block sizes. |
| Volume shape | `upload_heavy` | Upload:download byte ratio > 3.0 — DNS is naturally download-heavy; exfiltration flips that. |
| Query rate | `high_query_rate` | Sustained packets/sec far above interactive DoH lookup cadence. |
| Session shape | `long_lived_session` | Long-duration, high-packet-count sessions — DoH's normal unit of work is a single request/response pair. |
| Endpoint context | `unrecognized_resolver_endpoint` | SNI/IP doesn't match any resolver in the known-public-DoH fingerprint database. |
| Population outlier | Isolation Forest | Flows that are statistical outliers relative to the rest of the capture, even if no single rule fires (requires ≥15 flows to activate). |

Every finding lists exactly which rules fired and why — there is no opaque
black-box score. See `docs/DETECTION_METHODOLOGY.md` for false-positive
sources (VPN/corporate DoH proxies, IoT heartbeat-like polling, backup/sync
software) and tuning guidance.

## Project layout

```
doh-exfil-detector/
├── src/doh_detector/       # library + CLI source
│   ├── capture.py           # pcap parsing, flow reconstruction, TLS ClientHello/JA3
│   ├── features.py          # metadata → feature vector
│   ├── fingerprint.py       # known-DoH-resolver matching
│   ├── scoring.py           # explainable rule-based risk scoring
│   ├── detector.py          # orchestration + Isolation Forest outlier pass
│   ├── report.py            # JSON / Markdown / HTML report rendering
│   └── cli.py                # `doh-detector` command-line entrypoint
├── data/known_doh_resolvers.json   # public DoH resolver fingerprint DB
├── scripts/generate_sample_pcap.py # synthetic demo/test traffic generator
├── examples/                        # sample pcap + rendered reports
├── tests/                            # pytest suite (34 tests, 95% coverage)
├── docs/
│   ├── ARCHITECTURE.md
│   └── DETECTION_METHODOLOGY.md
└── .github/workflows/ci.yml
```

## Development

```bash
pip install -e ".[dev]"
pytest -v --cov=doh_detector --cov-report=term-missing
```

## Limitations & responsible use

- This is a **fingerprinting / triage aid**, not a definitive verdict.
  Rule-based scores are explainable but heuristic; validate flagged flows
  before acting on them, especially before blocking traffic.
- Thresholds in `scoring.py` are starting points calibrated against the
  bundled synthetic sample, not a production baseline. Retune against your
  own network's normal DoH traffic — see `docs/DETECTION_METHODOLOGY.md`.
- JA3 here covers TLS 1.2-style ClientHello fields (version, cipher suites,
  extension IDs); elliptic-curve/point-format extensions are omitted from
  the hash input for simplicity, so hashes won't match the reference JA3
  implementation byte-for-byte. Treat JA3 as a same-client-across-flows
  correlator, not a value to diff against third-party JA3 blocklists as-is.
- Built and intended for defensive network monitoring, threat hunting, and
  security research/education. It does not decrypt, intercept, or exfiltrate
  anyone's traffic — it only ever reads unencrypted packet metadata and the
  unencrypted TLS ClientHello.

## License

MIT — see [LICENSE](LICENSE).
