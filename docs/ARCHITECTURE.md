# Architecture

## Design goals

1. **No decryption, ever.** The only TLS bytes parsed are the ClientHello,
   which is sent in the clear before key exchange. This is a hard
   architectural boundary, not a policy note — `capture.py` never touches
   any TLS record after the handshake begins, and there is no code path in
   this project that has access to key material.
2. **Explainable over opaque.** The primary scoring mechanism
   (`scoring.py`) is a set of named, human-readable rules with capped point
   values, not a black-box classifier. An analyst reading a finding can see
   exactly which behaviors triggered it and why. The optional ML layer
   (`detector.py`, Isolation Forest) is additive context, not a
   replacement.
3. **Degrade gracefully.** Every stage works on a single pcap with as few
   as one flow. Population-level statistics (Isolation Forest) require a
   minimum flow count and silently skip themselves below that threshold
   rather than producing meaningless output.
4. **Small, inspectable dependency surface.** `scapy` for packet parsing,
   `scikit-learn`/`numpy` for the optional outlier pass. No web framework,
   no database, no network calls at runtime — this can run air-gapped on a
   pcap someone hands you on a USB stick.

## Data flow

```
                    ┌────────────┐
   capture.pcap ───▶│  capture.py │──▶ List[Flow]
                    └────────────┘
                          │  Flow = 5-tuple + ordered Packet[] (ts, len, dir)
                          │        + optional ClientHelloInfo (sni, ja3)
                          ▼
                    ┌────────────┐
                    │ features.py │──▶ List[FlowFeatures]
                    └────────────┘
                          │  fixed-width numeric vector per flow, plus
                          │  resolver-fingerprint match context
                          ▼
                    ┌────────────┐
                    │ detector.py │──▶ List[Finding]  (sorted, highest risk first)
                    │  ├─ scoring.py (rule-based, always runs)
                    │  └─ IsolationForest (optional, needs >=15 flows)
                    └────────────┘
                          │
                          ▼
                    ┌────────────┐
                    │  report.py  │──▶ JSON / Markdown / HTML string
                    └────────────┘
```

## Module responsibilities

### `capture.py`
- `PcapLoader.extract_flows()` streams a pcap with `scapy.PcapReader`
  (constant memory, doesn't load the whole file), filters to TCP traffic on
  candidate DoH ports (default 443/8443, configurable for DoH proxies on
  nonstandard ports), and reconstructs bidirectional flows keyed by 5-tuple.
- `_parse_client_hello` manually parses the TLS record + handshake header
  (version, cipher suites, extensions, SNI) using `struct`, rather than
  pulling in `scapy.layers.tls` — this keeps the dependency footprint
  small and makes the exact set of bytes read auditable in one function.
- Flows with fewer than 4 packets are dropped (usually scans / RSTs /
  incomplete captures, not real DoH sessions).

### `features.py`
- Converts a `Flow` into a `FlowFeatures` dataclass: volume, packet-size
  distribution (mean/stdev/Shannon entropy), timing (IAT mean/stdev/CV
  computed from **client-to-server packets only** — mixing in server
  response latency would dilute a slow polling interval with fast
  handshake noise), session shape, and resolver-fingerprint match.
- Depends on `fingerprint.py` for the known-resolver context but has no
  detection logic of its own — this module produces *measurements*, not
  *verdicts*.

### `fingerprint.py`
- Loads `data/known_doh_resolvers.json` (SNI hostnames + IPs for major
  public DoH providers) into lookup indices.
- `match()` returns whether a flow's SNI/IP/JA3 corresponds to a known
  public resolver. This is deliberately *not* used as a standalone
  malicious/benign flag (see README limitations) — it's one input to
  `scoring.py`.

### `scoring.py`
- Pure functions over a `FlowFeatures` object; no I/O, no state. Each rule
  is independently testable (see `tests/test_scoring.py`) and contributes a
  capped point value with a human-readable `detail` string.
- Thresholds live in one `THRESHOLDS` dict, overridable per-instance via
  `RiskScorer(thresholds={...})` without touching rule logic.

### `detector.py`
- `DoHDetector.analyze()` runs `RiskScorer` over every flow, then
  optionally fits an `IsolationForest` across the whole flow population and
  boosts (never solely determines) the score of statistical outliers.
  This two-layer design means a capture with only 2-3 flows still gets a
  fully explainable result, while a capture with hundreds of flows gets the
  benefit of population statistics too.

### `report.py`
- Three renderers (`to_json`, `to_markdown`, `to_html`) over the same
  `List[Finding]` — no shared mutable state, no template engine dependency.

### `cli.py`
- Thin argparse wrapper. Exit code `2` on any HIGH severity finding is
  intentional, for use as a CI/pipeline gate (e.g. "fail the build if a
  pcap fixture trips a HIGH finding").

## Extension points

- **Live capture**: `capture.py` is pcap-file-based today; swapping
  `scapy.PcapReader` for `scapy.sniff(prn=...)` with the same flow-assembly
  logic would add live-interface support without touching downstream
  modules (features/scoring/detector/report are all capture-source
  agnostic — they only depend on the `Flow`/`Packet` dataclasses).
- **JA3S / server fingerprints**: `capture.py` only parses ClientHello
  today; ServerHello parsing (for JA3S) would slot into the same
  `_parse_tls_*` family and attach to `Flow` the same way.
- **Threat-intel enrichment**: `fingerprint.py`'s `match()` is the natural
  seam for adding IP reputation / ASN lookups — deliberately not included
  in this OSS build to keep it dependency-light and runnable air-gapped.
