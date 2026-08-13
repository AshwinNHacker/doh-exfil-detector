# Detection Methodology

## Threat model

DoH wraps DNS queries in HTTPS specifically so that on-path observers cannot
read query contents. That's the point of the protocol (RFC 8484) and this
tool does not try to defeat it. Instead it targets a narrower, adjacent
problem: **DoH used as a covert channel** — for C2 check-ins or data
exfiltration — has behavioral properties that differ from DoH used for its
intended purpose (resolving names a user or application actually needs),
even though the *contents* of both are equally invisible.

The detector assumes the position of a realistic defender: someone with
visibility into packet headers (a SPAN port, NetFlow/IPFIX, a firewall
connection log) but no ability to decrypt TLS. Every feature below is
computed from information available at that vantage point.

## Signal-by-signal rationale

### 1. Beaconing regularity (`regular_beaconing`)
**What it measures:** the coefficient of variation (stdev/mean) of
inter-arrival time between successive client-initiated packets in a flow.

**Why it's a signal:** human-driven DNS resolution (a user browsing, an app
occasionally looking up a hostname) has irregular timing driven by user
behavior. Automated polling — C2 check-ins, scheduled exfil batches — tends
toward a fixed interval with only network-jitter-level variance. This is
the same underlying principle used in classical network-based C2 beacon
detection (see e.g. Cisco/Talos and various SANS/DFIR writeups on
"beaconing detection via timing analysis"), applied here specifically to
DoH's request cadence rather than raw TCP/NetFlow session timing.

**Known false positives:** legitimate scheduled/heartbeat traffic —
health-check pings, IoT device check-ins, some backup/sync tools, monitoring
agents — can also beacon at fixed intervals. This is why beaconing alone
(30 points) doesn't reach "high" severity; it needs to combine with at
least one other signal.

### 2. Packet-size entropy collapse (`low_size_entropy`)
**What it measures:** Shannon entropy of the on-wire packet-size
distribution within a flow.

**Why it's a signal:** legitimate DNS responses vary in size with the
answer (an A record vs. a CNAME chain vs. an SPF TXT record produce
different response sizes), so organic DoH traffic has moderate-to-high size
entropy. Tunneling/exfiltration tools frequently pad application data to a
small number of fixed block sizes (for framing/protocol simplicity, or
deliberately to blend in) — collapsing entropy toward zero.

**Known false positives:** some DoH implementations do fixed-size padding
themselves as an anti-fingerprinting privacy measure (RFC 8467, EDNS(0)
padding) — this is a real source of false positives and is called out
explicitly so analysts don't over-trust this signal alone.

### 3. Upload-heavy byte ratio (`upload_heavy`)
**What it measures:** bytes sent by the client divided by bytes received.

**Why it's a signal:** DNS is structurally download-heavy — a small query,
a larger response. A flow where the client sends significantly more than
it receives is shaped like data leaving the network, not name resolution
happening.

**Known false positives:** DoH implementations that batch many queries
per HTTP/2 connection (query pipelining) can look upload-heavier than a
single lookup; large TXT-record-based provisioning/config-pull use cases
also skew this ratio without being malicious.

### 4. Sustained high query rate (`high_query_rate`)
**What it measures:** packets/sec over the flow's duration.

**Why it's a signal:** interactive DoH lookups are sparse relative to
tunneling, where a channel needs sustained throughput to move data.

**Known false positives:** a DoH resolver aggressively prefetching/caching
for a busy client (many tabs, many services) can generate high legitimate
query rates.

### 5. Long-lived session shape (`long_lived_session`)
**What it measures:** flow duration combined with packet count.

**Why it's a signal:** DoH's unit of work is normally a discrete
request/response over a short-lived or reused-but-idle connection. A
session that stays busy (many packets) for minutes at a time looks more
like a persistent tunnel than repeated independent lookups.

**Known false positives:** HTTP/2 connection reuse by a busy browser or a
long-running application doing legitimate periodic resolution.

### 6. Unrecognized resolver endpoint (`unrecognized_resolver_endpoint`)
**What it measures:** whether the flow's SNI/destination IP matches
`data/known_doh_resolvers.json`, a curated list of major public DoH
providers (Cloudflare, Google, Quad9, NextDNS, AdGuard, and others).

**Why it's a signal:** malware authors often stand up custom
resolver-shaped infrastructure rather than routing through a well-known
provider (which may be monitored, rate-limited, or logged by the
provider itself).

**Known false positives — this is the single biggest source in this
tool.** Enterprise/private DoH resolvers, self-hosted `dnscrypt-proxy` or
`cloudflared` deployments, regional/ISP-specific resolvers, and newer
public providers not yet in the bundled list will all show up here. This
signal contributes only 10 points and is meant as *context* ("confirm this
is an authorized resolver"), never a standalone verdict. **Extend
`data/known_doh_resolvers.json` with your organization's approved
resolvers before relying on this signal.**

### 7. Population-level outlier detection (Isolation Forest)
**What it measures:** whether a flow's full feature vector (packet rate,
size stats, entropy, ratios, timing, duration) is a statistical outlier
relative to every other flow in the same capture.

**Why it's useful:** catches flows that don't individually cross any single
rule's threshold but are anomalous *relative to this network's own
baseline* — e.g., a network where typical DoH sessions are unusually chatty
would have different "normal" thresholds than the defaults calibrated here.

**Requirements & limits:** needs at least 15 flows in the capture to fit
meaningfully (`MIN_FLOWS_FOR_ML` in `detector.py`); with too few flows there
isn't enough population to define "outlier" against, so the model is
skipped rather than producing an unreliable result. Isolation Forest also
has no concept of *which* behavior was anomalous — it only boosts an
already-computed rule-based score, it never fires on its own.

## Tuning for your environment

The defaults in `scoring.py` (`THRESHOLDS`) are starting points calibrated
against the bundled synthetic sample (`scripts/generate_sample_pcap.py`),
**not** a production baseline for any real network. Before relying on this
in production:

1. Run `doh-detector analyze` against a known-clean capture from your own
   network for a representative period (a day of normal traffic is a
   reasonable start).
2. Inspect the `iat_cv`, `size_entropy`, and `upload_download_ratio`
   distributions of flows that scored "info"/"low" — these are your
   organization's actual normal ranges, which may differ from the defaults
   depending on which DoH clients (browsers, OS-level DoH, resolver
   software) are common on your network.
3. Adjust `THRESHOLDS` accordingly (via `RiskScorer(thresholds={...})` in
   code, or by editing `scoring.py`) so your known-benign traffic scores
   "info", leaving headroom before "low"/"medium".
4. Populate `data/known_doh_resolvers.json`'s `resolver_client_ja3` section
   and the `resolvers` list with any internal/enterprise DoH endpoints your
   organization runs or authorizes.

## What this tool does *not* do

- It does not decrypt TLS, terminate connections, or require a MITM
  position. It never has access to DoH query/response contents.
- It is not a signature-based IOC matcher against known-bad
  infrastructure — `fingerprint.py` only encodes *known-good* public
  resolvers, deliberately, since bad-infrastructure IOC lists go stale fast
  and are out of scope for a metadata-only OSS tool.
- It does not make blocking decisions. Findings are intended for analyst
  triage, alerting, or feeding a downstream SOAR/SIEM pipeline — not for
  automated traffic blocking without human review, given the false-positive
  sources documented above.
