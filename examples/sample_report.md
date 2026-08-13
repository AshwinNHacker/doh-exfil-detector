# DoH Exfiltration Detection Report

- **Source:** `examples/sample_traffic.pcap`
- **Generated:** 2026-08-11T18:42:09.341162+00:00
- **Flows analyzed:** 5
- **Flagged (score >= 15):** 1

| Severity | Score | Flow | SNI / Resolver | ML Outlier | Top Reason |
|---|---|---|---|---|---|
| high | 70 | `10.0.0.55:52233->203.0.113.77:443` | cdn-edge-sync.example-bad.net | no | regular_beaconing |
| info | 0 | `10.0.0.21:51000->1.1.1.1:443` | Cloudflare | no | - |
| info | 0 | `10.0.0.22:51001->8.8.8.8:443` | Google Public DNS | no | - |
| info | 0 | `10.0.0.23:51002->9.9.9.9:443` | Quad9 | no | - |
| info | 0 | `10.0.0.21:51003->1.1.1.1:443` | Cloudflare | no | - |

## Details

### 10.0.0.55:52233->203.0.113.77:443 -- HIGH (70/100)
- Destination: `203.0.113.77:443` (SNI: `cdn-edge-sync.example-bad.net`, resolver: unrecognized)
- JA3: `f75e7ba4fa292e9e25e0bd8c58826664`
  - **regular_beaconing** (+30): IAT coefficient of variation 0.003 < 0.15 (mean interval 10.01s) -- traffic timing is machine-regular.
  - **low_size_entropy** (+20): Packet-size entropy 0.14 bits < 1.5 -- traffic uses very few distinct packet sizes (possible fixed-size padding).
  - **long_lived_session** (+10): Flow lasted 250.4s across 51 packets -- unusually long-lived for discrete DNS resolution.
  - **unrecognized_resolver_endpoint** (+10): Destination cdn-edge-sync.example-bad.net does not match any resolver in the known-DoH fingerprint database -- confirm this is an authorized enterprise/private resolver.