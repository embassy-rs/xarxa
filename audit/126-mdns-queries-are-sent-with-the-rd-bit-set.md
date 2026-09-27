# 126. mDNS queries are sent with the RD bit set

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/dns.rs:593](../src/dns.rs#L593) |
| Features | `mdns` |
| Verification | confirmed against the RFC text |

## Summary
`dispatch` sets `Flags::RECURSION_DESIRED` on every query, including those to 224.0.0.251 and ff02::fb. RFC 6762 says RD should be zero in multicast queries. Responders must ignore it, so the interop impact is nil.

## Details
src/dns.rs:593:
```rust
packet.set_flags(Flags::RECURSION_DESIRED);
```
It is unconditional, although `pq.mdns` is checked a few lines later to pick the port.

## RFC reference
RFC 6762 §18.6: "In both multicast query and multicast response messages, the Recursion Desired bit SHOULD be zero on transmission, and MUST be ignored on reception."

## Suggested fix
Set RD only when `pq.mdns` is `MulticastDns::Disabled`.
