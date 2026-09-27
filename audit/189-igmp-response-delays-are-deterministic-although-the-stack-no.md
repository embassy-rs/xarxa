# 189. IGMP response delays are deterministic, although the stack has a PRNG

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/multicast.rs:460](../src/multicast.rs#L460), [src/multicast.rs:480](../src/multicast.rs#L480), [src/multicast.rs:424](../src/multicast.rs#L424) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
General queries are answered at fixed steps: 100 ms for v1, `max_resp_time / (n + 1)` for v2. Group-specific queries are answered at exactly `max_resp_time / 4`. RFC 2236 asks for independent random delays in (0, Max Resp Time]. This is a documented decision (private comment at line 424), but its reason, no RNG, no longer holds: MLD already uses `inner.rand` (line 571).

## Details
src/multicast.rs:460:
```rust
IgmpVersion::Version1 => Duration::from_millis(100),
```
src/multicast.rs:480:
```rust
let timeout = max_resp_time / 4;
```
Identical xarxa hosts answer the same query at the same instants. For v1 (max resp 0, meaning 10 s) reports are packed into 100 ms steps instead of spread over 10 s. They only overrun 10 s with more than about 99 groups, which needs `alloc`. Together with 190 (no suppression), every host reports every group in synchronized bursts.

## RFC reference
RFC 2236 §3: "Each timer is set to a different random value, using the highest clock granularity available on the host, selected from the range (0, Max Response Time] with Max Response Time as specified in the Query packet."

RFC 2236 §4: "The IGMPv1 router will send General Queries with the Max Response Time set to 0. This MUST be interpreted as a value of 100 (10 seconds)."

The §3 randomization is not phrased as a MUST.

## Suggested fix
Draw delays from `inner.rand` in (0, max_resp], as `process_mldv2` does.
