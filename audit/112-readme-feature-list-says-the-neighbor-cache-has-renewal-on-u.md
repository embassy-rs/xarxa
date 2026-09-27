# 112. README says the neighbor cache has "renewal on use", but sending never renews an entry

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [README.md:79](../README.md#L79), [src/neighbor.rs:169](../src/neighbor.rs#L169), [src/neighbor.rs:270](../src/neighbor.rs#L270) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The README is the crate docs (`#![doc = include_str!("../README.md")]` in src/lib.rs). It lists "Neighbor cache with expiry, renewal on use." Only traffic received from the neighbor renews an entry. An entry used only for sending expires 60 s after it was filled, and the next packet is parked while the neighbor is resolved again.

## Details
README.md:79:
```text
  - Neighbor cache with expiry, renewal on use.
```
src/neighbor.rs:169, egress lookup takes `&self` and never touches `expires_at`:
```rust
    pub(crate) fn lookup(&self, key: &Key, timestamp: Instant) -> Answer {
```
src/neighbor.rs:270, the only renewal, on ingress from a matching MAC and IP:
```rust
                expires_at: timestamp + Self::ENTRY_LIFETIME,
```
The internal docs at src/neighbor.rs:146 already say entries expire unless traffic from the neighbor refreshes them. The README says otherwise.

## Failure scenario
A one-way UDP telemetry stream to a collector that never sends back. Every 60 s the entry expires, a datagram is parked and an ARP request goes out. The user expected "renewal on use" to prevent that.

## Suggested fix
Reword to "Neighbor cache with expiry, renewed by traffic from the neighbor."
