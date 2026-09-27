# 293. UDP bind docs say the socket sends only from/to the bound addresses, but send metadata overrides both

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/udp.rs:477](../src/udp.rs#L477), [src/udp.rs:787](../src/udp.rs#L787), [src/udp.rs:881](../src/udp.rs#L881) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The `bind` docs say a concrete local address means the socket sends only from it, a multicast or broadcast local address means it can't send, and a concrete remote means it sends only to it. `prepare_datagram` lets `meta.local_addr` override the bound local address and honours an explicit `meta.remote_addr`. `send_with`'s own doc says so, contradicting `bind`.

## Details
src/udp.rs:477:
```rust
/// - `Some(_)`: the socket sends/receives packets from/to the given local address only.
```
src/udp.rs:787:
```rust
/// specified destination is honored even on a connected socket.
```
src/udp.rs:881:
```rust
let src_addr = match meta.local_addr.or(local.concrete_addr()) {
```
Only unspecified destination parts are defaulted from the bound remote (src/udp.rs:850-857). A socket bound to 224.0.0.251:5353 can send when `meta.local_addr` names one of our addresses. Replies to such sends are dropped by the socket's own filters.

## Suggested fix
Reject metadata that contradicts the bind, or reword the `bind` docs: the bind filters receives and supplies send defaults, and metadata overrides them.
