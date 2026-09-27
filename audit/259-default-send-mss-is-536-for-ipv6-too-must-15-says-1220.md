# 259. Default send MSS is 536 for IPv6 too (MUST-15 says 1220)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:596](../src/tcp/mod.rs#L596), [src/tcp/mod.rs:646](../src/tcp/mod.rs#L646), [src/tcp/listener.rs:113](../src/tcp/listener.rs#L113) |
| Features | ipv6 |
| Verification | confirmed against the RFC text |

## Summary
`DEFAULT_MSS = 536` is used when the peer's SYN or SYN|ACK has no MSS option, for both IP versions. IPv6 peers without the option get 536-byte segments instead of 1220. Conservative, so it costs throughput only.

## Details
src/tcp/mod.rs:596:
```rust
const DEFAULT_MSS: usize = 536;
```
Used in `new()` (mod.rs:646), in `reset()`, and in the listener's `PendingSyn` (listener.rs:113, `_ => DEFAULT_MSS`). On the SYN-SENT path `remote_mss` is only overwritten when an MSS option is present. No IP version check anywhere.

## Failure scenario
An IPv6 peer that omits the MSS option (some minimal or 6LoWPAN stacks) gets segments of at most 536 bytes. That is about 2.3x the packets.

## RFC reference
RFC 9293 §3.7.1: "If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15)."

## Suggested fix
Pick the default from the tuple's IP version.
