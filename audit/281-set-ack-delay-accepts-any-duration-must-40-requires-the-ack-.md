# 281. set_ack_delay accepts any duration, MUST-40 requires the ACK delay to be under 0.5 s

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/tcp/mod.rs:2381](../src/tcp/mod.rs#L2381), [src/tcp/mod.rs:1579](../src/tcp/mod.rs#L1579) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`set_ack_delay(Some(d))` stores any duration up to `Duration::MAX` without capping or rejecting it. The doc does not mention a limit. A delay of 500 ms or more breaks MUST-40 and can make the peer's RTO fire. The 10 ms default is compliant, so this only happens through user configuration.

## Details
src/tcp/mod.rs:2381-2383:
```rust
pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
    self.inner_mut().ack_delay = duration
}
```
src/tcp/mod.rs:1579 arms the timer with it:
```rust
AckDelayTimer::Waiting(now + ack_delay)
```
Only a full MSS unacked or out-of-order data forces the ACK out earlier.

## Failure scenario
A user calls `set_ack_delay(Some(Duration::from_secs(1)))` to save ACKs. Each small request from the peer is ACKed 1 s late. The peer retransmits (Linux RTO minimum is 200 ms) and throughput collapses.

## RFC reference
RFC 9293 §3.8.6.3: "A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK should not be excessively delayed; in particular, the delay MUST be less than 0.5 seconds (MUST-40)."

## Suggested fix
Clamp the delay below 500 ms (or reject larger values) and document the limit.
