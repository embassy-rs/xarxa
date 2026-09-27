# 280. Public docs of set_timeout, set_nagle_enabled and set_ack_delay do not match behavior

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2356](../src/tcp/mod.rs#L2356) (set_timeout), [src/tcp/mod.rs:2381](../src/tcp/mod.rs#L2381) (set_ack_delay), [src/tcp/mod.rs:2392](../src/tcp/mod.rs#L2392) (set_nagle_enabled), [src/tcp/mod.rs:1618](../src/tcp/mod.rs#L1618), [src/tcp/mod.rs:2033](../src/tcp/mod.rs#L2033) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Three public doc comments on `TcpSocket` do not match the code. `set_timeout` omits cases where the timeout is armed and does not say an RST is sent on expiry. `set_nagle_enabled` promises at most one sub-MSS segment in flight, which the ACK exemption breaks. `set_ack_delay` does not mention the 500 ms limit. The Nagle and ACK delay parts are covered in more detail by 282 and 281.

## Details
The `set_timeout` doc (mod.rs:2356-2368) lists three cases: after `connect`, with data in the transmit buffer, and with keep-alive on. `timeout_armed` also arms it in SYN-RECEIVED (after `accept`) and in FIN-WAIT-1, CLOSING and LAST-ACK whatever the transmit buffer holds. A queued FIN is not in `tx_buffer`, so `close()` with nothing else to send is not covered by the "data in the transmit buffer" case.

src/tcp/mod.rs:1618-1626:
```rust
fn timeout_armed(&self) -> bool {
    match self.state {
        State::Closed | State::TimeWait => false,
        State::SynSent | State::SynReceived | State::FinWait1 | State::Closing | State::LastAck => true,
        State::Established | State::FinWait2 | State::CloseWait => {
            !self.tx_buffer.is_empty() || self.keep_alive.is_some()
        }
    }
}
```

On expiry, dispatch moves to Closed with the tuple kept (mod.rs:1835-1838), and the Closed arm sends an RST (mod.rs:1962-1969).

Nagle is skipped when an ACK is due. src/tcp/mod.rs:2033:
```rust
if len < mss && self.nagle && offset != 0 && !want_fin && !self.ack_due(clock) {
```
The doc at mod.rs:2390-2392 says "it ensures at most only one segment smaller than MSS is in flight at a time".

`set_ack_delay` (mod.rs:2381-2383) stores any value. The doc only states the 10 ms default.

## Failure scenario
- A user sets a 5 s timeout and calls `close()`. The peer takes 6 s to ACK the FIN. The connection is aborted with an RST. The docs mention neither.
- A user relies on the Nagle guarantee and still sees many tinygrams in request/response traffic.
- `set_ack_delay(Some(Duration::from_secs(1)))` silently breaks MUST-40.

## RFC reference
RFC 9293 §3.8.6.3: "A TCP endpoint SHOULD implement a delayed ACK (SHLD-18), but an ACK should not be excessively delayed; in particular, the delay MUST be less than 0.5 seconds (MUST-40)."

## Suggested fix
Document the extra timeout cases (SYN-RECEIVED, unacknowledged FIN) and the RST on expiry. Document the ACK exception to Nagle. Document the ACK delay ceiling, or clamp it below 500 ms.
