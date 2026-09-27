# 353. TCP soft ICMP errors are recorded without waking any waker

| | |
|---|---|
| Severity | info |
| Category | api |
| Location | [src/tcp/mod.rs:955](../src/tcp/mod.rs#L955), [src/udp.rs:1093](../src/udp.rs#L1093) |
| Features | default (`icmp-errors`, `async`) |
| Verification | confirmed against the code |

## Summary
On a synchronized connection, `process_icmp_error` stores the error for `take_icmp_error()` and wakes nothing. UDP wakes its RX waker for the same event and documents it. An async TCP user only sees the soft error on the next unrelated wake.

## Details
src/tcp/mod.rs:955-965:
```rust
self.icmp_error = Some(error);
match self.state {
    State::SynSent | State::SynReceived => { ... self.set_state(State::Closed); ... }
    _ => {
        trace!("icmp error {}, recorded as soft error", error);
    }
}
```
Only `set_state` wakes the wakers, so handshake aborts wake and soft errors do not. `TcpSocket::take_icmp_error` (src/tcp/mod.rs:2943) promises no wake, so this is an asymmetry with UDP, not a doc mismatch.

## Suggested fix
Wake `rx_waker` (and maybe `tx_waker`) when a soft error is recorded, and say so in `take_icmp_error`, as UDP does.
