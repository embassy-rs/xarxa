# 262. Immediate ACK replies omit TSopt when the triggering segment lacked one, even on a timestamp connection

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:872](../src/tcp/mod.rs#L872) |
| Features | default (`tcp-timestamps`) |
| Verification | reproduced with a test |

## Summary
`ack_reply` adds TSopt only if the incoming segment carried one. On a connection that negotiated timestamps, a segment without TSopt gets an ACK with no TSopt. This covers challenge ACKs, out-of-window ACKs and ack-of-old-data replies. RFC 7323 requires TSopt on every non-RST segment. `process()` also never drops non-RST segments without TSopt (a SHOULD).

## Details
src/tcp/mod.rs:872:
```rust
reply_repr.timestamp = repr
    .timestamp
    .and_then(|tcp_ts| self.timestamp_repr(_now, tcp_ts.tsval));
```
`dispatch` instead uses `self.timestamp_repr(now, self.last_remote_tsval)`.

## Failure scenario
On a timestamp connection, a SYN without TSopt arrives in ESTABLISHED (RFC 5961 case), or a middlebox strips TSopt from a segment. The challenge ACK goes out without TSopt. A strict peer following RFC 7323 §3.2 drops it, and the RFC 5961 exchange does not complete. Impact is small since the trigger is itself a peer violation.

## RFC reference
RFC 7323 §3.2: "Once TSopt has been successfully negotiated, that is both <SYN> and <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST> segment for the duration of the connection ... If a non-<RST> segment is received without a TSopt, a TCP SHOULD silently drop the segment."

## Reproduction
Test in the `src/tcp/mod.rs` `mod test` harness, scratch copy, run with `cargo test --lib vv_f -- --nocapture`:
```rust
#[test]
fn vv_f1_ack_reply_no_tsopt() {
    let mut s = socket_established();
    s.timestamps = true;
    s.last_remote_tsval = 500;
    let r = send(&mut s, Instant::from_millis(100), &TcpRepr {
        seq_number: REMOTE_SEQ + 1 + 1000, ack_number: Some(LOCAL_SEQ + 1),
        payload: &b"x"[..], ..SEND_TEMPL }).expect("expected ack");
    assert!(r.timestamp.is_some(), "F1: ACK on timestamp connection lacks TSopt");
}
```
Output:
```
F1 reply timestamp: None
panicked: F1: ACK on timestamp connection lacks TSopt
```

## Suggested fix
Use `self.timestamp_repr(now, self.last_remote_tsval)` unconditionally in `ack_reply`. It already returns `None` when timestamps are not negotiated. Optionally drop non-RST segments without TSopt on timestamp connections.
