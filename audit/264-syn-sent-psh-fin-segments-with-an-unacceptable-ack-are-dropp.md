# 264. SYN-SENT: PSH/FIN segments with an unacceptable ACK are dropped instead of answered with RST

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1020](../src/tcp/mod.rs#L1020), [src/tcp/mod.rs:1034](../src/tcp/mod.rs#L1034) |
| Features | default |
| Verification | reproduced with a test |

## Summary
In SYN-SENT only a segment with `TcpControl::None` and a bad ACK gets an RST. A PSH|ACK or FIN|ACK with an unacceptable ACK falls into the `(State::SynSent, _, _)` arm and is dropped silently. A half-open peer is not told to reset, so cleanup is slower.

## Details
src/tcp/mod.rs:1020: the RST path exists only for `(State::SynSent, TcpControl::None, Some(ack_number))`. Everything else ends at:

src/tcp/mod.rs:1034
```rust
(State::SynSent, _, _) => {
    debug!("expecting a SYN|ACK");
    return None;
}
```

## Failure scenario
A stale PSH|ACK from an old connection arrives while we are in SYN-SENT. No RST is sent. The peer keeps its half-open state.

## RFC reference
RFC 9293 §3.10.7.3: "If the ACK bit is set, If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so drop the segment and return) <SEQ=SEG.ACK><CTL=RST> and discard the segment."

This is not a numbered MUST.

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn vv_f5_synsent_psh_bad_ack() {
    let mut s = socket_syn_sent();
    let r = send(&mut s, Instant::from_millis(0), &TcpRepr { control: TcpControl::Psh, seq_number: REMOTE_SEQ, ack_number: Some(LOCAL_SEQ + 100), payload: &b"x"[..], ..SEND_TEMPL });
    assert!(matches!(r, Some(TcpRepr { control: TcpControl::Rst, .. })));
}
```
Output: reply `None`, assertion fails.

## Suggested fix
In SYN-SENT, answer any non-RST, non-SYN segment carrying an unacceptable ACK with `rst_reply`.
