# 266. Acceptability test ignores the FIN's sequence space: FIN coalesced with already-received data is dropped

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1097](../src/tcp/mod.rs#L1097) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`segment_end` excludes SYN and FIN. A retransmission of already-received data with a new FIN, where SEG.SEQ+SEG.LEN-1 == RCV.NXT, is judged out of window. We send an ACK and ignore the FIN. The close is delayed until the peer sends the FIN again.

## Details
src/tcp/mod.rs:1097
```rust
let segment_end = repr.seq_number + repr.payload.len();
```
The non-empty, open-window branch needs `window_start < segment_end`, which fails when `segment_end == RCV.NXT`. The segment then gets a plain ACK through the data exemption at src/tcp/mod.rs:1191 and the FIN is discarded.

## Failure scenario
Our ACK for "abc" is lost. The peer (for example Linux collapsing segments on retransmit) resends "abc"+FIN at the same sequence number. We ACK the data only and stay in ESTABLISHED. The FIN costs another RTT or RTO.

## RFC reference
RFC 9293 §3.10.7.4, segment acceptability tests: SEG.LEN counts SYN and FIN, and a segment with SEG.LEN > 0 and RCV.WND > 0 is acceptable if "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND".

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn vv_f7_fin_with_old_data() {
    let mut s = socket_established();
    send!(s, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &b"abc"[..], ..SEND_TEMPL });
    let r = send(&mut s, Instant::from_millis(0), &TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &b"abc"[..], ..SEND_TEMPL });
    assert_eq!(s.state, State::CloseWait);
}
```
Output: reply ACK `SeqNumber(-9997)`, state ESTABLISHED, assertion fails (left: Established, right: CloseWait).

## Suggested fix
Use `repr.segment_len()` for the acceptability test, then trim data and FIN separately.
