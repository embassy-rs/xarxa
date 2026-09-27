# 267. ACK field of data segments ignored while our receive window is zero

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1125](../src/tcp/mod.rs#L1125) |
| Features | default |
| Verification | reproduced with a test |

## Summary
With a zero receive window, a data segment at RCV.NXT goes to the `(false, true)` case, which returns an ACK without processing SEG.ACK or SEG.WND. Peers that send 1-byte zero-window probes (lwIP, xarxa itself), or data in a bidirectional transfer, have their ACKs of our data ignored. Pure ACKs are still processed.

## Details
src/tcp/mod.rs:1125
```rust
(false, true) => {
    debug!("non-zero-length segment with zero receive window, will only send an ACK");
    false
}
```
The not-in-window path returns before ACK processing further down.

## Failure scenario
Bidirectional transfer. Our app stops reading and our window reaches zero. The peer's 1-byte probes acknowledge our outstanding data, but they are discarded whole. Our tx data stays unacknowledged and our retransmit timer can fire needlessly.

## RFC reference
RFC 9293 §3.10.7.4: "If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs." (lowercase should)

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn vv_f8_zero_window_ack_ignored() {
    let mut s = socket_established();
    s.view().send_slice(b"abcdef").unwrap();
    recv(&mut s, Instant::from_millis(0), 1, |_, _| {});
    send!(s, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &[0u8; 64][..], ..SEND_TEMPL });
    recv(&mut s, Instant::from_millis(100), 1, |_, r| println!("F8 our ack: {}", r));
    assert_eq!(s.remote_last_win, 0);
    let r = send(&mut s, Instant::from_millis(200), &TcpRepr { seq_number: REMOTE_SEQ + 1 + 64, ack_number: Some(LOCAL_SEQ + 1 + 6), payload: &b"z"[..], ..SEND_TEMPL });
    assert_eq!(s.tx_buffer.len(), 0);
}
```
Output: our ACK shows `win=0`; after the probe `tx_buffer.len()` is 6, assertion fails.

## Suggested fix
When SEG.SEQ == RCV.NXT and the window is zero, process the ACK and window fields, then drop the text.
