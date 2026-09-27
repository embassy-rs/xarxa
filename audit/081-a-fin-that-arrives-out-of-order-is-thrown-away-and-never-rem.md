# 081. A FIN that arrives out of order is thrown away and never remembered, so the connection only closes after the peer retransmits the FIN

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1236](../src/tcp/mod.rs#L1236), [src/tcp/mod.rs:1527](../src/tcp/mod.rs#L1527), [src/tcp/mod.rs:1560](../src/tcp/mod.rs#L1560), [src/tcp/mod.rs:1312](../src/tcp/mod.rs#L1312), [src/tcp/mod.rs:6174](../src/tcp/mod.rs#L6174), [src/tcp/mod.rs:1097](../src/tcp/mod.rs#L1097) |
| Features | default |
| Verification | reproduced with a test |

## Summary

When a segment carrying a FIN arrives above a hole, its data goes into the assembler but the FIN is cleared and not recorded. When the hole is filled, the data becomes contiguous but the FIN is never processed. The socket stays ESTABLISHED, ACKs FIN-1, and `recv` returns `Ok(0)` instead of `Finished` until the peer retransmits the FIN. Every connection whose last segment is reordered or follows a loss pays one peer RTO of EOF latency. The behaviour was inherited from smoltcp.

## Details

src/tcp/mod.rs:1234:

```rust
// If a FIN is received at the end of the current segment, but
// we have a hole in the assembler before the current segment, disregard this FIN.
if control == TcpControl::Fin && window_start < segment_start {
    trace!(...);
    control = TcpControl::None;
}
```

The payload is still stored (`add_then_remove_front` at src/tcp/mod.rs:1527, `enqueue_unallocated` at src/tcp/mod.rs:1560). No state records that a FIN sits at the end of the stored range. When a later segment fills the hole, `contig_len` covers the stored bytes, but the `(State::Established, TcpControl::Fin)` arm at src/tcp/mod.rs:1312 is not reached, because the filling segment has no FIN.

The existing test `test_established_fin_after_missing` (src/tcp/mod.rs:6174) asserts this behaviour: ACK 12 rather than 13, state stays Established.

Recovery depends on the peer. A bare FIN retransmission at the right sequence number closes the connection. A retransmission of the whole last segment (data + FIN) is judged entirely old, because the acceptability test ignores the FIN's sequence space (known issue, src/tcp/mod.rs:1097). It is dropped each time.

## Failure scenario

1. The peer sends its last segment, bytes 4..8 + FIN. It arrives before bytes 0..4 (reordering or loss).
2. Bytes 0..4 arrive. xarxa ACKs 8, not 9. State stays ESTABLISHED. `recv` returns the 8 bytes, then `Ok(0)`.
3. The peer waits for its RTO. Linux resends a bare FIN at seq 8 and the socket moves to CLOSE-WAIT. A peer that resends the whole segment is dropped every time until it trims it.

Interop capture against Linux (`netem delay 10ms 3ms loss 1% reorder 10% 50%`, 3,000,000 bytes to the discard port):

```
12.010423 L>X Flags [FP.], seq 2998921:3000001            <- FIN arrives above a hole
12.010432 X>L ack 2988785, sack 2 {2998921:3000001}{...}   <- data SACKed, FIN dropped
12.011139..12.012598  hole-filling segments arrive
12.012607 X>L ack 3000001, win 31728                       <- should be 3000002
12.256106 L>X Flags [FP.], seq 3000001, length 0           <- Linux resends the FIN after ~245 ms
12.256141 X>L ack 3000002
```

The IPv6 run of the same test showed the same pattern. The delay is at least 200 ms against Linux and at least 1 s against a peer that follows the RFC 6298 minimum RTO.

## RFC reference

RFC 9293 §3.10.7.4, first check:

> One could tailor actual segments to fit this assumption by trimming off any portions that lie outside the window (including SYN and FIN) and only processing further if the segment then begins at RCV.NXT. Segments with higher beginning sequence numbers SHOULD be held for later processing (SHLD-31).

The FIN is part of the segment that should be held. Here the data is held and the FIN is dropped.

## Reproduction

Test added to `mod test` in src/tcp/mod.rs of an unmodified copy of HEAD:

```rust
#[test]
fn zz_ooo_fin_forgotten() {
    let mut s = socket_established();
    send!(s, TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1 + 4,
        ack_number: Some(LOCAL_SEQ + 1), payload: &b"efgh"[..], ..SEND_TEMPL },
        Some(TcpRepr { seq_number: LOCAL_SEQ + 1, ack_number: Some(REMOTE_SEQ + 1), ..RECV_TEMPL }));
    let r = send(&mut s, Instant::from_millis(0), &TcpRepr { seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1), payload: &b"abcd"[..], ..SEND_TEMPL });
    println!("reply ack {:?}; ack covering FIN would be {:?}", r.map(|r| r.ack_number), REMOTE_SEQ + 1 + 9);
    println!("state {:?} rx_fin_received {}", s.state, s.rx_fin_received);
    let mut buf = [0u8; 64];
    println!("recv_slice {:?}", s.view().recv_slice(&mut buf));
    println!("recv_slice again {:?}", s.view().recv_slice(&mut buf));
    let mut sent = vec![];
    recv(&mut s, Instant::from_millis(5000), 0, |_, r| sent.push(r.ack_number));
    assert_eq!(s.state, State::Established, "FIN at 8 was forgotten");
    for i in 0..3 {
        let r = send(&mut s, Instant::from_millis(6000 + i * 1000), &TcpRepr { control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1 + 4, ack_number: Some(LOCAL_SEQ + 1), payload: &b"efgh"[..], ..SEND_TEMPL });
        println!("whole-segment retx {}: reply ack {:?}, state {:?}", i, r.map(|r| r.ack_number), s.state);
    }
    let r = send(&mut s, Instant::from_millis(10000), &TcpRepr { control: TcpControl::Fin,
        seq_number: REMOTE_SEQ + 1 + 8, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL });
    println!("bare FIN retx: reply ack {:?}, state {:?}", r.map(|r| r.ack_number), s.state);
}
```

`cargo test --lib zz_ -- --nocapture --test-threads=1`:

```
reply ack Some(Some(SeqNumber(-9992))); ack covering FIN would be SeqNumber(-9991)
state Established rx_fin_received false
recv_slice Ok(8)
recv_slice again Ok(0)
whole-segment retx 0: reply ack Some(Some(SeqNumber(-9992))), state Established
whole-segment retx 1: reply ack Some(Some(SeqNumber(-9992))), state Established
whole-segment retx 2: reply ack Some(Some(SeqNumber(-9992))), state Established
bare FIN retx: reply ack None, state CloseWait
test tcp::test::zz_ooo_fin_forgotten ... ok
```

## Suggested fix

When a FIN segment is stored out of order, remember the FIN's sequence number (for example `rx_fin_seq`). When `enqueue_unallocated` makes the contiguous data reach it, process the FIN as if it had just arrived. Clear it on reset. Update `test_established_fin_after_missing` to expect the FIN to be ACKed. The acceptability issue at src/tcp/mod.rs:1097 should be fixed as well, so whole-segment retransmissions are accepted.
