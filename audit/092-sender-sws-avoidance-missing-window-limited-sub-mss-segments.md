# 092. Sender SWS avoidance missing: window-limited sub-MSS segments are sent whenever nothing is in flight

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:2033](../src/tcp/mod.rs#L2033), [src/tcp/mod.rs:2022](../src/tcp/mod.rs#L2022) |
| Features | default |
| Verification | reproduced with a test |

## Summary

The data loop in `dispatch` sends up to `min(tx_len, remote_win_len, cwnd) - offset`, capped at the MSS. The only hold-back for a small segment is Nagle, which needs data in flight. With nothing in flight, a small peer window and more data queued than fits, xarxa sends a tiny segment that fills the window. This violates RFC 9293 MUST-38 and leads to silly window syndrome, including between two xarxa peers (the receiver side has no SWS avoidance either).

## Details

src/tcp/mod.rs:2022:

```rust
let limit = tx_len.min(self.remote_win_len).min(self.congestion_controller.window());
loop {
    let offset = self.flight_size();
    let len = limit.saturating_sub(offset).min(mss);
    let control = data_control(offset, len);
    if len == 0 && control != TcpControl::Fin {
        break;
    }
    // Nagle's algorithm: ...
    if len < mss && self.nagle && offset != 0 && !want_fin && !self.ack_due(clock) {
        break;
    }
    self.send_segment(clock, &mut send, &repr, control, offset, len)?;
}
```

With `offset == 0` the Nagle check never holds. None of the RFC's conditions is checked: rule (2) needs `D <= U`, rule (3) needs `min(D,U) >= Fs * Max(SND.WND)`. `remote_max_win_len` is already tracked and can stand in for `Max(SND.WND)`. There is no override timer (rule 4).

## Failure scenario

The peer's application reads 10 bytes at a time and the peer advertises a 10-byte window each time. We have 1000 bytes queued. xarxa sends one 10-byte segment per round trip instead of waiting for a useful window. Header overhead is about 80% and throughput collapses.

## RFC reference

RFC 9293 §3.8.6.2.1:

> A TCP implementation MUST include a SWS avoidance algorithm in the sender (MUST-38).

> (1) if a maximum-sized segment can be sent, i.e., if:
>
>     min(D,U) >= Eff.snd.MSS;
>
> (2) or if the data is pushed and all queued data can be sent now, i.e., if:
>
>     [SND.NXT = SND.UNA and] PUSHed and D <= U
>
> (3) or if at least a fraction Fs of the maximum window can be sent, i.e., if:
>
>     [SND.NXT = SND.UNA and] min(D,U) >= Fs * Max(SND.WND);
>
> (4) or if the override timeout occurs.

> Here Fs is a fraction whose recommended value is 1/2. The override timeout should be in the range 0.1 - 1.0 seconds. It may be convenient to combine this timer with the timer used to probe zero windows (Section 3.8.6.1).

## Reproduction

Test in `mod test` of src/tcp/mod.rs (scratch copy):

```rust
#[test]
fn zz_sender_sws() {
    let mut s = socket_established_with_buffer_sizes(1000, 64);
    s.view().send_slice(&[0x41u8; 500]).unwrap();
    send!(s, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 1,
        ..SEND_TEMPL
    });
    recv(&mut s, Instant::from_millis(0), 1, |_, r| {
        println!("ZZ sender seg len={}", r.payload.len() + r.payload2.len());
        assert_eq!(r.payload.len() + r.payload2.len(), 1);
    });
}
```

Output (500 bytes queued, window 1, max window seen 256):

```
ZZ sender seg len=1
test tcp::test::zz_sender_sws ... ok
```

## Suggested fix

Send a window-limited sub-MSS segment only if it carries all queued data or at least half of `remote_max_win_len`. Otherwise hold it and arm an override timer. The ZWP timer can serve, as the RFC suggests. The timer is required: without it, a receiver that shrank its buffer could deadlock the sender.
