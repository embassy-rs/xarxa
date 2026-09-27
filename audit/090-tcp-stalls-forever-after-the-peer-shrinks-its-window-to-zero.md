# 090. TCP stalls forever after the peer shrinks its window to zero: an RTO or the end of zero-window probing leaves in-flight data with no timer

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1869](../src/tcp/mod.rs#L1869), [src/tcp/mod.rs:1509](../src/tcp/mod.rs#L1509), [src/tcp/mod.rs:1514](../src/tcp/mod.rs#L1514), [src/tcp/mod.rs:2022](../src/tcp/mod.rs#L2022), [src/tcp/mod.rs:2048](../src/tcp/mod.rs#L2048) |
| Features | default |
| Verification | reproduced with a test |

## Summary

Two paths leave unacknowledged data with no retransmit or probe timer. When the retransmit timer fires while `remote_win_len == 0`, dispatch sets the timer to Idle and nothing can be sent, and no zero-window probe is armed. When a window update stops the ZWP timer, the timer also goes Idle, even with data in flight. Without keep-alive and a timeout the connection never recovers, and `poll` only asks for the one-day idle deadline. Finding 087 covers the same mechanism, starting from the partial ACK that replaces the retransmit timer.

## Details

Path 1, RTO under a zero window. An ACK with window 0 that acks nothing has `ack_len == 0` and a non-idle timer, so the ZWP start at src/tcp/mod.rs:1509 does not fire and the Retransmit timer stays. When it fires, src/tcp/mod.rs:1851 rewinds `remote_last_seq`, then src/tcp/mod.rs:1866-1869:

```rust
// The retransmission goes out below if it can, which arms the timer
// again. If it can't (like with a zero window), the timer must not
// stay expired.
self.timer.set_for_idle(now, self.keep_alive);
```

src/tcp/mod.rs:2022-2025, the send loop is capped by the zero window:

```rust
let limit = tx_len.min(self.remote_win_len).min(self.congestion_controller.window());
loop {
    let offset = self.flight_size();
    let len = limit.saturating_sub(offset).min(mss);
```

The probe block at src/tcp/mod.rs:2048 only runs for an existing `Timer::ZeroWindowProbe`. ZWP is only started in `process()` (1509) and `send_impl` (2807), neither of which runs here.

Path 2, ZWP exit with data in flight. src/tcp/mod.rs:1509-1517:

```rust
if self.remote_win_len == 0 && !self.tx_buffer.is_empty() && (self.timer.is_idle() || ack_len > 0) {
    ...
    self.timer.set_for_zero_window_probe(now, delay);
}
if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
    trace!("stopping zero-window-probe timer");
    self.timer.set_for_idle(now, self.keep_alive);
}
```

A partial ACK with window 0 replaces Retransmit with ZWP. The window update then sets Idle while `remote_last_seq > local_seq_no`. Dispatch starts at `offset = flight_size()`, so the in-flight bytes are never resent, and nothing re-arms the retransmit timer unless new data is queued.

## Failure scenario

Path 1:

1. 3 bytes in flight.
2. The peer shrinks its window to 0 with an ACK that acknowledges nothing.
3. The RTO fires at 1 s. Nothing goes out and the timer is Idle.
4. The peer's window-open update is lost.

The data is never delivered and no probe is ever sent. If the update does arrive, dispatch resends from offset 0 and recovers. With keep-alive enabled, the keep-alive's ACK can also recover.

Path 2 stalls even without loss: a peer that discarded the bytes past its shrunken window never gets them again after it reopens.

Both need a peer that shrinks its window, or a reordered old ACK (there is no SND.WL1/WL2 check). RFC 9293 discourages shrinking (SHLD-14) and Linux does not shrink by default.

## RFC reference

RFC 9293 §3.8.6:

> a sending TCP peer MUST be robust against window shrinking, which may cause the "usable window" (see Section 3.8.6.2.1) to become negative (MUST-34).
>
> If this happens, the sender SHOULD NOT send new data (SHLD-15), but SHOULD retransmit normally the old unacknowledged data between SND.UNA and SND.UNA+SND.WND (SHLD-16). [...] If the window shrinks to zero, the TCP implementation MUST probe it in the standard way (described below) (MUST-35).

RFC 9293 §3.8.6.1:

> Probing of zero (offered) windows MUST be supported (MUST-36).

## Reproduction

Tests inside `mod test` in src/tcp/mod.rs of a scratch copy:

```rust
#[test]
fn zz_rto_zero_window_stall() {
    let mut s = socket_established();
    s.view().send_slice(b"abc").unwrap();
    recv!(s, time 0, [TcpRepr { seq_number: LOCAL_SEQ + 1, ack_number: Some(REMOTE_SEQ + 1), payload: &b"abc"[..], ..RECV_TEMPL }]);
    send!(s, time 100, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), window_len: 0, ..SEND_TEMPL });
    println!("ZZ timer after zero-win ack: {:?}", s.timer);
    for t in [1000u32, 5000, 10_000, 60_000, 600_000, 3_600_000] {
        recv_nothing(&mut s, Instant::from_millis(t));
        println!("ZZ t={} timer={:?} deadline={:?}", t, s.timer, s.deadline);
    }
    assert!(matches!(s.timer, Timer::Idle { keep_alive_at: None }));
    assert_eq!(s.deadline, idle_deadline(Instant::from_millis(3_600_000)));
    assert_eq!(s.tx_buffer.len(), 3);
}

#[test]
fn zz_zwp_exit_leaves_inflight_unprotected() {
    let mut s = socket_established();
    s.nagle = false;
    s.view().send_slice(b"abc").unwrap();
    recv!(s, time 0, [TcpRepr { seq_number: LOCAL_SEQ + 1, ack_number: Some(REMOTE_SEQ + 1), payload: &b"abc"[..], ..RECV_TEMPL }]);
    s.view().send_slice(b"def").unwrap();
    recv!(s, time 0, [TcpRepr { seq_number: LOCAL_SEQ + 1 + 3, ack_number: Some(REMOTE_SEQ + 1), payload: &b"def"[..], ..RECV_TEMPL }]);
    send!(s, time 100, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 3), window_len: 0, ..SEND_TEMPL });
    send!(s, time 200, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 3), window_len: 256, ..SEND_TEMPL });
    for t in [1000u32, 5000, 60_000, 3_600_000] {
        recv_nothing(&mut s, Instant::from_millis(t));
        println!("ZZ t={} timer={:?} deadline={:?}", t, s.timer, s.deadline);
    }
    assert_eq!(s.tx_buffer.len(), 3);
}
```

Output (the tests assert the stall, so passing means the bug is present):

```
ZZ timer after zero-win ack: Retransmit { expires_at: Instant { millis: 1000 } }
ZZ t=1000 timer=Idle { keep_alive_at: None } deadline=Instant { millis: 86401000 }
...
ZZ t=3600000 timer=Idle { keep_alive_at: None } deadline=Instant { millis: 90000000 }
test tcp::test::zz_rto_zero_window_stall ... ok
ZZ timer after partial ack win0: ZeroWindowProbe { expires_at: Instant { millis: 400 }, delay: Duration { millis: 300 } }
ZZ timer after window open: Idle { keep_alive_at: None }
ZZ t=1000 timer=Idle { keep_alive_at: None } deadline=Instant { millis: 86401000 }
ZZ t=3600000 timer=Idle { keep_alive_at: None } deadline=Instant { millis: 90000000 }
test tcp::test::zz_zwp_exit_leaves_inflight_unprotected ... ok
```

## Suggested fix

- After the RTO branch, if nothing was sent and the window is zero with data queued, arm `set_for_zero_window_probe(now, rto)`.
- When stopping the ZWP timer because the window opened, arm the retransmit timer if `remote_last_seq > local_seq_no`, instead of going Idle.
