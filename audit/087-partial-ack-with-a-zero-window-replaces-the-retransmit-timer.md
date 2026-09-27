# 087. Partial ACK with a zero window replaces the retransmit timer, and in-flight data is never resent after the window reopens

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1509](../src/tcp/mod.rs#L1509), [src/tcp/mod.rs:1514](../src/tcp/mod.rs#L1514), [src/tcp/mod.rs:1869](../src/tcp/mod.rs#L1869), [src/tcp/mod.rs:2022](../src/tcp/mod.rs#L2022), [src/tcp/mod.rs:2048](../src/tcp/mod.rs#L2048) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`process()` starts the zero-window-probe timer when the window is 0, the tx buffer is not empty and `ack_len > 0`. That overwrites a running Retransmit timer while data is still in flight. When the window reopens, the ZWP timer becomes Idle, and no timer covers the in-flight data. If nothing new is queued it is never resent. A related path: an RTO that fires under a zero window leaves the timer Idle with no probe. Both stall the connection forever unless a timeout or keep-alive is set. Finding 090 describes the same two paths from the timer side.

## Details

src/tcp/mod.rs:1508-1517:

```rust
// start/stop the Zero Window Probe timer.
if self.remote_win_len == 0 && !self.tx_buffer.is_empty() && (self.timer.is_idle() || ack_len > 0) {
    let delay = self.rtte.retransmission_timeout();
    trace!("starting zero-window-probe timer for t+{}", delay);
    self.timer.set_for_zero_window_probe(now, delay);
}
if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
    trace!("stopping zero-window-probe timer");
    self.timer.set_for_idle(now, self.keep_alive);
}
```

While in ZWP, the probe at src/tcp/mod.rs:2048-2059 takes `get_allocated(flight_size(), 1)`. That is past the in-flight data, so if everything queued is in flight the probe is a bare ACK at SND.NXT. After the window reopens, dispatch starts new data at `offset = self.flight_size()` (src/tcp/mod.rs:2022-2025). With `limit = tx_len` it sends nothing, and the timer stays Idle. Only `send_segment` of new data re-arms the retransmit timer.

The RTO path, src/tcp/mod.rs:1866-1869:

```rust
// The retransmission goes out below if it can, which arms the timer
// again. If it can't (like with a zero window), the timer must not
// stay expired.
self.timer.set_for_idle(now, self.keep_alive);
```

With `remote_win_len == 0` the send loop's limit is 0. No ZWP is armed, because ZWP only starts in `process()` and in `send_impl` (src/tcp/mod.rs:2807). So a zero window with data in flight is never probed again.

The RTT sample for the stranded segment also stays pending while this lasts.

## Failure scenario

1. A request/response client sends its last request as two segments.
2. The peer ACKs the first with window 0 and drops the second (it shrank its window, or rounded its scaled window down).
3. The peer reopens its window.

The second segment is never retransmitted. The request never completes. Without `set_timeout` the socket hangs forever.

RTO variant: 3 bytes in flight, the peer sends ACK=SND.UNA with window 0. At the RTO nothing goes out and the timer becomes Idle. If the peer's window update is lost, nothing ever probes.

Both need a peer that shrinks its window. Linux does not do that by default.

## RFC reference

RFC 9293 §3.8.6:

> a sending TCP peer MUST be robust against window shrinking, which may cause the "usable window" (see Section 3.8.6.2.1) to become negative (MUST-34).
>
> If this happens, the sender SHOULD NOT send new data (SHLD-15), but SHOULD retransmit normally the old unacknowledged data between SND.UNA and SND.UNA+SND.WND (SHLD-16). [...] If the window shrinks to zero, the TCP implementation MUST probe it in the standard way (described below) (MUST-35).

## Reproduction

Tests inside `mod test` in src/tcp/mod.rs of a scratch copy. `zz_collect` dispatches and returns the segments sent.

```rust
#[test]
fn zz_f3_shrink_to_zero_stall() {
    let mut s = socket_established();
    s.view().set_nagle_enabled(false);
    s.view().send_slice(b"abc").unwrap(); zz_collect(&mut s, Instant::from_millis(0));
    s.view().send_slice(b"def").unwrap(); zz_collect(&mut s, Instant::from_millis(0));
    let _ = send(&mut s, Instant::from_millis(10), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 3), window_len: 0, ..SEND_TEMPL });
    let _ = send(&mut s, Instant::from_millis(20), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 3), window_len: 256, ..SEND_TEMPL });
    let mut total = Vec::new();
    for t in [30u32, 2_000, 10_000, 100_000, 1_000_000] { total.extend(zz_collect(&mut s, Instant::from_millis(t))); }
    assert!(!total.is_empty(), "in-flight 'def' never retransmitted");
}
```

Output:

```
after shrink timer=ZeroWindowProbe { expires_at: 210, delay: 200 }
after reopen timer=Idle { keep_alive_at: None } flight=3
t=30 sent [] deadline=86400030 ... t=1000000 sent [] deadline=87400000
panicked: in-flight 'def' never retransmitted
```

RTO variant (`zz_f3b_shrink_no_ack_stall`: send 6 bytes, peer ACKs LOCAL_SEQ+1 with window 0, follow deadlines 10 times):

```
after shrink timer=Retransmit { expires_at: 1000 }
t=1000 sent [] timer=Idle deadline=86401000
... (every later daily poll sends nothing)
panicked: zero window never probed
```

## Suggested fix

- Only switch to ZWP when nothing is in flight (`flight_size() == 0`), or keep the retransmit timer while data is outstanding.
- When leaving ZWP with `flight_size() > 0`, arm the retransmit timer (or rewind `remote_last_seq` to `local_seq_no`).
- After an RTO that sent nothing because the window is zero, arm the ZWP timer instead of Idle.
