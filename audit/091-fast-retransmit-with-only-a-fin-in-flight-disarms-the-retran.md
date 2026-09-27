# 091. Fast retransmit with only a FIN in flight disarms the retransmit timer, and the FIN is never retransmitted

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:2012](../src/tcp/mod.rs#L2012), [src/tcp/mod.rs:1855](../src/tcp/mod.rs#L1855), [src/tcp/mod.rs:1426](../src/tcp/mod.rs#L1426) |
| Features | default |
| Verification | reproduced with a test |

## Summary

When `Timer::FastRetransmit` fires, `dispatch` sets `pending_fast_retransmit` and puts the timer in Idle. The fast-retransmit block only runs when `tx_len != 0`. If the only thing outstanding is our FIN, nothing is sent, the timer stays Idle and the FIN is never retransmitted. The socket stays in FIN-WAIT-1 or CLOSING until the user timeout, or forever if none is set.

## Details

The dup-ACK test in `process` counts pure ACKs with `ack_number == local_rx_last_ack` and `ack_number < remote_last_seq`. A FIN in flight makes that true with an empty TX buffer.

src/tcp/mod.rs:1426:

```rust
Some(last_rx_ack)
    if repr.payload.is_empty()
        && last_rx_ack == ack_number
        && ack_number < self.remote_last_seq
        && !is_window_update =>
```

On the third one the timer is set with `set_for_fast_retransmit()`. In `dispatch`, the expired timer takes the fast-retransmit branch and then goes Idle.

src/tcp/mod.rs:1863:

```rust
    self.pending_fast_retransmit = true;
}

// The retransmission goes out below if it can, which arms the timer
// again. If it can't (like with a zero window), the timer must not
// stay expired.
self.timer.set_for_idle(now, self.keep_alive);
```

The retransmission is skipped because there is no data.

src/tcp/mod.rs:2012:

```rust
if self.pending_fast_retransmit && tx_len != 0 {
```

The data loop starts at `offset = self.flight_size()`, which is 1 (the FIN). `data_control(1, 0)` returns no FIN, `len` is 0, and the loop breaks. Nothing arms the retransmit timer again. `pending_fast_retransmit` also stays true.

LAST-ACK is not affected: a duplicate ACK there takes the challenge-ACK early return at src/tcp/mod.rs:1361-1366 before dup-ACK counting.

## Failure scenario

1. The socket calls `close()` in ESTABLISHED and sends its FIN (FIN-WAIT-1). The FIN is lost.
2. Three duplicate pure ACKs of SND.UNA arrive. Sources: network duplication, the peer's replies to our segments, or the peer's bare FIN counted as a dup ACK. In CLOSING, the peer's retransmitted FINs keep counting as dup ACKs.
3. The timer goes Idle and the next deadline is one day away.

Result: the FIN is never resent. The connection hangs in FIN-WAIT-1 or CLOSING unless a timeout or keep-alive is configured.

## Reproduction

Test in `mod test` of src/tcp/mod.rs (scratch copy). `vcollect` is a helper that dispatches at the given time and collects the emitted segments.

```rust
#[test]
fn vtest_f9_fin_only_fast_retransmit() {
    let mut s = socket_fin_wait_1();
    let p = vcollect(&mut s, 0);
    for i in 0..4 {
        let _ = send(&mut s, Instant::from_millis(10 + i * 5), &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
    }
    for t in [50u32, 2000, 10000, 100000, 1000000] {
        let p = vcollect(&mut s, t);
        println!("t={} {:?} timer={:?} deadline={:?} state={} pfr={}",
            t, p, s.timer, s.deadline, s.state, s.pending_fast_retransmit);
    }
}
```

Output:

```
t=0 [(10001, Fin, 0, ..)] timer=Retransmit { expires_at: 1000 }
after dupacks dup=3 timer=FastRetransmit
t=50 [] timer=Idle { keep_alive_at: None } deadline=86400050 state=FIN-WAIT-1 pfr=true
t=2000 [] ... t=10000 [] ... t=100000 [] ...
t=1000000 [] timer=Idle deadline=87400000 state=FIN-WAIT-1 pfr=true
```

## Suggested fix

Do not treat a fast retransmit with `tx_len == 0` as handled. Either resend the FIN from offset 0 (rewind `remote_last_seq`), or arm the Retransmit timer when nothing was sent. Alternatively, only count duplicate ACKs while data octets are outstanding, not just a FIN.
