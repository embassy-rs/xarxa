# 355. Zero-window probe timer keeps firing after the tx buffer empties, suppressing keep-alive

| | |
|---|---|
| Severity | info |
| Category | other |
| Location | [src/tcp/mod.rs:1514](../src/tcp/mod.rs#L1514), [src/tcp/mod.rs:2048](../src/tcp/mod.rs#L2048) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The ZWP timer is only stopped when the peer's window becomes non-zero. If the probe byte is accepted and the tx buffer empties while the window stays 0, the timer keeps firing. Each probe is an empty ACK, backed off to 60 s, forever. Keep-alive needs `Timer::Idle`, so it never runs.

## Details
src/tcp/mod.rs:1509 starts ZWP only when `!self.tx_buffer.is_empty()`. src/tcp/mod.rs:1514 stops it only when:
```rust
if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
```
The probe at 2048-2059 takes `get_allocated(offset, 1)`, which is empty when the tx buffer is empty. In FIN-WAIT-1, CLOSING and LAST-ACK the empty probe carries FIN, since `data_control(offset, 0)` returns `Fin` when offset == tx_len. The periodic ACKs still probe liveness, so the practical effect is small.

## Reproduction
In the `tcp` module test harness:
```rust
#[test] fn vtest_f10_zwp_after_drain() {
  let mut s = socket_established();
  s.view().set_keep_alive(Some(Duration::from_secs(5)));
  send!(s, time 0, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), window_len: 0, ..SEND_TEMPL });
  s.view().send_slice(b"x").unwrap();
  vcollect(&mut s, 1000);
  let _ = send(&mut s, Instant::from_millis(1010), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 2), window_len: 0, ..SEND_TEMPL });
  for t in [1020u32, 3000, 7000, 20000, 60000, 200000, 400000] { println!("{:?} {:?}", vcollect(&mut s, t), s.timer); }
}
```
Output: probe with 1 byte at t=1000, then txlen=0 with timer ZeroWindowProbe. Empty ACKs at t=3000 ... t=200000 with `ZeroWindowProbe { delay: 60000 }`, same at 400000. No keep-alive is sent.

## Suggested fix
When the tx buffer is empty and no FIN is pending, switch the timer back to Idle instead of probing.
