# 083. Congestion control uses the peer's MSS option (or its own 1024 default) as SMSS, not the real segment size

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1280](../src/tcp/mod.rs#L1280), [src/tcp/listener.rs:254](../src/tcp/listener.rs#L254), [src/tcp/mod.rs:1449](../src/tcp/mod.rs#L1449), [src/tcp/mod.rs:2008](../src/tcp/mod.rs#L2008), [src/tcp/congestion/reno.rs:96](../src/tcp/congestion/reno.rs#L96), [src/tcp/congestion/cubic.rs:219](../src/tcp/congestion/cubic.rs#L219), [src/tcp/congestion/reno.rs:5](../src/tcp/congestion/reno.rs#L5), [src/tcp/congestion/cubic.rs:12](../src/tcp/congestion/cubic.rs#L12) |
| Features | default (`tcp-cubic`), also `tcp-reno` |
| Verification | reproduced with a test |

## Summary

The congestion controller's `mss` is set from the peer's MSS option. Real segments are sized by `local_mss.min(remote_mss) - options_len`. So the loss window, the ssthresh floor, fast-recovery inflation and CA growth are in units that can be much larger than a real segment. A peer advertising MSS 8960 to a 1500-MTU device makes an RTO send 6 back-to-back segments where RFC 5681 allows one.

## Details

The controller's `mss` comes from:

- src/tcp/mod.rs:1277, active open, only when the SYN|ACK carries a non-zero MSS option:
  ```rust
  if max_seg_size != 0 {
      self.remote_mss = (max_seg_size as usize).max(MIN_REMOTE_MSS);
      self.congestion_controller.set_mss(self.remote_mss);
  }
  ```
- src/tcp/listener.rs:254, passive open: `s.congestion_controller.set_mss(syn.remote_mss);`. Without an option this is the socket's 536 default (listener.rs:109-113).
- Otherwise, on an active open with no MSS option, the controller keeps its own `DEFAULT_MSS = 1024` (reno.rs:5, cubic.rs:12), while the socket's `remote_mss` is 536.

The real segment size, src/tcp/mod.rs:2008:

```rust
let mss = local_mss.min(self.remote_mss).saturating_sub(options_len);
```

`on_dup_ack` is also passed `self.remote_mss` (src/tcp/mod.rs:1449).

Effects:

- `on_rto` sets `self.cwnd = self.mss` (reno.rs:96, cubic.rs:219). With cc mss 8960 and SMSS 1460 that is 6 segments.
- The ssthresh floor `2 * mss` and fast recovery `ssthresh + 3 * mss` are inflated the same way.
- Reno CA grows by `mss * mss / cwnd` per ACK, about 37x too fast with 8960 vs 1460. CUBIC's `C * mss` and W_est increment scale the same way.
- Active open with no MSS option: cc mss 1024 vs SMSS 536, so the loss window is about 2 segments.

The peer controls the MSS option, so it can largely turn our congestion control off. `reset()` recreates the controller, so a reused socket does not inherit a previous value.

## Failure scenario

A 1500-MTU device connects to a server advertising MSS 8960 and uploads in bulk. On the first RTO it sends 6 full segments back to back instead of 1. In fast recovery and CA it probes several times faster than Reno or CUBIC should, adding loss on a congested path.

## RFC reference

RFC 5681 §2:

> SENDER MAXIMUM SEGMENT SIZE (SMSS): The SMSS is the size of the largest segment that the sender can transmit. This value can be based on the maximum transmission unit of the network, the path MTU discovery algorithm, RMSS ..., or other factors.

RFC 5681 §3.1:

> upon a timeout ... cwnd MUST be set to no more than the loss window, LW, which equals 1 full-sized segment (regardless of the value of IW).

RFC 5681 §3.2 step 4:

> For each additional duplicate ACK received (after the third), cwnd MUST be incremented by SMSS.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, scratch copy of HEAD, default features:

```rust
fn zzv_dispatch_all(s: &mut TestSocket, t: u32) -> Vec<(TcpControl, usize)> {
    s.stack.inner.now = Instant::from_millis(t as _);
    let mut out = Vec::new();
    let _: Result<(), ()> = s.sockets.get_mut(0).dispatch(&mut s.stack.tx_context(), &mut Clock::new(Instant::from_millis(t as _)),
        |_, _route, _src, _dst, _hl, r| { out.push((r.control, r.payload.len() + r.payload2.len())); Ok(()) });
    out
}
#[test]
fn zzv_cc_mss_from_option() {
    let mut s = socket_syn_sent_with_buffer_sizes(100_000, 64);
    zzv_dispatch_all(&mut s, 0);
    send(&mut s, Instant::ZERO, &TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ack_number: Some(LOCAL_SEQ + 1), max_seg_size: Some(8960), window_len: 65535, ..SEND_TEMPL });
    zzv_dispatch_all(&mut s, 0);
    let data = [0x42u8; 50_000];
    s.view().send_slice(&data).unwrap();
    println!("initial burst: {:?}", zzv_dispatch_all(&mut s, 10));
    let v = zzv_dispatch_all(&mut s, 5000);
    println!("after RTO: {:?} cwnd={}", v, s.congestion_controller.window());
    assert_eq!(v.iter().filter(|(_, l)| *l > 0).count(), 1);
}
```

`cargo test --lib zzv_ -- --nocapture`:

```
initial burst: [(None, 1460)]
after RTO: [(None, 1460), (None, 1460), (None, 1460), (None, 1460), (None, 1460), (None, 1460)] cwnd=8960
assertion `left == right` failed
  left: 6
 right: 1
```

The finder saw the same with `tcp-reno`.

## Suggested fix

Give the controller the effective SMSS, `local_mss.min(remote_mss) - options_len`. Update it when the routed MTU changes, or at least when the handshake completes. Call `set_mss` on the active open even without an MSS option (536). Pass the same value to `on_dup_ack`.

Unrelated, noticed during verification: DESIGN.md §7 says no congestion control is the default, but Cargo.toml's default set includes `tcp-cubic`.
