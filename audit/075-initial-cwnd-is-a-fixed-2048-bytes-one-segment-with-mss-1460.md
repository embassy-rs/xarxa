# 075. Initial cwnd is a fixed 2048 bytes: one segment with MSS 1460, and more than 4 segments with MSS below 512

| | |
|---|---|
| Severity | medium |
| Category | performance |
| Location | [src/tcp/congestion/cubic.rs:39](../src/tcp/congestion/cubic.rs#L39), [src/tcp/congestion/reno.rs:25](../src/tcp/congestion/reno.rs#L25), [src/tcp/congestion/cubic.rs:228](../src/tcp/congestion/cubic.rs#L228), [src/tcp/congestion/reno.rs:102](../src/tcp/congestion/reno.rs#L102), [src/tcp/mod.rs:2022](../src/tcp/mod.rs#L2022) |
| Features | default (`tcp-cubic`), also `tcp-reno` |
| Verification | reproduced with a test |

## Summary

Reno and CUBIC both start with `cwnd = DEFAULT_MSS * 2 = 2048` bytes, and `set_mss` never changes it. With an MSS of 1460 the first flight is one full segment. The 588-byte remainder is held by Nagle, so a receiver that delays the ACK of a lone segment stalls every connection start. With a peer MSS below 512 the initial window is more than 4 segments, which RFC 5681 forbids.

## Details

src/tcp/congestion/cubic.rs:38 (DEFAULT_MSS is 1024, at line 12):

```rust
w_max: DEFAULT_MSS * 2,
cwnd: DEFAULT_MSS * 2,
```

src/tcp/congestion/reno.rs:25 sets `cwnd: DEFAULT_MSS * 2` too.

src/tcp/congestion/cubic.rs:228. Reno's (reno.rs:102) only sets `mss`:

```rust
fn set_mss(&mut self, mss: usize) {
    self.mss = mss;
    self.recompute_k();
}
```

src/tcp/mod.rs:2022, in `dispatch`:

```rust
let limit = tx_len.min(self.remote_win_len).min(self.congestion_controller.window());
loop {
    let offset = self.flight_size();
    let len = limit.saturating_sub(offset).min(mss);
    ...
    if len < mss && self.nagle && offset != 0 && !want_fin && !self.ack_due(clock) {
        break;
    }
```

With MSS 1460 the first segment is 1460 bytes. The second would be 588 bytes with data in flight, so Nagle stops the loop. In later rounds cwnd is 2048 + k*SMSS, so each flight keeps a sub-MSS remainder.

The peer MSS can be as low as `MIN_REMOTE_MSS = 48` (src/tcp/mod.rs:602). With MSS 100 the 2048-byte window is 20 segments back to back.

Two more details:
- `set_mss` is called with the peer's MSS option (`remote_mss`, src/tcp/mod.rs:1280), not the effective segment size. So the controller's `mss` can differ from the size of the segments sent.
- With no MSS option, `set_mss` is never called. The controller keeps mss 1024 while segments are 536 bytes. That gives 3.8 segments, within the limit. The over-limit case needs a peer MSS below 512.

## Failure scenario

- An HTTP server on the device replies with 4 KB to a client that delays ACKs (Windows, about 200 ms). It sends one 1460-byte segment, waits for the delayed ACK, then continues. This adds the delayed-ACK time to every response.
- A constrained peer advertises MSS 100. The first flight is 20 segments. RFC 5681 allows 4.

## RFC reference

RFC 5681 §3.1:

> IW, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.
>
> If SMSS > 2190 bytes:
>     IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
> If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes):
>     IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
> if SMSS <= 1095 bytes:
>     IW = 4 * SMSS bytes and MUST NOT be more than 4 segments

## Reproduction

Added to `mod test` in src/tcp/mod.rs, in a scratch copy of HEAD, default features (`tcp-cubic`):

```rust
fn vfy_first_flight(mss: usize) -> Vec<usize> {
    let mut s = socket_established_with_buffer_sizes(8192, 64);
    s.remote_win_len = 65535;
    s.remote_mss = mss;
    s.congestion_controller.set_mss(mss);
    let data = [b'x'; 6000];
    s.view().send_slice(&data[..]).unwrap();
    let mut lens = Vec::new();
    s.stack.inner.now = Instant::ZERO;
    let r: Result<(), ()> = s.sockets.get_mut(0).dispatch(
        &mut s.stack.tx_context(), &mut Clock::new(Instant::ZERO),
        |_, _route, _src, _dst, _hl, repr| { lens.push(repr.payload.len() + repr.payload2.len()); Ok(()) });
    assert_eq!(r, Ok(()));
    lens
}
#[test] fn vfy_iw_mss_1460() { let lens = vfy_first_flight(1460); println!("mss 1460 first flight: {:?}", lens); assert!(lens.len() >= 2, "only {:?}", lens); }
#[test] fn vfy_iw_mss_100() { let lens = vfy_first_flight(100); println!("mss 100 first flight: {} segments", lens.len()); assert!(lens.len() <= 4, "{} segments", lens.len()); }
```

Command: `cargo test --lib vfy_ -- --nocapture --test-threads=1`

Output:

```
test tcp::test::vfy_iw_mss_100 ... mss 100 first flight: 20 segments
panicked at src/tcp/mod.rs:7313:9: 20 segments
test tcp::test::vfy_iw_mss_1460 ... mss 1460 first flight: [1460]
panicked at src/tcp/mod.rs:7306:9: only [1460]
```

The same first flight was seen with `tcp-reno`.

## Suggested fix

Derive the initial window from SMSS when `set_mss` is called before anything has been sent: `cwnd = min(4 * SMSS, max(2 * SMSS, 4380))` (RFC 3390). Pass the effective segment size rather than the raw peer MSS. In CUBIC, keep `w_max` consistent with it.
