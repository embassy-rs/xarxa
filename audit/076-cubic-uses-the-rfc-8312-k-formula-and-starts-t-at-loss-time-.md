# 076. CUBIC computes K with the RFC 8312 formula and starts t at the loss, so app-limited flows regrow at 0.5 SMSS per ACK after a loss

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/congestion/cubic.rs:57](../src/tcp/congestion/cubic.rs#L57), [src/tcp/congestion/cubic.rs:195](../src/tcp/congestion/cubic.rs#L195), [src/tcp/congestion/cubic.rs:103](../src/tcp/congestion/cubic.rs#L103), [src/tcp/congestion/cubic.rs:162](../src/tcp/congestion/cubic.rs#L162), [src/tcp/congestion/cubic.rs:220](../src/tcp/congestion/cubic.rs#L220) |
| Features | `tcp-cubic` |
| Verification | reproduced with a test |

## Summary

`recompute_k` computes K = cbrt(W_max * (1 - β) / C). That assumes cwnd_epoch = β * W_max. RFC 9438 defines K = cbrt((W_max - cwnd_epoch) / C), with t counted from the start of congestion avoidance. The code's real cwnd_epoch is `ssthresh = β * flight_size`, and t is counted from the loss. When flight_size was much smaller than cwnd, W_cubic(0) sits far above cwnd, the target is clamped to 1.5 * cwnd, and cwnd grows by 0.5 SMSS per ACK right after the loss. Most of the multiplicative decrease is undone within a few RTTs.

## Details

src/tcp/congestion/cubic.rs:57:

```rust
fn recompute_k(&mut self) {
    let c_as_bytes = C * self.mss as f64;
    let k3 = (self.w_max as f64) * (1.0 - BETA_CUBIC) / c_as_bytes;
    self.k = cube_root(k3);
}
```

`on_loss` sets W_max from cwnd, ssthresh from the flight size, and starts the CUBIC clock at the loss. src/tcp/congestion/cubic.rs:195:

```rust
self.w_max = if self.cwnd < self.w_max {
    ((self.cwnd as f64) * (1.0 + BETA_CUBIC) / 2.0) as usize
} else {
    self.cwnd
};

self.ssthresh = ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * self.mss);
self.cwnd = self.ssthresh.min(self.rwnd).saturating_add(3 * self.mss);

self.recovery_start = Some(now);
self.in_fast_recovery = true;
self.recompute_k();
```

The first new ACK exits fast recovery with `self.cwnd = self.ssthresh` (cubic.rs:103). That is the real cwnd_epoch. But W_cubic(0) = W_max - C * K^3 = β * W_max, not β * flight_size.

The target is then clamped, src/tcp/congestion/cubic.rs:162:

```rust
raw.min(1.5 * self.cwnd as f64) // clamp to avoid increasing faster than slow-start would
```

and the increment at cubic.rs:167 becomes `(0.5 * cwnd) * segment / cwnd`, i.e. half a segment per ACK.

Example: cwnd grows to about 60 KB while app-limited (cwnd grows on every ACK, no RFC 7661 validation, reported separately). A loss hits with 10 KB in flight. ssthresh = 7000. The code's curve starts at about 42 KB, RFC 9438's at 7000. cwnd grows about x1.5 per RTT back toward 42 KB.

With fast convergence the error goes the other way: W_max is lowered, the curve starts below cwnd_epoch, and CUBIC stays in the Reno-friendly region longer.

Separately, `on_rto` sets `self.cwnd_prior = in_flight` (cubic.rs:220). RFC 9438 defines cwnd_prior as cwnd just before the reduction.

## Failure scenario

An app-limited flow sends small periodic messages, then a burst, and takes one loss. After fast recovery cwnd = 0.7 * flight. It then climbs to about 0.7 * old cwnd within a few RTTs at a slow-start-like rate, instead of following the concave curve from cwnd_epoch. On a shared bottleneck this causes repeated losses.

## RFC reference

RFC 9438 §4.2:

> where _t_ is the elapsed time in seconds from the beginning of the current congestion avoidance stage

> K = cubic_root((W_max - cwnd_epoch)/C) ... where _cwnd_epoch_ is the congestion window at the beginning of the current congestion avoidance stage.

RFC 9438 §4.4 (and the same in §4.5):

> In this region, _cwnd_ MUST be incremented by (target - cwnd)/cwnd for each received new ACK, where _target_ is calculated as described in Section 4.2.

RFC 9438 §4.1.2:

> _cwnd_prior_: Size of _cwnd_ in segments at the time of setting _ssthresh_ most recently, either upon exiting the first slow start or just before _cwnd_ was reduced in the last congestion event.

The §4.4/§4.5 MUST is followed, but with a target computed from the wrong K and t.

## Reproduction

Added to `mod test` in src/tcp/congestion/cubic.rs, in a scratch copy:

```rust
#[test]
fn vfy_app_limited_regrowth_after_loss() {
    let mss = 1460;
    let mut cubic = Cubic::new();
    cubic.set_mss(mss);
    let mut now = 0u32;
    while cubic.window() < 60_000 { cubic.on_ack(Instant::from_millis(now), mss, 0, &rtte()); now += 10; }
    let big = cubic.window();
    cubic.on_loss(Instant::from_millis(now), 10_000);
    let ssthresh = cubic.ssthresh;
    now += 50;
    cubic.on_ack(Instant::from_millis(now), mss, 5000, &rtte());
    assert_eq!(cubic.window(), ssthresh);
    let start = cubic.window();
    let w0 = C * mss as f64 * cube(0.0 - cubic.k) + cubic.w_max as f64;
    println!("big={} ssthresh={} w_max={} K={} W_cubic(0)={} ", big, ssthresh, cubic.w_max, cubic.k, w0);
    for i in 0..20 {
        let before = cubic.window();
        now += 5;
        cubic.on_ack(Instant::from_millis(now), mss, 5000, &rtte());
        if i < 3 { println!("ack {}: cwnd {} -> {} (+{})", i, before, cubic.window(), cubic.window() - before); }
    }
    println!("after 20 acks: {} (start {})", cubic.window(), start);
    assert!(cubic.window() < start + 3 * mss, "cwnd grew from {} to {}", start, cubic.window());
}
```

`cargo test --lib vfy_ -- --nocapture` (default features):

```
big=60448 ssthresh=7000 w_max=60448 K=3.1431544881409894 W_cubic(0)=42313.31445484292
ack 0: cwnd 7000 -> 7730 (+730)
ack 1: cwnd 7730 -> 8460 (+730)
ack 2: cwnd 8460 -> 9190 (+730)
after 20 acks: 21600 (start 7000)
panicked at src/tcp/congestion/cubic.rs:354:9: cwnd grew from 7000 to 21600
```

The size of the gap depends on cwnd having grown well past the flight size. The growth rate is exactly 0.5 SMSS per ACK.

## Suggested fix

Start the epoch when congestion avoidance starts (the first new ACK after fast recovery exits). Set `recovery_start` then, and compute K = cbrt(max(W_max - cwnd, 0) / (C * mss)). In `on_rto`, set `cwnd_prior = cwnd` before the reduction.
