# 077. The CUBIC increment `(target - cwnd) * segment` overflows usize on 32-bit targets

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/tcp/congestion/cubic.rs:167](../src/tcp/congestion/cubic.rs#L167), [src/tcp/congestion/cubic.rs:81](../src/tcp/congestion/cubic.rs#L81), [src/tcp/congestion/cubic.rs:201](../src/tcp/congestion/cubic.rs#L201), [src/tcp/congestion/cubic.rs:233](../src/tcp/congestion/cubic.rs#L233), [src/tcp/mod.rs:1279](../src/tcp/mod.rs#L1279) |
| Features | `tcp-cubic`, 32-bit target, overflow checks on to panic |
| Verification | reproduced with a test (product computed on a 64-bit host) |

## Summary

In the cubic region, `on_ack` computes the increment as a plain usize multiply of up to 0.5 * cwnd by up to one MSS. The MSS is the peer's option, up to 65535, and cwnd is capped only by the largest window the peer ever advertised. On 32-bit usize (Cortex-M, RISC-V32) the product passes u32::MAX. With overflow checks (the dev profile default) the firmware panics. In release it wraps and gives a wrong, smaller increment.

## Details

src/tcp/congestion/cubic.rs:81:

```rust
let segment = len.min(self.mss);
```

src/tcp/congestion/cubic.rs:162, the target is at most 1.5 * cwnd:

```rust
raw.min(1.5 * self.cwnd as f64) // clamp to avoid increasing faster than slow-start would
```

src/tcp/congestion/cubic.rs:167:

```rust
let increment = (w_cubic_target as usize).saturating_sub(self.cwnd) * segment / self.cwnd;
self.cwnd = (self.cwnd + increment).min(self.rwnd).max(self.mss);
```

The inputs are all peer-controlled:

- `self.mss` comes from the peer's MSS option with no upper cap (src/tcp/mod.rs:1279: `self.remote_mss = (max_seg_size as usize).max(MIN_REMOTE_MSS); self.congestion_controller.set_mss(self.remote_mss);`).
- `rwnd` keeps the maximum window ever advertised (`set_remote_window`, cubic.rs:233), up to 1 GiB with scaling.
- `len` is how many bytes one ACK covers.
- cwnd grows on every ACK, even while app-limited.

With MSS 65535, the ssthresh floor at cubic.rs:201 (`.max(2 * self.mss)`) keeps cwnd at 131070 or more after any loss. So an ACK covering about 64 KB overflows almost right away. The add on line 168 cannot realistically overflow.

## Failure scenario

A device built with the dev profile (or `overflow-checks = true`) serves a large download. The client advertises MSS 65535 and a large scaled window, triggers one fast retransmit with 3 dup ACKs, then ACKs in large chunks. The first congestion-avoidance ACKs overflow the multiply and panic the firmware. With smaller (8 KB) ACKs and a 16 MiB window it still overflows once cwnd reaches about 1.3 MB.

## Reproduction

No 32-bit target build was available, so the test drives the real `Cubic` on the host and computes the same product in u128 before each `on_ack`. Added to `mod test` in src/tcp/congestion/cubic.rs, in a scratch copy:

```rust
#[test]
fn vfy_increment_product_exceeds_u32() {
    let mss = 65535usize;
    let mut cubic = Cubic::new();
    cubic.set_mss(mss);
    cubic.set_remote_window(16 << 20);
    let mut now = 0u32;
    for _ in 0..20 { cubic.on_ack(Instant::from_millis(now), 16384, 16384, &rtte()); now += 5; }
    cubic.on_loss(Instant::from_millis(now), 32768);
    now += 5;
    cubic.on_ack(Instant::from_millis(now), 16384, 16384, &rtte());
    let mut max_prod: u128 = 0;
    for _ in 0..200000 {
        now += 5;
        let len = 65535;
        let segment = len.min(cubic.mss);
        let t = now.wrapping_sub(cubic.recovery_start.unwrap().as_millis() as u32) as f64;
        let c_as_bytes = C * cubic.mss as f64;
        let srtt = rtte().smoothed_rtt().max(1);
        let raw = c_as_bytes * cube((t + srtt as f64) / 1000.0 - cubic.k) + cubic.w_max as f64;
        let target = raw.min(1.5 * cubic.cwnd as f64);
        let prod = ((target as usize).saturating_sub(cubic.cwnd) as u128) * segment as u128;
        if prod > max_prod { max_prod = prod; }
        if prod > u32::MAX as u128 { println!("product {} > u32::MAX at cwnd {} after t={}ms", prod, cubic.cwnd, t); return; }
        cubic.on_ack(Instant::from_millis(now), len, 65535, &rtte());
    }
    panic!("no overflow, max prod {} cwnd {}", max_prod, cubic.cwnd);
}
// plus a copy `_8k` with len = 8192, in_flight 8192, on_loss(8192), counting acks
```

`cargo test --lib vfy_increment -- --nocapture`:

```
product 5368496130 > u32::MAX at cwnd 163837 after t=15ms
8k: product 4296253440 > u32::MAX at cwnd 1334670 after t=5465ms, 1091 acks
```

On a 32-bit target the same usize multiply with overflow checks panics with `attempt to multiply with overflow`.

## Suggested fix

Do the multiply in u64 (or f64): `((target - cwnd) as u64 * segment as u64 / cwnd as u64) as usize`. Also consider capping cwnd at the largest usable send window, and giving the controller the real SMSS rather than the raw peer MSS.
