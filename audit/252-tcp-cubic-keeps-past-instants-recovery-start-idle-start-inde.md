# 252. tcp-cubic keeps past instants (recovery_start, idle_start) indefinitely, and cwnd freezes after 24.8 days

| | |
|---|---|
| Severity | low |
| Category | timer |
| Location | [src/tcp/congestion/cubic.rs:65](../src/tcp/congestion/cubic.rs#L65), [src/tcp/congestion/cubic.rs:126](../src/tcp/congestion/cubic.rs#L126) |
| Features | `tcp-cubic` (in the Cargo default set) |
| Verification | reproduced with a test |

## Summary
`recovery_start` is kept from the start of congestion avoidance until the next loss or RTO. `idle_start` is kept while flight size is 0. Neither is a pending deadline, and neither is given up at poll time, as DESIGN.md §4 "Time" requires. After an idle period longer than 2^31 ms, every CA ACK returns early and cwnd stays frozen until the next loss.

## Details
src/tcp/congestion/cubic.rs:65:
```rust
if let (Some(idle), Some(start)) = (self.idle_start, self.recovery_start)
    && now >= idle
{
    self.recovery_start = Some(start + (now - idle));
}
self.idle_start = None;
```
After 2^31 ms, `now >= idle` is false, so `recovery_start` is not slid forward.

src/tcp/congestion/cubic.rs:126:
```rust
let Some(t) = now.checked_duration_since(recovery_start) else {
    return;
};
```
`checked_duration_since` returns `None` when the wrapping difference is negative as `i32`.

Smaller effects:
- An idle period between 12.4 and 24.8 days is only partly subtracted, because `now - idle` saturates at `Duration::MAX`. `t` jumps, but cwnd stays clamped by rwnd.
- In continuous CA with no idle, cwnd has usually reached rwnd long before 24.8 days. The freeze only matters if rwnd grows later.

## Failure scenario
A long-lived connection in CA with cwnd at 4 KB goes idle with no keep-alive for 30 days. Then the app sends a lot of data. Every ACK hits the `None` branch and cwnd stays at 4 KB until a loss.

## Reproduction
Test in the `cubic.rs` test module:
```rust
#[test]
fn zz_cubic_idle_30_days() {
    for idle_days in [1u32, 30] {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.set_remote_window(1 << 20);
        cubic.cwnd = 4 * MSS;
        cubic.ssthresh = cubic.cwnd;
        let t0 = Instant::from_millis(1000);
        cubic.on_ack(t0, MSS, MSS, &rtte()); // enter CA
        cubic.on_ack(t0, MSS, 0, &rtte());   // go idle
        let before = cubic.window();
        let nowm = 1000u32.wrapping_add(idle_days * 86_400_000);
        let now = Instant::from_millis(nowm);
        cubic.post_transmit(now, MSS);
        for i in 0..200u32 {
            cubic.on_ack(Instant::from_millis(nowm.wrapping_add(10 * i)), MSS, 3 * MSS, &rtte());
        }
        std::println!("idle {} days: cwnd before {} after {}", idle_days, before, cubic.window());
    }
}
```
Output:
```
idle 1 days: cwnd before 4592 after 21027
idle 30 days: cwnd before 4592 after 4592
```

## Suggested fix
Store state that doesn't age. For example restart the epoch (clear `recovery_start`) when an idle period starts, or give both instants up at poll time.
