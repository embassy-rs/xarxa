# 253. CUBIC's W_est counts at most one segment per ACK, so the Reno-friendly region grows at half rate with delayed ACKs

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/congestion/cubic.rs:81](../src/tcp/congestion/cubic.rs#L81), [src/tcp/congestion/cubic.rs:145](../src/tcp/congestion/cubic.rs#L145) |
| Features | `tcp-cubic` (default) |
| Verification | reproduced with a test |

## Summary
The W_est update uses `len.min(self.mss)`, so an ACK covering 2 SMSS counts as 1. RFC 9438 counts the segments actually acked, delayed ACKs included. Against a delayed-ACK receiver, W_est grows at half the intended rate, so CUBIC in the Reno-friendly region is less aggressive than Reno.

## Details
src/tcp/congestion/cubic.rs:81:
```rust
let segment = len.min(self.mss);
```
src/tcp/congestion/cubic.rs:145:
```rust
self.w_est += alpha * self.mss as f64 * segment as f64 / self.cwnd as f64;
```
The same cap in slow start is RFC 5681 ABC with L = 1 SMSS, which is allowed. The cubic target increment is per ACK in the RFC, so it is fine too. Only the W_est update deviates.

## RFC reference
RFC 9438 §4.1.2: "segments_acked: Number of SMSS-sized segments acked when a "new ACK" is received, i.e., an ACK that cumulatively acknowledges the delivery of previously unacknowledged data."

RFC 9438 §4.3: "Also note that this equation works for connections with enabled or disabled delayed ACKs [RFC5681], as segments_acked will be different based on the segments actually acknowledged by a new ACK."

## Reproduction
Test in the `cubic.rs` test module:
```rust
#[test]
fn zz_west_delayed_ack() {
    for per_ack in [MSS, 2 * MSS] {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.set_remote_window(1 << 20);
        cubic.cwnd = 20 * MSS;
        cubic.ssthresh = cubic.cwnd;
        cubic.cwnd_prior = 100 * MSS;
        cubic.on_ack(Instant::from_millis(0), per_ack, MSS, &rtte());
        let w0 = cubic.w_est;
        for _ in 0..(20 * MSS / per_ack) {
            cubic.on_ack(Instant::from_millis(1), per_ack, MSS, &rtte());
        }
        std::println!("per_ack {}: w_est growth over 20 MSS acked = {}", per_ack, cubic.w_est - w0);
    }
}
```
Output:
```
per_ack 1024: w_est growth over 20 MSS acked = 534.79
per_ack 2048: w_est growth over 20 MSS acked = 269.12
```

## Suggested fix
Use the full `len` in the W_est update. Keep `segment` for the cubic target increment.
