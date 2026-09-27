# 277. A single retransmitted SYN or SYN|ACK sets ssthresh to 2048 for the whole connection

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/tcp/mod.rs:1846](../src/tcp/mod.rs#L1846), [src/tcp/congestion/cubic.rs:210](../src/tcp/congestion/cubic.rs#L210), [src/tcp/congestion/reno.rs:86](../src/tcp/congestion/reno.rs#L86) |
| Features | tcp-cubic (default) or tcp-reno |
| Verification | reproduced with a test |

## Summary
The retransmit-timer path calls `on_rto(now, in_flight)` for SYN and SYN|ACK retransmissions too. With a flight of 1, ssthresh becomes `max(0.7 * 1, 2 * mss)` = 2048 (mss is still the controller's 1024 default). Nothing resets it after establishment, so the connection leaves slow start after about 2 KB. With cubic, `w_max` stays 2048 too.

## Details
src/tcp/mod.rs:1846: `self.congestion_controller.on_rto(now, in_flight);` runs for any `Timer::Retransmit`, including SYN-SENT and SYN-RECEIVED.

src/tcp/congestion/cubic.rs:210: `if !self.in_rto_recovery { self.ssthresh = ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * self.mss); ... }`. Reno is equivalent. `set_mss` at establishment does not touch ssthresh.

This is not a clear RFC violation. RFC 5681 §3.1 says ssthresh "MUST be reduced in response to congestion" and does not exempt the SYN. The only SYN-specific rule is IW = 1 segment, which cwnd = mss already gives. But a handshake timeout says little about path capacity, and Linux does not reduce ssthresh for it.

## Failure scenario
A WiFi device connects, the first SYN is lost, the retransmitted SYN succeeds. A following 1 MB upload runs in congestion avoidance from a 2 KB threshold and takes several times longer than without the SYN loss.

## Reproduction
`src/tcp/mod.rs` test module:
```rust
#[test] fn vtest_f6_syn_retransmit_ssthresh() {
    let mut s = socket_syn_sent();
    vcollect(&mut s, 0);
    vcollect(&mut s, 1000);
    println!("{:?}", s.congestion_controller);
}
```
Output:
```
t=0 [(10000, Syn, ..)] cc=Cubic { cwnd: 2048, mss: 1024, ssthresh: 18446744073709551615, in_rto_recovery: false }
t=1000 [(10000, Syn, ..)] cc=Cubic { cwnd: 1024, mss: 1024, ssthresh: 2048, cwnd_prior: 1, in_rto_recovery: true }
```

## Suggested fix
Skip `on_rto` for SYN/SYN|ACK retransmissions. When the handshake completes after one, set cwnd to 1 SMSS and leave ssthresh at its initial value.
