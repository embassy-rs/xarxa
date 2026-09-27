# 354. Without a congestion-control feature, every RTO resends the whole window

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1851](../src/tcp/mod.rs#L1851), [src/tcp/congestion/no_control.rs:15](../src/tcp/congestion/no_control.rs#L15) |
| Features | neither `tcp-reno` nor `tcp-cubic` (not the default) |
| Verification | confirmed against the code |

## Summary
The default build has `tcp-cubic` (Cargo.toml:55), where `on_rto` sets cwnd to one MSS and only one segment goes out after an RTO. In a build with neither `tcp-reno` nor `tcp-cubic`, `NoControl::window()` is `usize::MAX`. After an RTO, dispatch rewinds `remote_last_seq` to SND.UNA and resends everything up to the peer's window in one go-back-N burst.

## Details
src/tcp/mod.rs:1851:
```rust
self.remote_last_seq = self.local_seq_no;
```
The data loop then sends up to min(tx_len, remote window, cwnd). Data the peer already holds is resent too, since received SACK blocks are not used. Running without congestion control is a documented option. RFC 6298 (5.4) is part of a RECOMMENDED algorithm, and the RFC 5681 MUST applies to congestion control, which this build leaves out on purpose.

Side note: DESIGN.md §7 says no congestion control is the default and that `tcp-timestamps` is off by default. Both disagree with Cargo.toml.

## RFC reference
RFC 5681 §3.1: "upon a timeout (as specified in [RFC2988]) cwnd MUST be set to no more than the loss window, LW, which equals 1 full-sized segment".
RFC 6298 §5: "(5.4) Retransmit the earliest segment that has not been acknowledged by the TCP receiver."

## Suggested fix
Limit the post-RTO burst to one segment even with `NoControl`, or document the behaviour on the feature. Fix the DESIGN.md defaults.
