# 272. Missing SND.WL1/SND.WL2 check: reordered older data segments overwrite the send window

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1385](../src/tcp/mod.rs#L1385) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`process()` sets `remote_win_len` from every ACK that is not old. The socket keeps no SND.WL1/SND.WL2 state. An older segment with a lower SEG.SEQ (one that carried data, SYN or FIN) that arrives after a newer one can restore a stale window. We then wait for a zero-window probe, or send past the peer's current right edge.

## Details
src/tcp/mod.rs:1385:
```rust
if !old_ack {
    ...
    let new_remote_win_len = (repr.window_len as usize) << (scale as usize);
    is_window_update = new_remote_win_len != self.remote_win_len;
    self.remote_win_len = new_remote_win_len;
    ...
}
```
Segments with an older SEG.ACK are already ignored as `old_ack`. Two pure ACKs with the same SEG.SEQ and SEG.ACK are indistinguishable to the RFC rule too, so reordering them is not covered by this finding. The gap is only for an older segment with a lower SEG.SEQ.

## Failure scenario
1. The peer sends data D1 (seq=100, len=100, win=0), then window update U (seq=200, win=8192).
2. The network reorders them. U arrives first, then D1.
3. We end at win=0 and wait one ZWP interval (about one RTO). The opposite ordering of windows makes us send beyond a closed window, and the peer drops it.

Impact is bounded by the probe and retransmit timers.

## RFC reference
RFC 9293 §3.10.7.4: "If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK. ... The check here prevents using old segments to update the window."

## Suggested fix
Track SND.WL1/SND.WL2. Update the window only when WL1 < SEG.SEQ, or WL1 == SEG.SEQ and WL2 <= SEG.ACK.
