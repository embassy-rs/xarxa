# 256. Go-back-N after an RTO suppresses RTT samples for the whole recovery, so the backed-off RTO can ratchet up to 60 s

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/tcp/mod.rs:324](../src/tcp/mod.rs#L324) (on_send), [src/tcp/mod.rs:343](../src/tcp/mod.rs#L343) (on_rto), [src/tcp/mod.rs:363](../src/tcp/mod.rs#L363) (on_retransmit), [src/tcp/mod.rs:1851](../src/tcp/mod.rs#L1851) (rewind) |
| Features | default |
| Verification | confirmed against the code |

## Summary
After an RTO, `dispatch` rewinds `remote_last_seq` and resends everything below the old high-water mark. None of that data is timed, so no RTT sample is taken until the sender passes the old maximum. The backed-off RTO is not collapsed in the meantime. Each further loss that fast retransmit misses doubles it again, up to `RTTE_MAX_RTO` (60 s). The negotiated TCP timestamps could provide valid samples, but TSecr is ignored.

## Details
src/tcp/mod.rs:324 only starts a sample above `max_seq_sent`:
```rust
fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
    if self.max_seq_sent.map(|max_seq_sent| seq > max_seq_sent).unwrap_or(true) {
        self.max_seq_sent = Some(seq);
        if self.timestamp.is_none() {
            self.timestamp = Some((timestamp, seq));
```
src/tcp/mod.rs:347, in `on_rto`:
```rust
self.rto = (self.rto * 2).min(RTTE_MAX_RTO);
```
src/tcp/mod.rs:1851 rewinds, and every retransmission calls `self.rtte.on_retransmit()` (mod.rs:1872), which drops the pending sample:
```rust
self.remote_last_seq = self.local_seq_no;
```
`rto` is only lowered in `sample()`. Clearing the measurement after 3 RTOs does not touch `rto`.

This is Karn's algorithm and RFC 6298 allows it. Ignoring TSecr is a documented decision (DESIGN.md §7). The consequence here is not documented. Note that DESIGN.md §7 says `tcp-timestamps` is off by default, but Cargo.toml has it in the default set. One of the two is wrong. Without the feature, the TSecr fix below does not apply.

## Failure scenario
Reported from a netsim run (not reproduced by the verifier): 576-byte MTU, 55 ms delay, 9 % loss on the data direction, small writes, 1-packet device ring. The RTO got pinned at 60 s and stayed there through a later phase where ACKs advanced normally for 700 ms. A 98 kB transfer took 444 s, with 60 s silent gaps (141109, 201050, 261735, 322767, 383225 ms). Plain bulk runs at 25 ms delay and 2-8 % loss peaked at 2-3.2 s RTO. The extreme case needs repeated losses during a long go-back-N recovery.

## RFC reference
RFC 6298 §3: "RTT samples MUST NOT be made using segments that were retransmitted ... The only case when TCP can safely take RTT samples from retransmitted segments is when the TCP timestamp option [JBB92] is employed".

RFC 6298 §5 notes the RTO may "collapse" back down once a new RTT measurement is obtained after backoff.

## Suggested fix
When timestamps are negotiated, take RTT samples from TSecr on ACKs of new data (RFC 7323 RTTM), retransmitted data included. Independently, retransmitting only what was lost instead of rewinding SND.NXT would let new data be timed.
