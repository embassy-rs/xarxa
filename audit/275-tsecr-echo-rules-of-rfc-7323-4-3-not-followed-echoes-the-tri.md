# 275. TSecr echo rules of RFC 7323 §4.3 not followed, and ack_reply can omit TSopt

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1486](../src/tcp/mod.rs#L1486), [src/tcp/mod.rs:872](../src/tcp/mod.rs#L872), [src/tcp/mod.rs:1937](../src/tcp/mod.rs#L1937) |
| Features | tcp-timestamps (in the default set) |
| Verification | confirmed against the RFC text |

## Summary
`last_remote_tsval` (TS.Recent) is overwritten by every accepted segment, including out-of-order ones and ones with an older TSval. Delayed ACKs echo the newest segment instead of the earliest unacknowledged one. `ack_reply` echoes the triggering segment's own TSval, and sends no TSopt at all if that segment had none. The peer underestimates RTT, and replies without TSopt break a MUST.

## Details
src/tcp/mod.rs:1484:
```rust
#[cfg(feature = "tcp-timestamps")]
if let Some(timestamp) = repr.timestamp {
    self.last_remote_tsval = timestamp.tsval;
}
```
No `SEG.TSval >= TS.Recent && SEG.SEQ <= Last.ACK.sent` check.

src/tcp/mod.rs:872:
```rust
reply_repr.timestamp = repr
    .timestamp
    .and_then(|tcp_ts| self.timestamp_repr(_now, tcp_ts.tsval));
```
src/tcp/mod.rs:1937: dispatch echoes `self.timestamp_repr(now, self.last_remote_tsval)`.

`tcp-timestamps` is in the default feature set (Cargo.toml:56). DESIGN.md §7 says it is off by default, which is also stale.

## Failure scenario
- Delayed ACK (10 ms default): segments with TSval 1 and 2 are ACKed with TSecr=2. RFC says 1.
- Loss: A (TSval=1) arrives, C (TSval=3) out of order. The dup ACK echoes 3. RFC says 1.
- A challenge ACK or keep-alive reply to a segment without TSopt goes out without TSopt.

The peer (Linux uses TSecr for RTT) measures RTT too short, which can cause spurious retransmissions. Peers enforcing §3.2 may drop the TSopt-less replies.

## RFC reference
RFC 7323 §4.3:
- "(A) ... when delayed ACKs are in use, the receiver SHOULD reply with the TSval field from the earliest unacknowledged segment."
- "(B) ... An <ACK> for an out-of-order segment SHOULD, therefore, contain the timestamp from the most recent segment that advanced RCV.NXT."
- "(2) If: SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent then SEG.TSval is copied to TS.Recent; otherwise, it is ignored."

RFC 7323 §3.2: "the TSopt MUST be sent in every non-<RST> segment for the duration of the connection".

## Suggested fix
Update `last_remote_tsval` only when SEG.TSval >= TS.Recent (wrapping compare) and SEG.SEQ <= `remote_last_ack`. In `ack_reply`, echo `last_remote_tsval` whenever timestamps are negotiated, whether or not the incoming segment carried TSopt.
