# 282. set_nagle_enabled doc says at most one sub-MSS segment is in flight, but the ack_due exemption breaks that

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2392](../src/tcp/mod.rs#L2392), [src/tcp/mod.rs:2033](../src/tcp/mod.rs#L2033) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The public doc says Nagle "ensures at most only one segment smaller than MSS is in flight at a time". Dispatch skips the Nagle hold whenever an ACK is due. On a bidirectional flow every due ACK can carry another small segment while earlier ones are unacknowledged. The exemption is deliberate, so the doc is what is wrong. It is also a minor deviation from SHLD-7.

## Details
src/tcp/mod.rs:2030-2035:
```rust
// Nagle's algorithm: while there's data in flight, hold back a
// segment smaller than MSS, unless it's the end of the stream
// (we're closing), or it has to go out anyway to carry an ACK.
if len < mss && self.nagle && offset != 0 && !want_fin && !self.ack_due(clock) {
    break;
}
```
`test_nagle_held_data_rides_on_ack` covers this behavior. With the default 10 ms ACK delay, a peer streaming to us makes an ACK due every 10 ms or every full MSS, and each can carry a tinygram.

## Failure scenario
An interactive application writes 1 byte at a time while receiving a stream. Many 1-byte segments are in flight at once, with Nagle on and the doc promising otherwise.

## RFC reference
RFC 9293 §3.7.4: "If there is unacknowledged data (i.e., SND.NXT > SND.UNA), then the sending TCP endpoint buffers all user data (regardless of the PSH bit) until the outstanding data has been acknowledged or until the TCP endpoint can send a full-sized segment" ... "A TCP implementation SHOULD implement the Nagle algorithm to coalesce short segments (SHLD-7)."

## Suggested fix
Document the ACK piggyback exemption in `set_nagle_enabled`, or drop the exemption.
