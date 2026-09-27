# 284. abort()/is_open()/is_active() docs are inaccurate

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2679](../src/tcp/mod.rs#L2679), [src/tcp/mod.rs:2683](../src/tcp/mod.rs#L2683), [src/tcp/mod.rs:2703](../src/tcp/mod.rs#L2703), [src/tcp/mod.rs:2600](../src/tcp/mod.rs#L2600), [src/tcp/mod.rs:2638](../src/tcp/mod.rs#L2638) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`abort()` promises "One reset packet will be sent to the remote peer". The RST is only sent by the next dispatch. A `connect()` or `accept()` on the socket before that poll calls `reset()`, which clears the tuple, so the RST never goes out. `is_open`'s doc is wrong about TIME-WAIT and aborted sockets (see also 285). `is_active`'s doc links "abort" to `#method.close`.

## Details
src/tcp/mod.rs:2679-2681:
```rust
pub fn abort(&mut self) {
    self.inner_mut().set_state(State::Closed);
}
```
The Closed arm of dispatch sends the RST and then clears the tuple (mod.rs:1962-1969). `connect` only checks `!is_open()`, which Closed passes, then calls `s.reset(now)` (mod.rs:2600). `accept` calls `s.reset(self.tx.inner.now)` (mod.rs:2638).

`is_open` (mod.rs:2683-2691) says it is true iff the socket "will process incoming or dispatch outgoing packets". `accepts()` (mod.rs:920-923) only rejects `State::Closed`, so TIME-WAIT sockets still process segments and ACK them, and an aborted socket still dispatches its RST.

src/tcp/mod.rs:2703:
```rust
/// If a connection is established, [abort](#method.close) will send a reset to
```

## Failure scenario
The app calls `abort()` and then `connect()` on the same socket in one loop iteration. The old peer never gets the RST and keeps a half-open connection until its own timeout.

## Suggested fix
Document that the RST goes out at the next poll and is skipped if the socket is reused first, or send it before resetting in `connect`/`accept`. Fix the `is_open` wording and the `is_active` link.
