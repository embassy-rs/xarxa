# 258. TIME-WAIT is 10 s and can be cut short by connect()/accept() on the same socket

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:382](../src/tcp/mod.rs#L382), [src/tcp/mod.rs:707](../src/tcp/mod.rs#L707), [src/tcp/mod.rs:2549](../src/tcp/mod.rs#L2549), [src/tcp/mod.rs:2583](../src/tcp/mod.rs#L2583), [src/tcp/mod.rs:2634](../src/tcp/mod.rs#L2634) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
TIME-WAIT lasts 10 s, not 2*MSL. `is_open()` is false in TIME-WAIT, so `connect()` or `accept()` on that same socket resets it at once, even to the identical 4-tuple. ISNs are pure PRNG output (see 261), so RFC 9293's condition for reopening early is not met. Neither README nor DESIGN.md documents this. It is inherited from smoltcp.

## Details
src/tcp/mod.rs:382:
```rust
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);
```
src/tcp/mod.rs:707, in `is_open`:
```rust
State::TimeWait => false,
```
src/tcp/mod.rs:2549, in `connect` (same check in `accept` at 2634):
```rust
if self.is_open() {
```
src/tcp/mod.rs:2583 skips the socket's own index:
```rust
.any(|(i, s)| i != index && s.binding == binding && s.tuple == Some(Tuple { local, remote }))
```
Only the same socket can skip TIME-WAIT. Other sockets and ephemeral allocation still see the TIME-WAIT tuple as in use for the 10 s.

## Failure scenario
- Lost final ACK, the more realistic case. On a lossy link our ACK of the peer's FIN is lost repeatedly. The peer retransmits its FIN at 1, 3, 7, 15 s. At 15 s our socket has left TIME-WAIT, the FIN gets an RST, and the peer sees a reset instead of a clean close.
- Old duplicates. An app reconnects its one socket from a fixed local port to the same server right after an active close. A delayed segment from the old connection lands in the new random window and is accepted as data. Low probability.

## RFC reference
RFC 9293 §3.6: "When a connection is closed actively, it MUST linger in the TIME-WAIT state for a time 2xMSL (Maximum Segment Lifetime) (MUST-13). However, it MAY accept a new SYN from the remote TCP endpoint to reopen the connection directly from TIME-WAIT state (MAY-2), if it: (1) assigns its initial sequence number for the new connection to be larger than the largest sequence number it used on the previous connection incarnation..."

## Suggested fix
Lengthen TIME-WAIT, or refuse `connect`/`accept` of the same 4-tuple on a socket in TIME-WAIT. With a clock-driven ISN (261) the early reuse becomes defensible. At minimum, document the 10 s choice.
