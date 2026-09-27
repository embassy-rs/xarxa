# 261. TCP ISN has no clock component (RFC 9293 MUST-8)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:781](../src/tcp/mod.rs#L781) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`random_seq_no` is a pure PRNG draw with no monotonic clock term. ISNs of successive connections on one 4-tuple are not guaranteed to increase. With the 10 s TIME-WAIT that the same socket can skip entirely (258), an old duplicate can land in a new incarnation's window.

## Details
src/tcp/mod.rs:780:
```rust
#[cfg(not(test))]
fn random_seq_no(rand: &mut Rand) -> TcpSeqNumber {
    TcpSeqNumber(rand.rand_u32() as i32)
}
```
Used by `connect` and by listener accept. There is no PAWS (DESIGN.md §7), so timestamps do not reject old duplicates either. PRNG predictability of the ISN is a separate finding.

## Failure scenario
A no-alloc app reuses one `TcpSocket` for back-to-back connections to the same server port from the same local port. A delayed segment from the previous incarnation falls in the new window and is accepted as data. Probability is about window/2^32 per reconnect.

## RFC reference
RFC 9293 §3.4.1: "A TCP implementation MUST use the above type of \"clock\" for clock-driven selection of initial sequence numbers (MUST-8), and SHOULD generate its initial sequence numbers with the expression: ISN = M + F(localip, localport, remoteip, remoteport, secretkey)"

## Suggested fix
ISN = clock term from the poll clock + keyed hash of the 4-tuple (RFC 6528).
