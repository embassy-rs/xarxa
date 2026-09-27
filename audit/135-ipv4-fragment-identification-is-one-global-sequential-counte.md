# 135. IPv4 fragment identification is one global sequential counter: predictable and not rate-limited

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/fragmentation.rs:169](../src/fragmentation.rs#L169), [src/fragmentation.rs:157](../src/fragmentation.rs#L157) |
| Features | ipv4-fragmentation (default) |
| Verification | confirmed against the RFC text |

## Summary
`next_ipv4_frag_ident` increments one stack-wide `u16`, seeded once from the PRNG. A peer that sees one fragmented datagram from the host knows the next ident to every other destination, which enables off-path fragment injection at that destination. Non-atomic datagrams are not rate-limited, which RFC 6864 §5.2 requires.

## Details
src/fragmentation.rs:169:
```rust
pub(crate) fn next_ipv4_frag_ident(&mut self) -> u16 {
    let ipv4_id = self.ipv4_id;
    self.ipv4_id = self.ipv4_id.wrapping_add(1);
    ipv4_id
}
```
Seeded once in `initial_ipv4_id` (fragmentation.rs:157-164). Atomic datagrams use ID 0, which RFC 6864 §4.1 allows.

A global counter does not repeat an ID within one tuple sooner than a per-tuple counter would. Both need 65536 non-atomic datagrams to wrap. The issues are predictability across destinations and the missing rate limit. Impact is small: fragmentation is a fallback path, and only one packet per interface can be in the fragmenter at a time. A separately reported PRNG-state recovery issue would make even the seed predictable.

## Failure scenario
An attacker learns the current ident from a fragmented reply, e.g. a fragmented echo reply on a small-MTU interface. It then sends spoofed non-first fragments with ident+1..+k to a third party the device sends fragmented UDP to. The victim reassembles the attacker's bytes into the device's datagram. Only the UDP checksum protects it.

## RFC reference
RFC 6864 §4.3:
> Sources emitting non-atomic datagrams MUST NOT repeat IPv4 ID values within one MDL for a given source address/destination address/protocol tuple.

RFC 6864 §5.2:
> Sources of non-atomic IPv4 datagrams MUST rate-limit their output to comply with the ID uniqueness requirements.

## Suggested fix
Draw a random ident per non-atomic datagram from the PRNG, or use a keyed hash of (src, dst, proto) plus a per-bucket counter. Add a rate limit on fragmented datagrams if strict §5.2 compliance is wanted.
