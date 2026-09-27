# 343. Ephemeral ports use only 49152-65535, RFC 6056 recommends the largest possible range

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/stack.rs:492](../src/stack.rs#L492), [src/stack.rs:500](../src/stack.rs#L500) |
| Features | default (`udp` or `tcp`) |
| Verification | confirmed against the RFC text |

## Summary
`alloc_ephemeral_port` draws from the IANA dynamic range, 16384 ports. RFC 6056 says the largest possible range SHOULD be used, to make guessing harder. This is a documented decision (DESIGN.md §7) with no interop impact.

## Details
src/stack.rs:492:
```rust
pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;
```
That is 14 bits of port entropy, about 2 bits less than 1024-65535.

## RFC reference
RFC 6056 §3.2: "Ephemeral port selection algorithms SHOULD use the largest possible port range, since this reduces the chances of an off-path attacker of guessing the selected port numbers."

## Suggested fix
Optionally use 1024-65535, skipping locally bound ports. Otherwise leave as documented.
