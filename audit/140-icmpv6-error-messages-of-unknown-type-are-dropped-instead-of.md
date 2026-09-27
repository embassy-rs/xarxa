# 140. ICMPv6 error messages of unknown type are dropped instead of being passed to the upper layer (RFC 4443 §2.4(a))

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/icmpv6.rs:233](../src/wire/icmpv6.rs#L233), [src/icmp_error.rs:57](../src/icmp_error.rs#L57), [src/stack.rs:1814](../src/stack.rs#L1814) |
| Features | default (`icmp-errors`) |
| Verification | confirmed against the RFC text |

## Summary
An ICMPv6 error of unknown type (below 128, other than 1-4) never reaches the erring socket. There are two blockers: `Icmpv6Packet::check_len` rejects every unlisted type, and `from_icmpv6` maps only types 1-4. RFC 4443 requires delivery. The public doc of `check_len`/`new_checked` is also wrong: it says `Malformed` means the buffer is too short. Practical impact is small, since only experimental error types exist outside 1-4.

## Details
src/wire/icmpv6.rs:232-233
```rust
Message::RplControl => return Err(Malformed),
_ => return Err(Malformed),
```
src/stack.rs:1814
```rust
let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
```
So the `msg_type if msg_type.is_error()` arm at src/stack.rs:1875 is never reached. Even if it were:

src/icmp_error.rs:57
```rust
_ => None,
```
`IcmpError::Other` already exists as a catch-all. Raw sockets still get the bytes, since the raw copy happens first. Users of the public `new_checked` also get `Malformed` for valid, long-enough messages of unlisted types, such as MLDv1 (131/132) or RPL (155, which is in the enum).

## Failure scenario
A router sends an ICMPv6 error of experimental type 100 quoting a UDP datagram we sent. It is dropped. The socket never gets `IcmpError::Other`.

## RFC reference
RFC 4443 §2.4 (a):
> If an ICMPv6 error message of unknown type is received at its destination, it MUST be passed to the upper-layer process that originated the packet that caused the error, where this can be identified (see Section 2.4, (d)).

## Suggested fix
In `check_len`, accept any type with at least the 8-byte header. Map unknown error types to `Some(IcmpError::Other)` in `from_icmpv6`. Fix the `check_len` doc.
