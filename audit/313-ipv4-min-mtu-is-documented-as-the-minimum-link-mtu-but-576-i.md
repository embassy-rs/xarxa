# 313. IPV4_MIN_MTU is documented as the minimum link MTU, but 576 is the minimum datagram every host must receive

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ipv4.rs:9](../src/wire/ipv4.rs#L9) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
The public constant `IPV4_MIN_MTU = 576` is documented as "Minimum MTU required of all links supporting IPv4". RFC 791 sets the unfragmented forwarding minimum at 68 octets. 576 is the minimum datagram every destination must accept, reassembled or not. The internal comment under the doc and the stack's own uses (DHCP buffer asserts, ICMP error quote limit) already use the 576 meaning.

## Details
src/wire/ipv4.rs:9:
```rust
/// Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1].
```
The link also points at §3.1. The quoted text is in §3.2.

## RFC reference
RFC 791 §3.2: "Every internet module must be able to forward a datagram of 68 octets without further fragmentation. This is because an internet header may be up to 60 octets, and the minimum fragment is 8 octets. Every internet destination must be able to receive a datagram of 576 octets either in one piece or in fragments to be reassembled."

Duplicate of the second bullet of x-docs-sockets-25.

## Suggested fix
Document it as the minimum datagram size every IPv4 host must be able to receive (EMTU_R), and link §3.2.
