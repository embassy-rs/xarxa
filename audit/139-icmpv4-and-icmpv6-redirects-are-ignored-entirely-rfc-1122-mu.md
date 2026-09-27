# 139. ICMPv4 and ICMPv6 Redirects are ignored entirely (RFC 1122 MUST, RFC 4861 SHOULD)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/icmp_error.rs:39](../src/icmp_error.rs#L39), [src/stack.rs:1636](../src/stack.rs#L1636), [src/stack.rs:1875](../src/stack.rs#L1875) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`IcmpError::from_icmpv4` returns `None` for Redirect, and nothing else processes ICMPv4 Redirect or ICMPv6 Redirect (type 137). The routing table is never updated. This is a MUST for IPv4 hosts (RFC 1122) and a SHOULD for IPv6 (RFC 4861). Neither README "Not yet implemented" nor DESIGN §10/§11 mentions it.

## Details
src/icmp_error.rs:39-41
```rust
// Redirects are routing hints, not errors. Everything else is
// informational.
_ => None,
```
`process_icmpv4` reaches Redirect only through the `msg_type.is_error()` arm (src/stack.rs:1636), which only delivers what `from_icmpv4` maps. `process_icmpv6` has no `Icmpv6Message::Redirect` arm. `Routes` has no host-route cache a redirect could fill. Many hosts disable redirects on purpose, so this may be deliberate, but it is undocumented.

## Failure scenario
A LAN with two routers. The default gateway G redirects traffic for 10.2.0.0/16 to router R. xarxa keeps sending through G. Each packet takes an extra hop and triggers another Redirect. If G only redirects and does not forward, the traffic is lost.

## RFC reference
RFC 1122 §3.2.2.2:
> A host receiving a Redirect message MUST update its routing information accordingly. Every host MUST be prepared to accept both Host and Network Redirects

RFC 4861 §8.3:
> A host receiving a valid redirect SHOULD update its Destination Cache accordingly so that subsequent traffic goes to the specified target.

## Suggested fix
Implement redirects as expiring host routes via the new gateway, validated per RFC 1122 §3.2.2.2 and RFC 4861 §8.1. Or list them as a deliberate omission in README and DESIGN.
