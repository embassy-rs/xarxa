# 238. Fixed TTL 64 for stack-generated packets and the socket default is not configurable

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2079](../src/stack.rs#L2079), [src/stack.rs:2129](../src/stack.rs#L2129), [src/stack.rs:1627](../src/stack.rs#L1627), [src/stack.rs:1557](../src/stack.rs#L1557), [src/stack.rs:2643](../src/stack.rs#L2643), [src/udp.rs:839](../src/udp.rs#L839), [src/tcp/mod.rs:1900](../src/tcp/mod.rs#L1900) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
Stack-generated packets use a literal 64 for TTL/hop limit, and so does the socket default. Sockets can set their own hop limit, but the fixed value cannot be changed.

## Details
Literal `64` at:
- src/stack.rs:1557 (TCP RST and challenge ACK)
- src/stack.rs:1627 (echo reply)
- src/stack.rs:2079, 2129 (ICMPv4/ICMPv6 errors)
- neighbor-failure errors, around src/stack.rs:1999 and 2036
- src/stack.rs:2643 (DHCP)
- src/udp.rs:839 `socket.hop_limit.unwrap_or(64)`, src/tcp/mod.rs:1900 `self.hop_limit.unwrap_or(64)`

There is no stack-level setter.

## RFC reference
RFC 1122 §3.2.1.7: "The IP layer MUST provide a means for the transport layer to set the TTL field of every datagram that is sent. When a fixed TTL value is used, it MUST be configurable."

## Suggested fix
Add a stack-level default hop limit and use it at all these call sites.
