# 229. Echo replies drop IP options and do not reverse a received source route

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1437](../src/stack.rs#L1437), [src/stack.rs:1576](../src/stack.rs#L1576) |
| Features | default (`icmp-ping-reply`) |
| Verification | confirmed against the RFC text |

## Summary
The echo reply reuses the request buffer after the IPv4 header, options included, is pulled. `transmit_reply` then writes a fresh 20-byte header. Record Route and Timestamp are not carried into the reply (SHOULD), and a Source Route is not reversed (MUST). Source routing is deprecated and widely filtered, so impact is small.

## Details
src/stack.rs:1437:
```rust
buf.pull_front(header_len);
```
The EchoRequest arm (src/stack.rs:1576-1628) ends in:
```rust
self.transmit_reply(&route, buf, IpAddr::V4(reply_src), IpAddr::V4(src_addr), IpProtocol::Icmp, 64);
```
A duplicate report also flagged that echoes to a broadcast address are answered from `iface.ipv4_addr()`, allowing smurf-style reflection. RFC 1122 §3.2.2.6 only says such requests MAY be silently discarded, so this is a hardening item, not a violation.

## Failure scenario
`ping -R` against xarxa shows no return path. An LSRR ping gets a reply without the reversed route.

## RFC reference
RFC 1122 §3.2.2.6: "If a Record Route and/or Time Stamp option is received in an ICMP Echo Request, this option (these options) SHOULD be updated to include the current host and included in the IP header of the Echo Reply message, without "truncation"." and "If a Source Route option is received in an ICMP Echo Request, the return route MUST be reversed and used as a Source Route option for the Echo Reply message."

## Suggested fix
Document the omission, and drop source-routed datagrams (see 225). Optionally ignore echoes to broadcast addresses.
