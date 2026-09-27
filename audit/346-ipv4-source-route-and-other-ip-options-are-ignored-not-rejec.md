# 346. IPv4 source-route options are ignored: the recorded route is not passed up or reversed

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/stack.rs:1305](../src/stack.rs#L1305), [src/stack.rs:1335](../src/stack.rs#L1335), [src/stack.rs:1437](../src/stack.rs#L1437) |
| Features | `ipv4` |
| Verification | confirmed against the RFC text |

## Summary
`process_ipv4` never parses IP options. A datagram with a completed source route is accepted as the final destination, but the recorded route is not passed up and replies go by normal routing. RFC 1122 requires the route to be passed up and reversed. Most modern stacks drop or ignore source routes for security, so this is a known deviation. Options are within the validated header, so there is no memory-safety issue. Transit (incomplete) source routes are covered by rfc1122-checklist-16.

## Details
src/stack.rs:1335:
```rust
let header_len = ipv4_packet.header_len() as usize;
```
src/stack.rs:1437:
```rust
buf.pull_front(header_len);
```
Nothing in between looks at the options. Raw sockets in IP mode still see them.

## Failure scenario
A source-routed datagram reaches a local socket. The reply ignores the source route and goes out by the ordinary route.

## RFC reference
RFC 1122 §3.2.1.8(c): "A host MUST support originating a source route and MUST be able to act as the final destination of a source route. If host receives a datagram containing a completed source route ... the option as received (the recorded route) MUST be passed up to the transport layer ... This recorded route will be reversed and used to form a return source route for reply datagrams".

## Suggested fix
Drop datagrams carrying LSRR/SSRR options (common practice), or document that they are ignored.
