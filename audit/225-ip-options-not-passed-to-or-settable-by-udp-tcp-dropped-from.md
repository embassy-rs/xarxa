# 225. IPv4 options are invisible to UDP/TCP, and incomplete source routes are delivered locally

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1437](../src/stack.rs#L1437), [src/stack.rs:1305](../src/stack.rs#L1305), [src/udp.rs:323](../src/udp.rs#L323) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
xarxa ignores IPv4 options on every path. UDP and TCP cannot send options or read received ones. A datagram whose LSRR/SSRR has not reached its last hop is treated as addressed to us, and no Destination Unreachable code 5 is sent. Only raw IP-mode sockets see options, since they get the bytes verbatim. The echo-reply part is covered by finding 229.

## Details
`process_ipv4` checks only the header's dst, then strips the header without parsing options.

src/stack.rs:1437:
```rust
buf.pull_front(header_len);
```
`parse_datagram` (src/udp.rs:323) skips `header_len` without exposing the options, and the UDP send path has no options input. README does not list this as not implemented.

## Failure scenario
A packet with an LSRR whose pointer still names a next hop X, and whose current dst is xarxa, is delivered to a local UDP socket. No ICMP code 5 is returned.

## RFC reference
RFC 1122 §3.2.1.8: "There MUST be a means for the transport layer to specify IP options to be included in transmitted IP datagrams" and "All IP options (except NOP or END-OF-LIST) received in datagrams MUST be passed to the transport layer".

RFC 1122 §3.3.5: "If a host receives a datagram with an incomplete source route but does not forward it for some reason, the host SHOULD return an ICMP Destination Unreachable (code 5, Source Route Failed) message".

RFC 1122 §4.1.3.2: "UDP MUST pass any IP option that it receives from the IP layer transparently to the application layer. An application MUST be able to specify IP options to be sent in its UDP datagrams".

## Suggested fix
Drop, or answer with code 5, packets with an incomplete LSRR/SSRR. Expose the raw option bytes of received UDP datagrams, which are still in the buffer. List the rest under "Not yet implemented".
