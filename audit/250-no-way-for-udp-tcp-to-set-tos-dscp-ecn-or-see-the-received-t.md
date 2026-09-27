# 250. No way for UDP/TCP to set DSCP/ECN or see the received value

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2799](../src/stack.rs#L2799), [src/stack.rs:2831](../src/stack.rs#L2831), [src/udp.rs:43](../src/udp.rs#L43) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`push_ipv4_header` always writes DSCP 0 and ECN 0, and `push_ipv6_header` always writes traffic class 0. UDP and TCP sockets have no setter, and `UdpMetadata` does not carry the received value. Only raw sockets can mark traffic.

## Details
src/stack.rs:2799:
```rust
packet.set_dscp(0);
packet.set_ecn(0);
```
src/stack.rs:2831:
```rust
packet.set_traffic_class(0);
```
No DSCP or TOS API exists in src/udp.rs or src/tcp/mod.rs.

## Failure scenario
A VoIP app cannot mark its UDP traffic EF, so network QoS cannot prioritize it.

## RFC reference
RFC 1122 §3.2.1.6: "The IP layer MUST provide a means for the transport layer to set the TOS field of every datagram that is sent; the default is all zero bits. The IP layer SHOULD pass received TOS values up to the transport layer."

RFC 1122 §4.1.4: "An application-layer program MUST be able to set the TTL and TOS values as well as IP options for sending a UDP datagram".

RFC 9293 §3.9.1 (MUST-48): "The application layer MUST be able to specify the Differentiated Services field for segments that are sent on a connection".

The TOS field is now the DS field (RFC 2474), but the requirement stands.

## Suggested fix
Add a per-socket DSCP/traffic class setting, like the hop limit, and pass it to the header builders. Expose the received value in `UdpMetadata`.
