# 279. No way for the application to set the DSCP/Diffserv field on TCP segments (MUST-48)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1900](../src/tcp/mod.rs#L1900), [src/tcp/mod.rs:2257](../src/tcp/mod.rs#L2257), [src/stack.rs:2799](../src/stack.rs#L2799), [src/stack.rs:2831](../src/stack.rs#L2831) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`TcpSocket` has setters for timeout, ACK delay, Nagle, keep-alive and hop limit, but nothing for DSCP. Segments go through `transmit_ip(..., hop_limit)` and the IP header writers hardcode DSCP/ECN 0 and traffic class 0. RFC 9293 requires the application to be able to set it. Not listed in README "Not yet implemented".

## Details
src/tcp/mod.rs:2257: `cx.transmit_ip(&route, buf, src_addr, dst_addr, IpProtocol::Tcp, hop_limit);`

src/stack.rs:2799: `packet.set_dscp(0);` and src/stack.rs:2831: `packet.set_traffic_class(0);`

UDP and the other stack-built IP headers share the same writers and the same limitation. Raw sockets can set the field themselves.

## Failure scenario
A VoIP control application needs its TCP signalling marked CS3/EF on a managed network and cannot do it.

## RFC reference
RFC 9293 §3.9.1.9: "The application layer MUST be able to specify the Differentiated Services field for segments that are sent on a connection (MUST-48)."

## Suggested fix
Add a per-socket DSCP (and optionally ECN) setting, passed down to the IP header writer. Do the same for UDP.
