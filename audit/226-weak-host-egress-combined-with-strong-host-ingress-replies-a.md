# 226. Neighbor-failure ICMP errors are dropped when the source belongs to another interface

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:2000](../src/stack.rs#L2000), [src/stack.rs:1394](../src/stack.rs#L1394), [src/stack.rs:1697](../src/stack.rs#L1697) |
| Features | default (`icmp-errors`) |
| Verification | confirmed against the code |

## Summary
UDP may send with a source address of any interface (weak host, DESIGN §6). Ingress only accepts destinations assigned to the arrival interface. `deliver_neighbor_failure_error` feeds the locally built ICMP error into `process_ipv4` on the egress interface, so an error for a packet whose source is another interface's address is dropped. The socket never gets `HostUnreachable`. The IPv6 path does the same. Dropping network replies to such sources is allowed strong-ES receive (RFC 1122 §3.3.4.2), so only the local error is a bug.

## Details
src/stack.rs:1999:
```rust
push_ipv4_header(&mut reply, reply_src, src_addr, IpProtocol::Icmp, 64, &checksum_caps);
self.process_ipv4(iface, None, reply);
```
src/stack.rs:1394:
```rust
if !iface.has_ip_addr(dst_addr.into())
```
The check is against the egress interface only. src/stack.rs:1697 is the IPv6 equivalent.

## Failure scenario
Two interfaces. A UDP socket is bound to 10.0.0.1 (iface B) and sends to 192.168.1.99, on-link on iface A and dead. ARP fails after 3 s. `take_icmp_error()` stays `None`. The same socket bound to A's address gets the error.

## Suggested fix
Skip the per-interface destination check for locally generated errors, for example by accepting any address assigned to any interface for them.
