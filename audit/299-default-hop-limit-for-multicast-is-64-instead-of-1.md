# 299. Default hop limit for multicast UDP is 64 instead of 1

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/udp.rs:839](../src/udp.rs#L839), [src/udp.rs:413](../src/udp.rs#L413) |
| Features | default |
| Verification | plausible, not demonstrated |

## Summary
UDP uses `hop_limit.unwrap_or(64)` for every destination, multicast included. Linux and lwIP default multicast TTL to 1 (`IP_MULTICAST_TTL`, `IPV6_MULTICAST_HOPS`), after RFC 1112. The behavior matches the public `set_hop_limit` doc. The behavior was reproduced. The RFC violation is not demonstrated, since RFC 1112 is not in `rfcs/`.

## Details
src/udp.rs:839:
```rust
socket.hop_limit.unwrap_or(64),
```
This goes unchanged to `TxContext::transmit_ip` for multicast destinations. The doc at src/udp.rs:413-414 says: "A socket without an explicitly set hop limit value uses the default [IANA recommended] value (64)." TCP cannot send to multicast. Raw sockets write their own TTL.

## Failure scenario
An app sends discovery datagrams to 239.255.255.250 without setting a hop limit. They leave with TTL 64 and multicast routers forward them site-wide.

## RFC reference
RFC 1122 §3.3.7: "A host SHOULD support local IP multicasting ... This implies support for all of [IP:4] except the IGMP protocol itself". [IP:4] is RFC 1112, not in `rfcs/`, so its default-TTL text could not be quoted.

## Reproduction
`udp.rs` test harness, scratch copy:
```rust
#[test] fn vfy_udp14_mcast_ttl() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(1000, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(h).send_slice(b"hi", SocketAddr::new(Ipv4Addr::new(239,255,255,250).into(), 1900)).unwrap();
    let mut f = tx.borrow()[0].clone();
    let ip = Ipv4Packet::new_checked(&mut f[..]).unwrap();
    println!("mcast ttl {}", ip.hop_limit());
}
```
Output: `mcast ttl 64`

## Suggested fix
Default to 1 for multicast destinations when the hop limit is unset (or add a separate multicast hop limit), and document it.
