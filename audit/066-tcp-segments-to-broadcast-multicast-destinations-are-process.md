# 066. TCP segments to broadcast/multicast destinations are processed and answered with an RST sourced from that address

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:1538](../src/stack.rs#L1538), [src/stack.rs:1394](../src/stack.rs#L1394), [src/stack.rs:1483](../src/stack.rs#L1483), [src/stack.rs:1779](../src/stack.rs#L1779), [src/tcp/listener.rs:185](../src/tcp/listener.rs#L185), [src/stack.rs:481](../src/stack.rs#L481) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`process_ipv4` admits broadcast and joined multicast destinations, and `process_ipv6` admits joined multicast groups (ff02::1 included). Both pass TCP straight to `process_tcp`, which never looks at the destination. With no matching socket, the RST fallback uses the broadcast/multicast destination as the reply's IP source. A wildcard listener also records SYNs sent to such addresses, so `accept()` yields a connection whose local address is broadcast or multicast.

## Details

src/stack.rs:1394:
```rust
if !iface.has_ip_addr(dst_addr.into())
    && !iface.has_multicast_group(dst_addr.into())
    && !iface.is_broadcast_v4(dst_addr)
```

src/stack.rs:1456 (and 1779 for IPv6) dispatches `IpProtocol::Tcp` to `process_tcp` with `dst_addr` unchanged.

src/stack.rs:1486-1491. The only address check, with a comment that misses broadcast and multicast:
```rust
// The destination was already checked to be one of ours. The IPv4 layer lets
// an unspecified source through, for DHCP.
if src_addr.is_unspecified() {
    return;
}
```

src/stack.rs:1536-1540. The RST fallback:
```rust
if tcp_repr.control != TcpControl::Rst {
    let reply = TcpSocketState::rst_reply(&tcp_repr);
    self.transmit_tcp_reply(iface, &reply, dst_addr, src_addr);
}
```

Nothing below validates the source, so the RST goes out with source 192.168.1.255, 255.255.255.255, 224.0.0.1 or ff02::1.

Listeners: `process_listeners` (src/tcp/listener.rs:185) calls `match_score`, which uses `addr_score` (src/stack.rs:481). For a listener with no address, `addr_score` returns `Some(0)` for any destination. `record_syn` then stores `local: SocketAddr::new(*dst_addr, repr.dst_port)` (src/tcp/listener.rs:98).

A socket accepted from such a token has a local address that `has_ip_addr` rejects (src/tcp/mod.rs:1887), so every SYN|ACK is dropped at emit. Other reports say it then stays in SYN-RECEIVED until a timeout, forever with the default of no timeout. The verifier did not test this part.

## Failure scenario

- An on-link host sends one SYN (or any non-RST segment) to 192.168.1.255, port with no listener, possibly with a spoofed source. Every xarxa host on the link answers with an RST whose IP source is 192.168.1.255. One RST per host, sent to the spoofed victim.
- The same SYN to a port with a wildcard listener takes a backlog slot. Accepting it gives a socket that can never complete the handshake.
- Same on IPv6 with ff02::1.

## RFC reference

RFC 9293 §3.9.2.3:
> A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address [(MUST-57)]. This prevents connection state and replies from being erroneously generated, and implementers should note that this guidance is applicable to all incoming segments, not just SYNs, as specifically indicated in RFC 1122.

RFC 1122 §3.2.1.3:
> When a host sends any datagram, the IP source address MUST be one of its own IP addresses (but not a broadcast or multicast address).

## Reproduction

Scratch test in the `src/stack.rs` test module, default features, `cargo test --lib zz_tcp_bcast -- --nocapture`:

```rust
let (mut stack, rx, tx) = test_stack(Medium::Ip);
let listener = stack.add_tcp_listener().unwrap();
stack.tcp_listener(listener).listen(1234).unwrap();
for dst in [Ipv4Addr::new(192,168,1,255), Ipv4Addr::BROADCAST] {
    // SYN to closed port 80 -> print what is sent
    // SYN to 1234 -> print accept() token local addr
}
// SYN to [ff02::1]:80
```

Output:
```
to 192.168.1.255: sent 192.168.1.255 -> 192.168.1.2 proto Tcp
token local SocketAddr { addr: V4(192.168.1.255), port: 1234 }
to 255.255.255.255: sent 255.255.255.255 -> 192.168.1.2 proto Tcp
token local SocketAddr { addr: V4(255.255.255.255), port: 1234 }
to ff02::1: sent ff02::1 -> fdaa::2 proto Tcp
```

## Suggested fix

At the top of `process_tcp`, drop the segment unless `dst_addr` is a unicast address assigned to the arrival interface. That covers IPv4 broadcast (limited and directed) and multicast for both versions, before the socket demux, the listeners and the RST fallback. Fix the comment too.
