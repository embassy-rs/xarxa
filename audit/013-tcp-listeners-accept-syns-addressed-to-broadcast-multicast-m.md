# 013. TCP accepts segments addressed to broadcast/multicast: listeners record them, accepted sockets hang in SYN-RECEIVED, and RSTs go out with a broadcast source

| | |
|---|---|
| Severity | high |
| Category | rfc-compliance |
| Location | [src/stack.rs:1483](../src/stack.rs#L1483), [src/tcp/listener.rs:175](../src/tcp/listener.rs#L175), [src/stack.rs:1536](../src/stack.rs#L1536), [src/stack.rs:1394](../src/stack.rs#L1394), [src/tcp/mod.rs:1887](../src/tcp/mod.rs#L1887) |
| Features | default (`tcp-listener` for the listener part) |
| Verification | reproduced with a test |

## Summary

`process_tcp` never checks that the destination is unicast. The IPv4 layer lets broadcast and joined multicast destinations through. A wildcard listener records a SYN sent to 192.168.1.255 or 255.255.255.255 and hands out an `AcceptToken` whose local address is the broadcast address. The accepted socket can never send (its source is not one of our addresses), so it stays in SYN-RECEIVED forever. Unmatched segments to a broadcast address get an RST whose IP source is that broadcast address.

## Details

The IPv4 ingress check admits broadcast and multicast:

src/stack.rs:1394
```rust
if !iface.has_ip_addr(dst_addr.into())
    && !iface.has_multicast_group(dst_addr.into())
    && !iface.is_broadcast_v4(dst_addr)
{
```

`process_tcp` only rejects an unspecified source. Its comment is wrong about the destination:

src/stack.rs:1487
```rust
// The destination was already checked to be one of ours. The IPv4 layer lets
// an unspecified source through, for DHCP.
if src_addr.is_unspecified() {
    return;
}
```

A wildcard listener's `match_score` matches any destination, so the SYN is recorded with `tuple.local = dst_addr`:

src/tcp/listener.rs:175
```rust
TcpControl::Syn if repr.ack_number.is_none() => {
    ...
    listeners.get_mut(index).record_syn(src_addr, dst_addr, repr);
```

After `TcpSocket::accept`, dispatch checks `cx.has_ip_addr(tuple.local.addr)` (src/tcp/mod.rs:1887). That is false for a broadcast or multicast address, so `route` is `None` and every segment is dropped at emit. The default timeout is `None`, so the socket never leaves SYN-RECEIVED.

The RST fallback uses the destination as the reply source:

src/stack.rs:1537
```rust
let reply = TcpSocketState::rst_reply(&tcp_repr);
self.transmit_tcp_reply(iface, &reply, dst_addr, src_addr);
```

Related: `TcpListener::listen` (src/tcp/listener.rs:309) accepts a concrete multicast, broadcast or non-local address. UDP `bind` rejects these with `Unaddressable`. The same gap likely applies to IPv6 multicast destinations through `process_ipv6` (not re-tested).

## Failure scenario

Anyone on the LAN sends SYNs to the subnet broadcast (or 255.255.255.255, or 224.0.0.1) on the device's server port, from several source ports. Each fills a backlog slot. Each socket the application accepts for them sits in SYN-RECEIVED forever, sending nothing. With the fixed-N reused-socket model, a few packets stop the server from accepting real clients. Separately, TCP probes to a broadcast address make the device emit packets with a broadcast source.

## RFC reference

RFC 9293 §3.9.2.3: "A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address [(MUST-57)]. This prevents connection state and replies from being erroneously generated, and implementers should note that this guidance is applicable to all incoming segments, not just SYNs, as specifically indicated in RFC 1122."

RFC 1122 §3.2.1.3 (e): "{ <Network-number>, <Subnet-number>, -1 } Directed broadcast to the specified subnet. It MUST NOT be used as a source address."

## Reproduction

Added to `mod stack_test` of src/tcp/mod.rs in a scratch copy:

```rust
fn vfy_tcp_packet_to(repr: &TcpRepr, dst: Ipv4Addr) -> Vec<u8> {
    let mut buf = build_tcp_packet(repr, &REMOTE_ADDR.into(), &dst.into(), &ChecksumCapabilities::default()).unwrap();
    crate::stack::push_ipv4_header(&mut buf, REMOTE_ADDR, dst, IpProtocol::Tcp, 64, &ChecksumCapabilities::default());
    buf.to_vec()
}
#[test]
#[cfg(feature = "tcp-listener")]
fn vfy_broadcast_syn() {
    for dst in [Ipv4Addr::new(192, 168, 1, 255), Ipv4Addr::new(255, 255, 255, 255)] {
        let (mut stack, driver) = stack();
        let lh = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(lh).listen(LOCAL_PORT).unwrap();
        driver.rx.borrow_mut().push_back(vfy_tcp_packet_to(&TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ..SEND_TEMPL }, dst));
        stack.poll(Instant::from_millis(0));
        println!("dst {}: can_accept={}", dst, stack.tcp_listener(lh).can_accept());
        if let Some(token) = stack.tcp_listener(lh).accept() {
            println!("  token local {}", token.local_addr());
            let h = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
            stack.tcp_socket(h).accept(token).unwrap();
            for t in [0u32, 1000, 5000, 20000, 60000] { stack.poll(Instant::from_millis(t)); }
            println!("  state {:?}, tx frames {}", stack.tcp_socket(h).state(), driver.tx.borrow().len());
        }
        driver.tx.borrow_mut().clear();
        driver.rx.borrow_mut().push_back(vfy_tcp_packet_to(&TcpRepr { dst_port: 81, seq_number: REMOTE_SEQ, ack_number: Some(TcpSeqNumber(5)), ..SEND_TEMPL }, dst));
        stack.poll(Instant::from_millis(61000));
        for f in driver.tx.borrow_mut().iter_mut() {
            let ip = Ipv4Packet::new_checked(&mut f[..]).unwrap();
            println!("  RST frame src {} dst {}", ip.src_addr(), ip.dst_addr());
        }
    }
}
```

`cargo test --lib vfy_broadcast_syn -- --nocapture`

```
dst 192.168.1.255: can_accept=true
  token local 192.168.1.255:80
  state SynReceived, tx frames 0
  RST frame src 192.168.1.255 dst 192.168.1.2
dst 255.255.255.255: can_accept=true
  token local 255.255.255.255:80
  state SynReceived, tx frames 0
  RST frame src 255.255.255.255 dst 192.168.1.2
```

## Suggested fix

At the top of `process_tcp`, drop any segment whose destination is multicast, the limited broadcast, or a directed broadcast of the arrival interface. Do it before the connected-socket demux, the listeners and the RST fallback. Consider rejecting non-unicast addresses in `listen` too, like UDP `bind` does for non-local ones.
