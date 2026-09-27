# 097. UDP receive metadata gives the raw broadcast/multicast destination, not the specific-destination address or arrival interface, so replying with it fails

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/udp.rs:355](../src/udp.rs#L355), [src/udp.rs:881](../src/udp.rs#L881), [src/udp.rs:895](../src/udp.rs#L895), [src/udp.rs:51](../src/udp.rs#L51) |
| Features | default |
| Verification | reproduced with a test |

## Summary

For a datagram sent to a broadcast or multicast address, `UdpMetadata::local_addr` is that broadcast or group address, and no arrival interface is reported. Passing the received metadata back to `send_slice`, the natural reply pattern, fails with `Unaddressable` because the broadcast address is not assigned to any interface. RFC 1122 requires the specific-destination address to be passed up, and for broadcast/multicast that is an address of the arrival interface.

## Details

src/udp.rs:353-357, `parse_datagram`:

```rust
let meta = UdpMetadata {
    remote_addr: SocketAddr::new(src_addr, udp.src_port()),
    local_addr: Some(dst_addr),
    meta: packet_meta,
};
```

src/udp.rs:881-897, `prepare_datagram`:

```rust
let src_addr = match meta.local_addr.or(local.concrete_addr()) {
    Some(addr) => addr,
    ...
};
...
if !self.tx.has_ip_addr(src_addr) {
    return Err(SendError::Unaddressable);
}
```

The doc at src/udp.rs:51 ("the destination address. Always `Some`.") matches the code, and `test_udp_broadcast_delivery` (src/stack.rs:7518) asserts the broadcast value on purpose. So this is a deliberate choice, not a doc bug. But nothing on the receive side records the arrival interface or a specific-destination address. IPv4 multicast groups and IPv6 multicast (e.g. all-nodes) behave the same way.

## Failure scenario

A discovery server bound to `0.0.0.0:9` receives a probe sent to 255.255.255.255 or to the subnet broadcast. It replies with `socket.send_slice(resp, meta)` and gets `Err(Unaddressable)`. The workaround is to set `meta.local_addr = None` before replying, which lets the stack pick a source from the route. On a multi-interface stack the application still cannot tell which interface, and so which of its addresses, the probe was for.

## RFC reference

RFC 1122 §4.1.3.5:

> When a UDP datagram is received, its specific-destination address MUST be passed up to the application layer.

> A request/response application that uses UDP should use a source address for the response that is the same as the specific destination address of the request.

RFC 1122 §3.2.1.3:

> The specific-destination address is defined to be the destination address in the IP header unless the header contains a broadcast or multicast address, in which case the specific-destination is an IP address assigned to the physical interface on which the datagram arrived.

RFC 1122 §3.4:

> Since this may be a broadcast or multicast address, the SpecDest parameter (not shown in RFC-791) MUST be passed.

## Reproduction

Test in `mod test` of src/stack.rs, in a scratch copy of the crate:

```rust
#[test]
fn v_udp_broadcast_reply() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(9, ListenSocketAddr::UNSPECIFIED).unwrap();
    for dst in [Ipv4Addr::BROADCAST, Ipv4Addr::new(192, 168, 1, 255)] {
        let datagram = udp_datagram(REMOTE_V4.into(), 4000, dst.into(), 9, b"probe");
        inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, dst, IpProtocol::Udp, &datagram));
        let mut socket = stack.udp_socket(udp);
        let meta = socket.recv().unwrap().meta();
        let r = socket.send_slice(b"here", meta);
        println!("reply to {:?}: {:?}, tx {}", dst, r, tx.borrow().len());
        assert_eq!(r, Ok(()));
    }
}
```

`cargo test --lib v_udp_broadcast_reply -- --nocapture`:

```
meta = UdpMetadata { remote_addr: 192.168.1.2:4000, local_addr: Some(V4(255.255.255.255)), ... }
reply to 255.255.255.255: Err(Unaddressable), tx 0
assertion `left == right` failed  left: Err(Unaddressable) right: Ok(())
```

The 192.168.1.255 case also returns `Err(Unaddressable)`.

## Suggested fix

Record the arrival interface with the queued packet and expose it in `UdpMetadata`, together with a specific-destination address (an address of that interface when the destination is broadcast or multicast). Alternatively, or in addition, make send treat a broadcast or multicast `local_addr` as "pick a source".
