# 067. Incoming ICMP errors are not checked against traffic we could have sent: spoofed errors make wildcard UDP recv() fail

| | |
|---|---|
| Severity | medium |
| Category | security |
| Location | [src/stack.rs:1655](../src/stack.rs#L1655), [src/stack.rs:1636](../src/stack.rs#L1636), [src/icmp_error.rs:89](../src/icmp_error.rs#L89), [src/udp.rs:1090](../src/udp.rs#L1090), [src/udp.rs:683](../src/udp.rs#L683) |
| Features | default (`icmp-errors`, `udp`) |
| Verification | reproduced with a test |

## Summary

`deliver_icmp_error` trusts the quoted packet. It does not check that the quoted source is one of our addresses, that the quote's IP version matches the ICMP version, or that the outer ICMP was sent to a unicast address of ours. The UDP demux then matches a wildcard-bound socket on the port alone. Anyone who knows a UDP server's port can make its `recv()` return `IcmpError`, one failed call per spoofed packet.

This is a hardening gap, not an RFC violation. RFC 1122 requires UDP to pass ICMP errors up, and RFC 8085's validation SHOULD is aimed at applications. Delivery to unconnected sockets is a documented choice (DESIGN §7). What is not documented is that quotes which cannot be our traffic are accepted too.

## Details

src/stack.rs:1636. `process_icmpv4` hands every error to `deliver_icmp_error`, whatever the outer destination (broadcast passes the IPv4 ingress check):
```rust
(msg_type, msg_code) if msg_type.is_error() => {
    if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
        self.deliver_icmp_error(error, icmp_packet.data_mut());
    }
}
```

src/stack.rs:1655-1666. No check on `local.addr`:
```rust
let Some(quoted) = parse_quoted_packet(quote) else { ... };
let local = SocketAddr::new(quoted.src_addr, quoted.src_port);
let remote = SocketAddr::new(quoted.dst_addr, quoted.dst_port);
match quoted.protocol {
    IpProtocol::Udp => crate::udp::process_icmp_error(&mut self.sockets.udp, error, local, remote),
```

src/icmp_error.rs:89. `parse_quoted_packet` dispatches on `IpVersion::of_packet(quote)`, so an ICMPv4 message may carry an IPv6 quote and vice versa.

src/udp.rs:1090 runs the normal scored demux, and a socket bound to `ListenSocketAddr::UNSPECIFIED` with no remote matches any addresses:
```rust
if let Some(index) = demux(sockets, None, &remote.addr, remote.port, &local.addr, local.port) {
    ...
    socket.pending_error = Some((error, remote));
```

src/udp.rs:683. `recv` returns the pending error before any queued datagram.

The slot holds one error and is cleared when taken. So each spoofed packet costs one failed `recv()`, not a permanent failure. An application written as `recv()?` stops on the first one. DESIGN §7 says "the attached remote endpoint keeps them attributable", but the attacker picks that endpoint. TCP is protected by its sequence check.

## Failure scenario

An off-path attacker sends ICMP port unreachable messages from 9.9.9.9 to 255.255.255.255, quoting UDP 1.2.3.4:5353 -> 8.8.8.8:1. The source 1.2.3.4 is not ours and the flow never existed. An mDNS/DNS/CoAP server bound to the wildcard on 5353 gets `Err(IcmpError { PortUnreachable, 8.8.8.8:1 })` from `recv()` for each one.

## RFC reference

RFC 5927 §4.3:
> As the source address contained in the payload of the ICMP error message does need to be spoofed to perform the attacks described in this document, this kind of advanced filtering serves as a counter-measure against these attacks.

RFC 8085 §5.2:
> Applications SHOULD appropriately validate the payload of ICMP messages to ensure these are received in response to transmitted traffic (i.e., a reported error condition that corresponds to a UDP datagram actually sent by the application).

RFC 1122 §4.1.3.3 (why errors must still be passed up):
> UDP MUST pass to the application layer all ICMP error messages that it receives from the IP layer.

## Reproduction

Test in the `src/stack.rs` test module of a scratch copy, `cargo test --lib vv_ -- --nocapture --test-threads=1`:

```rust
#[test]
fn vv_icmp_spoof_wildcard() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(5353, ListenSocketAddr::UNSPECIFIED).unwrap();
    let fake_src = Ipv4Addr::new(1, 2, 3, 4);
    let fake_dst = Ipv4Addr::new(8, 8, 8, 8);
    let quote = ipv4_packet(fake_src, fake_dst, IpProtocol::Udp,
        &udp_datagram(fake_src.into(), 5353, fake_dst.into(), 1, b"x"));
    let error = icmpv4_error_packet(Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(255, 255, 255, 255),
        Icmpv4Message::DstUnreachable, Icmpv4DstUnreachable::PortUnreachable.into(), &quote);
    inject(&mut stack, &rx, error);
    let r = stack.udp_socket(handle).recv();
    std::println!("wildcard spoof recv: {:?}", r.as_ref().map(|_| ()));
    assert!(matches!(r, Err(UdpRecvError::IcmpError { .. })));
    let quote6 = ipv6_packet(OUR_V6, REMOTE_V6, IpProtocol::Udp,
        &udp_datagram(OUR_V6.into(), 5353, REMOTE_V6.into(), 1, b"x"));
    let error = icmpv4_error_packet(REMOTE_V4, OUR_V4, Icmpv4Message::DstUnreachable,
        Icmpv4DstUnreachable::PortUnreachable.into(), &quote6);
    inject(&mut stack, &rx, error);
    let r = stack.udp_socket(handle).recv();
    std::println!("v4-quoting-v6 recv: {:?}", r.as_ref().map(|_| ()));
    assert!(matches!(r, Err(UdpRecvError::IcmpError { .. })));
}
```

Output:
```
wildcard spoof recv: Err(IcmpError { error: PortUnreachable, remote: SocketAddr { addr: V4(8.8.8.8), port: 1 } })
v4-quoting-v6 recv: Err(IcmpError { error: PortUnreachable, remote: SocketAddr { addr: V6(fdaa::2), port: 1 } })
ok
```

## Suggested fix

In `deliver_icmp_error` (or its callers), drop the error unless:
- the outer ICMP destination is a unicast address of ours,
- the quote's IP version matches the ICMP version,
- the quoted source address is assigned to an interface.

Optionally, deliver errors to unconnected UDP sockets only when the socket has a concrete remote, as Linux does without `IP_RECVERR`.
