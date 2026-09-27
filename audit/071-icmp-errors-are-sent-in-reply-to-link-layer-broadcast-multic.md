# 071. ICMP errors are sent in reply to link-layer broadcast and multicast frames

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:1245](../src/stack.rs#L1245), [src/stack.rs:2063](../src/stack.rs#L2063), [src/stack.rs:2103](../src/stack.rs#L2103), [src/udp.rs:1024](../src/udp.rs#L1024), [src/sixlowpan.rs:138](../src/sixlowpan.rs#L138) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`process_ethernet` accepts broadcast and multicast frames, but passes only the source MAC to `process_ipv4` and `process_ipv6`. Whether the frame was a link-layer broadcast or multicast is lost. `transmit_icmpv4_error` and `transmit_icmpv6_error` only look at IP addresses. So a unicast-IP datagram carried in a broadcast or multicast frame still draws a port unreachable, protocol unreachable or parameter problem. RFC 1122 and RFC 4443 both say MUST NOT.

## Details

src/stack.rs:1248 accepts the frame on any of three destination kinds:

```rust
if !eth_frame.dst_addr().is_broadcast()
    && !eth_frame.dst_addr().is_multicast()
    && eth_frame.dst_addr() != self.ifaces.get(iface.index()).ethernet_addr()
{
    return;
}
```

src/stack.rs:1279 and 1281 then pass only the source:

```rust
EthernetProtocol::Ipv4 => self.process_ipv4(iface, Some(src_addr), buf),
EthernetProtocol::Ipv6 => self.process_ipv6(iface, Some(HardwareAddress::Ethernet(src_addr)), buf),
```

src/stack.rs:2063, the only suppression in `transmit_icmpv4_error`:

```rust
if !iface.is_unicast_v4(src_addr) || !iface.is_unicast_v4(dst_addr) {
    return;
}
```

src/stack.rs:2103, the only suppression in `transmit_icmpv6_error`:

```rust
if !src_addr.x_is_unicast() {
    return;
}
if dst_addr.is_multicast() && !allow_multicast_dst {
    return;
}
```

Affected callers:
- UDP port unreachable, src/udp.rs:1024.
- IPv4 protocol unreachable, src/stack.rs:1463.
- IPv6 hop-by-hop parameter problem, src/stack.rs:1734.
- IPv6 unrecognized next header, src/stack.rs:1787.

`process_ieee802154` (src/sixlowpan.rs:138) has the same gap. It does not pass on that the MAC destination was the broadcast short address 0xffff.

When the sender's neighbor entry is unresolved, the IPv6 error is parked in the pending queue and an NS goes out. So the reaction also costs a pool buffer and a solicitation.

RFC 1122 §3.3.6 also says such datagrams SHOULD be silently discarded. They are currently delivered to matching sockets.

## Failure scenario

1. A host on the LAN sends UDP to our unicast IPv4 address, closed port 9, in an Ethernet frame to ff:ff:ff:ff:ff:ff.
2. We answer with ICMP Destination Unreachable, code 3.

Every xarxa host that owns the address answers. On a misconfigured LAN, hosts with overlapping addresses answer too. This is the broadcast-storm case the rule exists for. The IPv6 variant (frame to 33:33:00:00:00:01, unicast IPv6 destination, unknown next header) draws a Parameter Problem.

## RFC reference

RFC 1122 §3.2.2:

> An ICMP error message MUST NOT be sent as the result of receiving:
> ...
> * a datagram sent as a link-layer broadcast, or

RFC 4443 §2.4(e):

> An ICMPv6 error message MUST NOT be originated as a result of receiving the following:
> ...
> (e.4) A packet sent as a link-layer multicast (the exceptions from e.3 apply to this case, too).
>
> (e.5) A packet sent as a link-layer broadcast (the exceptions from e.3 apply to this case, too).

RFC 1122 only names link-layer broadcast. A unicast-IP datagram in a link-layer multicast frame is not strictly covered for IPv4, though the same reasoning applies.

## Reproduction

Test added to `mod test` in src/stack.rs, in a scratch copy of HEAD:

```rust
#[test]
fn vfy_f2_ll_broadcast_icmp_error() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    inject(&mut stack, &rx, arp_request_from(OTHER_HW, REMOTE_V4));
    tx.borrow_mut().clear();
    let dgram = udp_datagram(REMOTE_V4.into(), 1000, OUR_V4.into(), 9, b"hello");
    let pkt = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &dgram);
    inject(&mut stack, &rx, eth_frame_from(OTHER_HW, EthernetAddress::BROADCAST, EthernetProtocol::Ipv4, &pkt));
    { let tx = tx.borrow(); println!("F2 v4: {} frames", tx.len());
      for f in tx.iter() { let (t, c, _) = parse_icmpv4_reply(&f[ETHERNET_HEADER_LEN..], OUR_V4, REMOTE_V4); println!("F2 v4 reply type={:?} code={}", t, c); }
      assert_eq!(tx.len(), 1); }
    tx.borrow_mut().clear();
    let pkt6 = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol(99), b"abcd");
    inject(&mut stack, &rx, eth_frame_from(OTHER_HW, EthernetAddress([0x33,0x33,0,0,0,1]), EthernetProtocol::Ipv6, &pkt6));
    let tx = tx.borrow();
    for f in tx.iter() { println!("F2 v6 frame ethertype={:?} len={}", ethertype_of(f), f.len()); }
    assert!(!tx.is_empty());
}
```

Output:

```
F2 v4: 1 frames
F2 v4 reply type=DstUnreachable code=3
F2 v6 frame ethertype=Ipv6 len=86
ok
```

The IPv6 frame is the NS for the sender. It goes out because the Parameter Problem was generated and parked behind it.

## Suggested fix

Carry a "link-layer broadcast or multicast" flag from `process_ethernet` and `process_ieee802154` into `process_ipv4` and `process_ipv6`, down to the error paths. Suppress ICMP errors when it is set. Keep the RFC 4443 e.3 exceptions for IPv6 (Packet Too Big, and Parameter Problem code 2 for options with high bits 10). Optionally also drop such datagrams before socket delivery, per RFC 1122 §3.3.6.
