# 056. IEEE 802.15.4 ingress never checks the frame's destination address

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/sixlowpan.rs:138](../src/sixlowpan.rs#L138), [src/iface/mod.rs:333](../src/iface/mod.rs#L333), [src/stack.rs:1248](../src/stack.rs#L1248), [xarxa-driver/src/lib.rs:51](../xarxa-driver/src/lib.rs#L51) |
| Features | medium-ieee802154 (reassembly scenario also needs sixlowpan-reassembly, default) |
| Verification | reproduced with a test |

## Summary

`process_ieee802154` checks the frame type, the security bit and the destination PAN id. It never compares the MAC destination address against the interface's address or broadcast. A frame unicast to another node is decompressed and passed on. Ethernet ingress does filter on the destination MAC, and the public doc of `Iface::set_hardware_addr` promises ingress filtering.

## Details

src/sixlowpan.rs:155-167, after the PAN check there is nothing else:

```rust
let pan_id = self.ifaces.get(iface.index()).sixlowpan.pan_id;
if pan_id.is_some()
    && ieee802154_repr.dst_pan_id != pan_id
    && ieee802154_repr.dst_pan_id != Some(Ieee802154Pan::BROADCAST)
{
    ...
    return;
}

buf.pull_front(header_len);
self.process_sixlowpan(iface, &ieee802154_repr, buf)
```

Compare src/stack.rs:1248-1254:

```rust
if !eth_frame.dst_addr().is_broadcast()
    && !eth_frame.dst_addr().is_multicast()
    && eth_frame.dst_addr() != self.ifaces.get(iface.index()).ethernet_addr()
{
    return;
}
```

The driver contract does not ask for address filtering. The `Medium::Ieee802154` doc (xarxa-driver/src/lib.rs:51-56) only describes the frame format and MTU. Radios in promiscuous mode, Linux monitor sockets and some MCU radio drivers pass every frame on the channel.

src/iface/mod.rs:333-334, public doc of `set_hardware_addr`:

```rust
/// The stack starts using it for the frames it sends and for ingress filtering
/// immediately.
```

On this medium no ingress filtering happens.

`process_ipv6` still checks the IPv6 destination, so overheard unicast with a foreign IPv6 destination is dropped there. What gets through:

- Fragments. Reassembly runs before the IPv6 checks, so third-party fragments are keyed and reassembled. They take a reassembly slot (one by default) and a pool buffer.
- IPv6 multicast carried in frames unicast to another node.
- Packets whose IPv6 destination is ours but whose MAC destination is another node.

Many radios filter addresses in hardware, which limits the real-world impact.

## Failure scenario

The driver runs the radio without hardware address filtering. Nodes B and C exchange a fragmented datagram and xarxa (node A) misses one of its fragments. A's only reassembly slot stays held by B's datagram until the reassembly timeout (60 s). A's own incoming fragmented datagrams are dropped meanwhile.

## Reproduction

Test in the `sixlowpan.rs` `mod test` harness, default features:

```rust
#[test]
fn zz_not_our_mac() {
    let (mut stack, _iface, rx, _tx, _room) = test_stack(OUR_LL, Some(PAN));
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(6969, ListenSocketAddr::UNSPECIFIED).unwrap();
    let other = Ieee802154Address::Extended([0x02; 8]);
    let datagram = udp_datagram(PEER_LINK_LOCAL.into(), 1234, OUR_LINK_LOCAL.into(), 6969, b"notforus");
    let packet = ipv6_packet(PEER_LINK_LOCAL, OUR_LINK_LOCAL, IpProtocol::Udp, &datagram);
    let (compressed, _) = compress(&packet, PEER_LL, other, 0);
    inject(&mut stack, &rx, frame(PEER_LL, other, PAN, &compressed));
    let r = stack.udp_socket(udp).recv().map(|p| p.to_vec());
    assert!(r.is_err(), "frame to another MAC was delivered");
}
```

`cargo test --lib zz_ -- --nocapture`:

```
recv Ok([110, 111, 116, 102, 111, 114, 117, 115])
panicked ... frame to another MAC was delivered
```

## Suggested fix

In `process_ieee802154`, drop data frames whose destination address is present and is neither broadcast (0xffff) nor the interface's short or extended address, as Ethernet does. Alternatively, require drivers to filter in the `Medium::Ieee802154` doc and fix the `set_hardware_addr` doc.
