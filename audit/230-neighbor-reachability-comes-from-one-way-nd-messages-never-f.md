# 230. Gateway neighbor entries expire every 60 s under traffic and are re-resolved

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/stack.rs:1407](../src/stack.rs#L1407), [src/stack.rs:1709](../src/stack.rs#L1709), [src/neighbor.rs:169](../src/neighbor.rs#L169), [src/neighbor.rs:252](../src/neighbor.rs#L252) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Ingress refreshes the neighbor entry keyed by the packet's IP source. Traffic forwarded by a gateway carries remote sources, so the gateway's entry is never refreshed by it. After 60 s it becomes Stale, which is not used to send, and the next packet waits for a fresh ARP/NDISC round trip. This affects IPv4 and IPv6. Packets are lost only if one burst exceeds the 16-entry drop-head pending queue.

## Details
src/stack.rs:1407 (IPv6 at 1709):
```rust
self.inner.neighbor_cache.reset_expiry_if_existing(
```
keyed on `(iface.handle, IpAddr::V4(src_addr))`. src/neighbor.rs:252 turns the entry Stale at expiry, and `lookup` (src/neighbor.rs:169) returns `NotFound` for Stale. There is no upper-layer hint from TCP.

This follows from the documented reduced state machine (DESIGN §6). It also means RA/NS SLLAOs and unsolicited NAs create Reachable entries, where RFC 4861 creates STALE ones. An RFC node would also send using those STALE entries, so the practical difference is small. The public `NeighborCache` doc ("expire after 60 s unless traffic from the neighbor refreshes them") does not make the gateway case clear.

## Failure scenario
A device streams data to a cloud server through its router. Every 60 s outgoing packets wait for an ARP round trip. A TCP dispatch of more than 16 segments in that window loses the oldest ones.

## RFC reference
RFC 4861 §7.3.1: "For off-link destinations, forward progress implies that the first-hop router is reachable. When available, this upper-layer information SHOULD be used."

RFC 4861 §7.3.1: "Receipt of other Neighbor Discovery messages, such as Router Advertisements and Neighbor Advertisement with the Solicited flag set to zero, MUST NOT be treated as a reachability confirmation."

## Reproduction
Test in a scratch copy of `src/stack.rs` `mod test`:
```rust
#[test]
#[cfg(feature = "medium-ethernet")]
fn vv_gateway_expiry_under_traffic() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let gw = Ipv4Addr::new(192, 168, 1, 254);
    let gw_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0xfe]);
    stack.routes_mut().add_default_ipv4_route(gw, iface).unwrap();
    stack.inner.neighbor_cache.fill((iface, IpAddr::V4(gw)), HardwareAddress::Ethernet(gw_hw), Instant::ZERO);
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(9, ListenSocketAddr::UNSPECIFIED).unwrap();
    let far = Ipv4Addr::new(8, 8, 8, 8);
    let mut arp_at = None;
    for t in 1..=65u32 {
        let now = Instant::from_secs(t);
        let pkt = ipv4_packet(far, OUR_V4, IpProtocol::Udp, &udp_datagram(far.into(), 53, OUR_V4.into(), 9, b"in"));
        rx.borrow_mut().push_back(eth_frame_from(gw_hw, OUR_HW, EthernetProtocol::Ipv4, &pkt));
        stack.poll(now);
        let mut buf = [0u8; 8];
        let _ = stack.udp_socket(handle).recv_slice(&mut buf);
        tx.borrow_mut().clear();
        stack.udp_socket(handle).send_slice(b"out", (far, 53)).unwrap();
        if tx.borrow().iter().any(|f| ethertype_of(f) == EthernetProtocol::Arp) && arp_at.is_none() {
            arp_at = Some(t);
            std::println!("ARP for gateway at t={t}, frames={}", tx.borrow().len());
        }
    }
    assert!(arp_at.is_some());
}
```
Output:
```
ARP for gateway at t=60, frames=1
ok
```

## Suggested fix
Let TCP refresh the next hop's entry on a new ACK, using the route it already computes. Or keep sending on an expired entry that is in use while probing it with a unicast solicitation.
