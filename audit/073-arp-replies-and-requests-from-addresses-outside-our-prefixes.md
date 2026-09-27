# 073. ARP from senders outside the interface's prefixes is dropped, so an off-prefix gateway never resolves

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/stack.rs:2206](../src/stack.rs#L2206), [src/iface/dhcpv4.rs:873](../src/iface/dhcpv4.rs#L873), [src/route.rs:154](../src/route.rs#L154), [src/stack.rs:372](../src/stack.rs#L372), [src/stack.rs:2529](../src/stack.rs#L2529) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`process_arp` drops every ARP packet whose sender protocol address is outside the interface's CIDRs. This includes the reply to our own request. Nothing stops a route's gateway from being off-prefix, and the DHCP client installs the leased router whatever the mask. With a /32 lease or any off-prefix gateway, the gateway never resolves and all off-link traffic fails with HostUnreachable.

## Details

src/stack.rs:2206, before `fill_neighbor` at 2215:

```rust
if !iface.in_same_network(&IpAddr::V4(source_protocol_addr)) {
    debug!("arp: source IP address not in same network as us");
    return;
}
```

Nothing else requires the gateway to be on-link:
- `Routes::add` (src/route.rs:154) only checks `route.via_router.is_unicast()`.
- The DHCP client (src/iface/dhcpv4.rs:873) installs `Route::new_ipv4_gateway(new_router, handle)` with no check against the leased prefix.
- `TxContext::route` (src/stack.rs:372) returns the table's `via_router` as next hop.
- `transmit_arp_request` (src/stack.rs:2529) sends the request for it, with a source from `get_source_address_ipv4`.

The reply is thrown away and the entry stays Incomplete. After `MAX_MULTICAST_SOLICIT` probes the parked packets fail with HostUnreachable. Each new send restarts resolution and fails the same way.

The same filter also stops us answering ARP requests from on-link peers configured in another prefix.

smoltcp has the same filter.

This is the same root cause as [053](053-routes-via-a-gateway-outside-the-interface-s-subnets-are-acc.md), reached from the ARP side. One fix covers both.

## Failure scenario

A DHCP server hands out 10.0.0.5 with mask 255.255.255.255 and router 10.0.0.1. Some cloud and ISP setups do this (Hetzner Cloud: x.x.x.x/32, gateway 172.31.1.1). A user can also configure a /32 address with a gateway route by hand. Every packet to the default route is parked on the gateway's resolution, the gateway's reply is dropped, and after about 3 s every send fails. There is no off-link connectivity.

## RFC reference

RFC 826, packet reception:

> ?Do I have the hardware type in ar$hrd?
> Yes: (almost definitely)
>   [optionally check the hardware length ar$hln]
>   ?Do I speak the protocol in ar$pro?
>   Yes:
>     [optionally check the protocol length ar$pln]
>     Merge_flag := false
>     ...
>     ?Am I the target protocol address?

There is no check of the sender's network.

## Reproduction

Test added to `mod test` in src/stack.rs, in a scratch copy of HEAD:

```rust
#[test]
fn vfy_f5_offsubnet_gateway() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let h = IfaceHandle::new(0);
    let us = Ipv4Addr::new(10, 0, 0, 5);
    let gw = Ipv4Addr::new(10, 0, 0, 1);
    stack.iface(h).set_ip_addrs([IpCidr::new(us.into(), 32)]).unwrap();
    stack.routes_mut().add_default_ipv4_route(gw, h).unwrap();
    stack.poll(Instant::ZERO);
    tx.borrow_mut().clear();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp).send_slice(b"hi", (Ipv4Addr::new(8, 8, 8, 8), 53)).unwrap();
    { let tx = tx.borrow(); assert_eq!(tx.len(), 1); assert_eq!(ethertype_of(&tx[0]), EthernetProtocol::Arp);
      let mut f = tx[0].clone(); let arp = ArpPacket::new_checked(&mut f[ETHERNET_HEADER_LEN..]).unwrap();
      assert_eq!(arp.target_protocol_addr(), &gw.octets()[..]); assert_eq!(arp.source_protocol_addr(), &us.octets()[..]); }
    tx.borrow_mut().clear();
    let mut reply = vec![0; ETHERNET_HEADER_LEN + ARP_BUFFER_LEN];
    { let mut eth = EthernetFrame::new_unchecked(&mut reply[..]);
      eth.set_dst_addr(OUR_HW); eth.set_src_addr(OTHER_HW); eth.set_ethertype(EthernetProtocol::Arp);
      let mut arp = ArpPacket::new_unchecked(&mut reply[ETHERNET_HEADER_LEN..]);
      arp.set_hardware_type(ArpHardware::Ethernet); arp.set_protocol_type(EthernetProtocol::Ipv4);
      arp.set_hardware_len(6); arp.set_protocol_len(4); arp.set_operation(ArpOperation::Reply);
      arp.set_source_hardware_addr(OTHER_HW.as_bytes()); arp.set_source_protocol_addr(&gw.octets());
      arp.set_target_hardware_addr(OUR_HW.as_bytes()); arp.set_target_protocol_addr(&us.octets()); }
    inject(&mut stack, &rx, reply);
    println!("F5: {} frames flushed after gateway ARP reply", tx.borrow().len());
    for s in 1..=4 { stack.poll(Instant::from_secs(s)); }
    println!("F5: icmp error on socket = {:?}", stack.udp_socket(udp).take_icmp_error());
    let n_ipv4 = tx.borrow().iter().filter(|f| ethertype_of(f) == EthernetProtocol::Ipv4).count();
    println!("F5: ipv4 frames ever sent = {}", n_ipv4);
    assert_eq!(n_ipv4, 0);
}
```

Output:

```
F5: 0 frames flushed after gateway ARP reply
F5: icmp error on socket = Some((HostUnreachable, SocketAddr { addr: V4(8.8.8.8), port: 53 }))
F5: ipv4 frames ever sent = 0
ok
```

## Suggested fix

Drop the `in_same_network` filter, or apply it only to learning from unsolicited packets. Always accept a reply that matches an Incomplete entry, and answer any request whose target address is ours, as Linux does.
