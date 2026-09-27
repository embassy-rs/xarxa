# 053. Routes via a gateway outside the interface's subnets are accepted but never resolve

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/route.rs:154](../src/route.rs#L154), [src/route.rs:214](../src/route.rs#L214), [src/stack.rs:375](../src/stack.rs#L375), [src/stack.rs:2206](../src/stack.rs#L2206), [src/iface/dhcpv4.rs:876](../src/iface/dhcpv4.rs#L876) |
| Features | default (`medium-ethernet`, `ipv4`) |
| Verification | reproduced with a test |

## Summary

`Routes::add`, `add_default_ipv4_route` and the DHCP client accept an IPv4 gateway that is not inside any of the interface's prefixes. The ARP request for it goes out, but `process_arp` drops every ARP packet whose sender is outside the interface's prefixes. That covers both the gateway's reply and its own request for us. The gateway never resolves, and all off-link traffic fails with `HostUnreachable` after about 3 s, while `send` returns `Ok`. There is no error at configuration time.

## Details

src/route.rs:154 checks only unicast-ness:

```rust
pub fn add(&mut self, route: Route) -> Result<(), RouteError> {
    if !route.via_router.is_unicast() {
        return Err(RouteError::NotUnicast);
    }
    self.storage.push(route).map_err(|_| RouteError::Full)
}
```

`add_default_ipv4_route` (src/route.rs:209) is the same. `TxContext::route` uses the gateway as next hop (src/stack.rs:375, `next_hop: route.via_router`). `dispatch_ip` parks the packet and `transmit_arp_request` broadcasts a request for the gateway.

The answer is then discarded at src/stack.rs:2206:

```rust
if !iface.in_same_network(&IpAddr::V4(source_protocol_addr)) {
    debug!("arp: source IP address not in same network as us");
    return;
}
```

So the neighbor cache is never filled, no ARP reply is sent to the gateway's own request, and on resolution failure the parked packets get a local `HostUnreachable`.

The DHCP client installs the router option as-is (src/iface/dhcpv4.rs:876, `Route::new_ipv4_gateway(new_router, handle)`), with no on-link check. /32 leases and routers outside the leased subnet are used by some cloud and ISP DHCP servers.

The route's egress interface and `in_same_network` are checked independently, so a gateway that is on-link for a different interface than `route.iface` fails the same way.

Linux rejects such a manual route ("Nexthop has invalid gateway") unless `onlink` is given.

## Failure scenario

- A DHCP server hands out 203.0.113.7/32 with router 203.0.113.1.
- Or the user calls `add_default_ipv4_route(10.0.0.1)` on an interface that only has 192.168.1.1/24.

Every off-link packet parks, the router's ARP traffic is discarded, and after 3 s the socket gets `HostUnreachable`. No connectivity, no configuration error.

## Reproduction

Test in the `stack.rs` test module (`test_stack(Medium::Ethernet)`, interface 192.168.1.1/24), run in a scratch copy of the crate:

```rust
#[test]
fn vrfy_offlink_gateway_never_resolves() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let gw = Ipv4Addr::new(10, 0, 0, 1);
    let iface = stack.ifaces().next().map(|(h, _)| h).unwrap();
    stack.routes_mut().add_default_ipv4_route(gw, iface).unwrap();
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    stack.udp_socket(handle).send_slice(b"hi", (dst, 53)).unwrap();
    { let t = tx.borrow(); assert_eq!(t.len(), 1); let mut f0 = t[0].clone();
      let eth = EthernetFrame::new_checked(&mut f0[..]).unwrap(); assert_eq!(eth.ethertype(), EthernetProtocol::Arp); }
    tx.borrow_mut().clear();
    let gw_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x99]);
    inject(&mut stack, &rx, arp_request_from(gw_hw, gw));
    println!("frames after ARP from gw: {}", tx.borrow().len());
    assert!(tx.borrow().is_empty());
    for secs in 1..=4 { stack.poll(Instant::ZERO + Duration::from_secs(secs)); }
    let err = stack.udp_socket(handle).take_icmp_error();
    println!("icmp error: {:?}", err);
    assert_eq!(err, Some((IcmpError::HostUnreachable, SocketAddr::new(dst.into(), 53))));
}
```

Output:

```
frames after ARP from gw: 0
icmp error: Some((HostUnreachable, SocketAddr { addr: V4(8.8.8.8), port: 53 }))
ok
```

## Suggested fix

Either:

- Reject such routes in `add` with a new `RouteError` variant, and have the DHCP client install an on-link host route for a router outside the lease's prefix (as RFC 3442 setups do).
- Or treat a route's gateway as on-link for ARP: in `process_arp`, also accept a sender that is the `via_router` of a route out of this interface.
