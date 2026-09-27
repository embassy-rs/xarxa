# 054. Routes::add accepts a gateway of the other IP family, which panics on 802.15.4

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/route.rs:154](../src/route.rs#L154), [src/stack.rs:375](../src/stack.rs#L375), [src/stack.rs:2721](../src/stack.rs#L2721), [src/stack.rs:2382](../src/stack.rs#L2382), [src/stack.rs:2549](../src/stack.rs#L2549), [src/iface/mod.rs:388](../src/iface/mod.rs#L388) |
| Features | default, or `medium-ieee802154` + `ipv4` + `ipv6` without `medium-ethernet` |
| Verification | reproduced with a test |

## Summary

`Routes::add` only checks that `via_router` is unicast. It does not check that it has the same IP family as `cidr`. With a route like `::/0 via 192.168.1.254` out of an 802.15.4 interface, an IPv6 send starts ARP resolution of the IPv4 next hop. Without `medium-ethernet` that hits `unreachable!()`. In the default build it hits `ethernet_or_panic()` when the 802.15.4 interface also has an IPv4 address, which `add_ip_addr`/`set_ip_addrs` accept.

## Details

src/route.rs:154 has no family check. `TxContext::route` uses the gateway as next hop (src/stack.rs:375). `dispatch_ip` drops IPv4 *destinations* on 802.15.4, but not IPv4 *next hops* (src/stack.rs:2718-2724):

```rust
#[cfg(feature = "ipv4")]
if let IpAddr::V4(_) = dst_addr {
    debug!("dropping IPv4 packet routed to an IEEE 802.15.4 interface");
    return;
}
match self.lookup_hardware_addr(iface, &dst_addr, next_hop) {
```

`lookup_hardware_addr` calls `solicit_neighbor` with the IPv4 next hop. src/stack.rs:2378-2382:

```rust
// IPv4 is never dispatched to an 802.15.4 interface (`dispatch_ip`),
// so no IPv4 resolution ever starts without Ethernet.
#[cfg(all(feature = "ipv4", not(feature = "medium-ethernet")))]
IpAddr::V4(_) => unreachable!(),
```

The comment holds for destinations but not for next hops.

With `medium-ethernet`, `transmit_arp_request` runs. If `get_source_address_ipv4` finds an IPv4 address on the interface, src/stack.rs:2549 calls `iface.ethernet_addr()`, which is `self.hardware_addr.ethernet_or_panic()` (src/iface/mod.rs:699).

The panic fires synchronously inside `send_slice` (or TCP dispatch) on the first lookup. The retransmit path in `poll_neighbor_timers` (src/stack.rs:1935) also calls `solicit_neighbor`. With no IPv4 address on the interface, `send_slice` returns `Ok` and the packet parks until resolution fails.

On Ethernet, an IPv6 route via an IPv4 gateway silently sends IPv6 frames to the MAC of an ARP-resolved IPv4 host. The reverse, an IPv4 route with an IPv6 next hop (RFC 5549 style), works on Ethernet and is legitimate.

## Failure scenario

The application adds a default IPv6 route by hand and passes an IPv4 gateway by mistake. The first IPv6 send to an off-link destination panics inside `send_slice` or TCP dispatch.

## Reproduction

Default features, in the `stack.rs` test module. `test_stack(Medium::Ieee802154)` gives the interface 192.168.1.1/24 and fdaa::1/64.

```rust
#[test]
#[cfg(feature = "medium-ieee802154")]
fn zz_v4_gateway_on_sixlowpan() {
    let (mut stack, _rx, _tx) = test_stack(Medium::Ieee802154);
    let iface = IfaceHandle::new(0);
    let route = crate::route::Route { cidr: IpCidr::new(Ipv6Addr::UNSPECIFIED.into(), 0), via_router: Ipv4Addr::new(192,168,1,254).into(), iface, origin: crate::route::RouteOrigin::Manual, preferred_until: None, expires_at: None };
    assert!(stack.routes_mut().add(route).is_ok());
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let _ = stack.udp_socket(udp).send_slice(b"hi", (Ipv6Addr::new(0x2001,0xdb8,0,0,0,0,0,1), 1000));
}
```

Output:

```
panicked at src/wire/mod.rs:344:18: hardware address is not an Ethernet address
```

The same scenario as a standalone test module in `sixlowpan.rs`, gated `#[cfg(all(test, feature = "ipv4", feature = "udp", not(feature = "medium-ethernet")))]`, using `TestDevice::new(Medium::Ieee802154).install(...)`:

```
cargo test --lib --no-default-features --features std,alloc,log,medium-ieee802154,ipv4,ipv6,udp zz_v4_gateway_noeth2
panicked at src/stack.rs:2382:30: internal error: entered unreachable code
```

## Suggested fix

- Reject unusable combinations in `Routes::add` with a new `RouteError` variant: at least an IPv4 gateway for an IPv6 prefix, and any IPv4 gateway on a non-Ethernet interface. Keep IPv4-via-IPv6 on Ethernet.
- Make `solicit_neighbor` drop instead of `unreachable!()`, and skip ARP on non-Ethernet interfaces.
- Optionally reject IPv4 addresses on 802.15.4 interfaces in `add_ip_addr`/`set_ip_addrs`.
