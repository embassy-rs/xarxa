# 055. Among equal-prefix routes, lookup always picks the last one and never fails over

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/route.rs:304](../src/route.rs#L304), [src/route.rs:249](../src/route.rs#L249), [src/iface/slaac.rs:516](../src/iface/slaac.rs#L516), [src/iface/dhcpv4.rs:876](../src/iface/dhcpv4.rs#L876), [src/stack.rs:1937](../src/stack.rs#L1937) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`Routes::lookup` picks with `Iterator::max_by_key`, which returns the last of several equally specific routes. Nothing consults the gateway's neighbor state. With two SLAAC default routers, two manual defaults, or DHCP on two interfaces, all off-link traffic goes to the last-installed router, even while its resolution keeps failing. The public `default_ipv4_route()`/`default_ipv6_route()` report the first one, so they disagree with what is used.

## Details

src/route.rs:303-304:

```rust
// pick the most specific one (highest prefix_len)
.max_by_key(|route| route.cidr.prefix_len())
```

SLAAC installs one `::/0` route per advertising router (src/iface/slaac.rs:515-527, up to `SLAAC_ROUTER_COUNT`). When resolution of the chosen gateway fails, `poll_neighbor_timers` (src/stack.rs:1937) answers the parked packets with `HostUnreachable` and removes the neighbor entry. The route stays, so the next packet resolves the same gateway again. For IPv6 this lasts until the router lifetime runs out (1800 s by default, up to 9000 s, refreshed by every RA while the router lives). For IPv4 it lasts forever.

src/route.rs:249-258: `default_ipv4_route` / `default_ipv6_route` use `.find(..)`, the first match. `remove_default_ipv4_route` also removes the first match, so `add_default_ipv4_route` with several defaults may remove a route that is not the one in use. A DHCP router change appends a new default route, which then wins over any earlier manual one by position alone.

The tie-break is not documented on `lookup` (which is `pub(crate)`). None of this is listed in README "Not yet implemented" or DESIGN.md §10/§11.

## Failure scenario

A LAN has two IPv6 routers A and B, both advertising router lifetime 1800 s. B was learned last and loses power. A still works. Every off-link IPv6 send NSes B for 3 s, fails with `HostUnreachable`, and repeats. IPv6 is broken for up to 30 min though A is reachable. With two IPv4 default routes, the same happens with no end.

## RFC reference

RFC 1122 §3.3.1.4:

> The IP layer MUST be able to detect the failure of a "next-hop" gateway that is listed in its route cache and to choose an alternate gateway (see Section 3.3.1.5).

RFC 1122 §3.3.1.5:

> If it is the current default that failed, the IP layer MUST select a different default gateway (assuming more than one default is known) for the failed route and for establishing new routes.

RFC 4861 §6.3.6:

> 1) Routers that are reachable or probably reachable (i.e., in any state other than INCOMPLETE) SHOULD be preferred over routers whose reachability is unknown or suspect (i.e., in the INCOMPLETE state, or for which no Neighbor Cache entry exists).
>
> 2) When no routers on the list are known to be reachable or probably reachable, routers SHOULD be selected in a round-robin fashion, so that subsequent requests for a default router do not return the same router until all other routers have been selected.

## Reproduction

Test in the `stack.rs` test module, default features, run in a scratch copy of the crate:

```rust
#[test]
#[cfg(feature = "medium-ethernet")]
fn zz_equal_default_routes() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let a = Ipv4Addr::new(192,168,1,253); let b = Ipv4Addr::new(192,168,1,254);
    stack.routes_mut().add(crate::route::Route::new_ipv4_gateway(a, iface)).unwrap();
    stack.routes_mut().add(crate::route::Route::new_ipv4_gateway(b, iface)).unwrap();
    assert_eq!(stack.routes().default_ipv4_route().unwrap().via_router, IpAddr::from(a));
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let mut now = Instant::ZERO;
    for round in 0..3 {
        tx.borrow_mut().clear();
        stack.udp_socket(udp).send_slice(b"hi", (Ipv4Addr::new(8,8,8,8), 1000)).unwrap();
        for _ in 0..10 { now = now + Duration::from_secs(1); stack.poll(now); }
        // collect ARP target_protocol_addr of every tx frame
        ... assert!(targets.iter().all(|t| t[..] == b.octets()[..]));
    }
}
```

Output (the test passes, which shows the behavior):

```
round 0 arp targets [[192,168,1,254] x3]
round 1 arp targets [[192,168,1,254] x3]
round 2 arp targets [[192,168,1,254] x3]
```

## Suggested fix

- On equal prefix length, prefer a route whose gateway has a neighbor entry that is not Incomplete. Otherwise rotate among them, for example by moving a route behind its peers when its gateway's resolution fails.
- At minimum, make `default_*_route`, `remove_default_*_route` and `lookup` agree on which route is used, and document the tie-break.
