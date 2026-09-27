# 248. DHCP unicast renewal takes a gateway from any interface's route, then resolves it on the DHCP interface

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:2651](../src/stack.rs#L2651), [src/iface/dhcpv4.rs:824](../src/iface/dhcpv4.rs#L824), [src/route.rs:304](../src/route.rs#L304) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`transmit_ipv4_on` picks the next hop for an off-link destination with `routes.lookup(IfaceBinding::Any, ...)`. It uses the route's `via_router` but ignores the route's `iface`, and always transmits on the DHCP interface. With default routes on two interfaces, a unicast renewal can be resolved for the other interface's gateway on the wrong link. The renewal is lost until broadcast rebinding at T2.

## Details
src/stack.rs:2647:
```rust
let next_hop = if !dst.is_unicast() || iface.in_same_network(&dst) {
    dst
} else {
    self.routes
        .lookup(IfaceBinding::Any, &dst, self.now)
        .map(|route| route.via_router)
        .unwrap_or(dst)
};
self.transmit_ip(iface, dst, next_hop, buf, EthernetProtocol::Ipv4);
```
`Routes::lookup` filters only by `binding.iface()`. Without `iface-bind`, `IfaceBinding` has only `Any`. Among equal-prefix routes, `max_by_key` (src/route.rs:304) returns the last one. Each DHCP client installs its own 0.0.0.0/0 route (src/iface/dhcpv4.rs:872-881), so the last one added wins.

The renewal destination today is the OFFER's source address (src/iface/dhcpv4.rs:824). That is usually on-link, so the bug needs an off-link source: a relayed server, or a server replying from an address outside the leased subnet.

## Failure scenario
iface0 and iface1 both run DHCP. iface0's server replies from 192.168.1.1 while leasing 192.168.2.x/24. iface1's default route was added last. At T1, iface0's DHCPREQUEST to 192.168.1.1 gets next hop = iface1's router. ARP for it on iface0 fails. Every T1 retry fails the same way, until broadcast rebinding at T2.

## Suggested fix
Only take routes whose `iface` is the DHCP interface, for example with a lookup variant that takes an `IfaceHandle` independent of `iface-bind`. Fall back to `dst` otherwise.
