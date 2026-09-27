# 216. A route naming a nonexistent interface makes poll() panic on network input

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/stack.rs:376](../src/stack.rs#L376), [src/route.rs:154](../src/route.rs#L154) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`Routes::add` and the `add_default_*_route` helpers accept any `IfaceHandle`. `TxContext::route` indexes the interface slab with the route's handle, and `Slab::get` panics on a vacant slot. Once such a route exists, any packet routed through it panics, including replies to remote input inside `Stack::poll`. `Routes::add` documents no such precondition.

## Details
src/stack.rs:372-377:
```rust
let route = self.inner.routes.lookup(binding, dst_addr, self.inner.now)?;
Some(EgressRoute {
    iface: route.iface,
    next_hop: route.via_router,
    ip_mtu: self.ifaces.get(route.iface.index()).ip_mtu(),
})
```
`remove_iface` purges routes that exist at removal time. A route added later with the old handle, or a handle from another stack, is stored unchecked. The `Routes::add` docs list only `NotUnicast` and `Full`.

Only this lookup was checked. Other places that look up a route's interface may panic the same way.

## Failure scenario
The app removes a USB NIC on unplug, keeps its handle, and re-adds a default route with it on a "network changed" event. The next ICMP echo request or TCP SYN from an off-link host makes the reply path route through it, and `poll` panics with "no item at this index".

## Reproduction
Test in the `stack.rs` test module:
```rust
#[test]
#[should_panic(expected = "no item at this index")]
fn vtest_f5_stale_route_panics_in_poll() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    stack.routes_mut().add_default_ipv4_route(Ipv4Addr::new(192, 168, 1, 254), IfaceHandle::new(1)).unwrap();
    let echo = icmpv4_echo(Icmpv4Message::EchoRequest, 1, 1, b"hi");
    inject(&mut stack, &rx, ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), OUR_V4, IpProtocol::Icmp, &echo));
}
```
Output: `panicked at src/storage/slab.rs:27:5: no item at this index`. The test passes.

## Suggested fix
Have `TxContext::route` skip routes whose interface slot is vacant. At minimum, document a `# Panics` section on `Routes::add` and the default-route helpers.
