# 046. NeighborCache::insert accepts a hardware address of the wrong medium, and the next send to that neighbor panics

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/neighbor.rs:355](../src/neighbor.rs#L355), [src/stack.rs:2709](../src/stack.rs#L2709), [src/stack.rs:2726](../src/stack.rs#L2726), [src/stack.rs:2436](../src/stack.rs#L2436), [src/wire/mod.rs:344](../src/wire/mod.rs#L344) |
| Features | default (needs both `medium-ethernet` and `medium-ieee802154`) |
| Verification | reproduced with a test |

## Summary
`NeighborCache::insert` only checks that the addresses are unicast. It cannot check that the hardware address kind matches the interface's medium, because it has no access to the interfaces. In a build with both Ethernet and 802.15.4, inserting an `Ieee802154` address for an Ethernet interface (or the reverse) returns `Ok`. The next packet to that neighbor panics the stack.

## Details
src/neighbor.rs:355:
```rust
if !addr.is_unicast() || !hardware_addr.is_unicast() {
    return Err(NotUnicast);
}

self.fill_with_expiration((iface, addr), hardware_addr, expires_at);
```
The doc lists only `NotUnicast` as an error, and no panic.

`dispatch_ip` trusts the cached address to match the medium. src/stack.rs:2709:
```rust
NeighborLookup::Found(hardware_addr) => {
    self.transmit_ethernet(iface, hardware_addr.ethernet_or_panic(), buf, ethertype)
}
```
src/stack.rs:2726 does the same with `ieee802154_or_panic()`. `ethernet_or_panic` panics with "hardware address is not an Ethernet address" (src/wire/mod.rs:344).

The pending-queue flush path, `transmit_link` (src/stack.rs:2436), matches on the address variant rather than on `iface.medium()`. So a parked packet flushed against a wrong-kind entry is sent through the other medium's path (`dispatch_ieee802154` on an Ethernet interface or `transmit_ethernet` on an 802.15.4 one), which reaches the interface's own `ethernet_addr()`/`ieee802154_addr()` accessor and panics there too.

Network input cannot trigger this. NDISC link-layer options are parsed with `lladdr.parse(iface.medium())`, and ARP only produces Ethernet addresses. `remove_iface` clears the interface's cache entries (src/stack.rs:755), so a reused handle does not inherit them. The public `insert` is the only trigger.

The panic is not only on socket sends. ICMP replies and TCP RSTs to that neighbor, triggered by remote packets, also go through `dispatch_ip` and panic inside `Stack::poll`.

## Failure scenario
A gateway has iface0 on Ethernet and iface1 on 802.15.4. The application pre-seeds a neighbor with `stack.neighbor_cache_mut().insert(iface0, gw, HardwareAddress::Ieee802154(..), t)`, meaning iface1. The call succeeds. The next packet routed to `gw` on iface0 panics the whole stack, from `UdpSocket::send_*` or from `Stack::poll`, far from the bad insert.

## Reproduction
Test in the `src/stack.rs` test module:
```rust
#[test]
fn verify_neighbor_insert_wrong_medium_panics() {
    let (mut stack, _rx, _tx, _room) = test_stack_with_room(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    stack.neighbor_cache_mut().insert(
        iface,
        REMOTE_V4.into(),
        HardwareAddress::Ieee802154(Ieee802154Address::Extended([2; 8])),
        Instant::from_secs(60),
    ).unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000));
    }));
    assert!(r.is_ok());
}
```
`cargo test --lib stack::test::verify_ -- --nocapture`:
```
panicked at src/wire/mod.rs:344:18: hardware address is not an Ethernet address
```

## Suggested fix
Validate the medium at a level that sees the interfaces: for example a `Stack`/`Iface` method that checks `hardware_addr` against `iface.medium()` and returns an error, with `NeighborCache::insert` made crate-private or given the medium. Document the new error. As a second line of defense, have `dispatch_ip` and `transmit_link` drop a packet whose cached address does not match the medium instead of panicking.
