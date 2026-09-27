# 244. Routes::add accepts a gateway of the other address family: parked packets are flushed with the wrong ethertype, and 802.15.4 panics

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/route.rs:154](../src/route.rs#L154), [src/stack.rs:2418](../src/stack.rs#L2418), [src/stack.rs:2436](../src/stack.rs#L2436), [src/stack.rs:2382](../src/stack.rs#L2382) |
| Features | default (panic path: medium-ieee802154) |
| Verification | reproduced with a test |

## Summary
`Routes::add` checks only that `via_router` is unicast, not that its family matches the cidr. With a mismatched route, an IPv4 packet parked on an IPv6 next hop is flushed with ethertype 0x86DD. If the neighbor was already cached, the same packet goes out correctly, so behavior depends on cache state. On 802.15.4 an IPv6 route via an IPv4 gateway reaches an `unreachable!()` or a panicking `ethernet_addr()`.

## Details
src/route.rs:154:
```rust
pub fn add(&mut self, route: Route) -> Result<(), RouteError> {
    if !route.via_router.is_unicast() {
        return Err(RouteError::NotUnicast);
    }
```
`flush_pending` passes the next hop as the destination (src/stack.rs:2418):
```rust
self.transmit_link(iface, hardware_addr, packet.buf, packet.key.1);
```
and `transmit_link` derives the ethertype from it (src/stack.rs:2436):
```rust
let ethertype = match dst_addr {
    #[cfg(feature = "ipv4")]
    IpAddr::V4(_) => EthernetProtocol::Ipv4,
    #[cfg(feature = "ipv6")]
    IpAddr::V6(_) => EthernetProtocol::Ipv6,
```
`dispatch_ip` uses the packet's own ethertype on `Found`.

On 802.15.4, `solicit_neighbor` with a V4 next hop hits src/stack.rs:2382 without `medium-ethernet`:
```rust
IpAddr::V4(_) => unreachable!(),
```
With `medium-ethernet` it goes to `transmit_arp_request`, which calls `iface.ethernet_addr()` and panics on an 802.15.4 interface. This path was traced, not run.

Needs a user misconfiguration or RFC 5549 style routing. Not remotely triggerable.

## Failure scenario
- `Route { cidr: 10.0.0.0/8, via_router: fe80::99, .. }` on Ethernet: IPv4 packets sent before fe80::99 is resolved go out as IPv6 frames.
- `Route { cidr: ::/0, via_router: 192.168.1.1, iface: lowpan }`: the first IPv6 send panics.

## Reproduction
Test in `src/stack.rs` `mod test`, scratch copy of HEAD:
```rust
#[test]
#[cfg(all(feature = "ipv4", feature = "ipv6", feature = "medium-ethernet"))]
fn lo4_route_family_mismatch_ethertype() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    let gw = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
    stack.routes_mut().add(crate::route::Route { cidr: IpCidr::new(Ipv4Addr::new(10, 0, 0, 0).into(), 8), via_router: gw.into(), iface: IfaceHandle::new(0), origin: crate::route::RouteOrigin::Manual, preferred_until: None, expires_at: None }).unwrap();
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(h).send_slice(b"hi", (Ipv4Addr::new(10, 1, 2, 3), 1000)).unwrap();
    tx.borrow_mut().clear();
    stack.neighbor_cache_mut().insert(IfaceHandle::new(0), gw.into(), HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 0x99])), Instant::from_secs(100)).unwrap();
    stack.poll(Instant::ZERO);
    let frames = tx.borrow();
    assert!(frames.iter().any(|f| ethertype_of(f) == EthernetProtocol::Ipv6 && f[14] >> 4 == 4));
}
```
Output:
```
ethertype Ipv6 ip first byte 45
test ... ok
```

## Suggested fix
Reject routes whose `via_router` family differs from the cidr's in `Routes::add`, and skip them in `lookup` (as for non-unicast gateways written through `iter_mut`). Alternatively store the ethertype with each pending packet instead of deriving it from the next hop.
