# 213. Broadcast and multicast go to the first interface even when it can't carry that IP version

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:357](../src/stack.rs#L357), [src/stack.rs:2719](../src/stack.rs#L2719), [src/udp.rs:873](../src/udp.rs#L873) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`TxContext::route` sends every non-unicast destination out of the first interface without checking its medium or its addresses. The first-interface rule is documented (DESIGN.md §11). The extra bug: IPv4 broadcast routed to a first 802.15.4 interface returns Ok and is then silently dropped, breaking the "Ok means in the device or parked" promise of DESIGN.md §7. From a wildcard socket the same send fails with `Unaddressable`, though another interface could send it.

## Details
src/stack.rs:357
```rust
return candidates.next().map(|(_, iface)| EgressRoute {
```
src/stack.rs:2719
```rust
if let IpAddr::V4(_) = dst_addr {
    debug!("dropping IPv4 packet routed to an IEEE 802.15.4 interface");
    return;
}
```
A concrete bound source skips route-based source selection and only has to pass `has_ip_addr` (src/udp.rs:873-889), so the send returns Ok. A wildcard source looks for an IPv4 address on the 802.15.4 interface, finds none, and fails. This also breaks IPv4 mDNS from `DnsClient`. A first IP-medium interface with no IPv6 address likely has the same problem for IPv6 multicast; that case was not tested.

## Failure scenario
A border router adds its 802.15.4 radio first, then Ethernet with 192.168.1.1/24. A UDP socket bound to 192.168.1.1:5000 sends to 255.255.255.255. `send_slice` returns Ok and nothing leaves any interface. A wildcard socket sending to 224.0.0.251:5353 gets `Unaddressable`.

## Reproduction
Test in the `stack` module test harness:
```rust
#[test]
fn vtest_f2_bcast_first_iface_154() {
    let mut stack = Stack::new(0x1234_5678_dead_beef, Instant::ZERO);
    let d0 = TestDevice::new(Medium::Ieee802154); let tx0 = d0.tx.clone();
    let _h0 = d0.install(&mut stack, HardwareAddress::Ieee802154(Ieee802154Address::Extended([0x02; 8])));
    let d1 = TestDevice::new(Medium::Ethernet); let tx1 = d1.tx.clone();
    let h1 = d1.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));
    stack.iface(h1).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    stack.poll(Instant::ZERO); tx0.borrow_mut().clear(); tx1.borrow_mut().clear();
    let u = stack.add_udp_socket().unwrap();
    stack.udp_socket(u).bind((IpAddr::V4(OUR_V4), 5000), ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(u).send_slice(b"x", (Ipv4Addr::new(255, 255, 255, 255), 9));
    let w = stack.add_udp_socket().unwrap();
    stack.udp_socket(w).bind(5001, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r2 = stack.udp_socket(w).send_slice(b"x", (Ipv4Addr::new(224, 0, 0, 251), 5353));
    println!("{:?} {} {} {:?}", r, tx0.borrow().len(), tx1.borrow().len(), r2);
    assert_eq!(r, Ok(())); assert_eq!(tx0.borrow().len() + tx1.borrow().len(), 0);
}
```
Output: `F2 bound bcast: Ok(()) tx0=0 tx1=0`, `F2 wildcard mdns: Err(Unaddressable)`. The test passes, showing the bug.

## Suggested fix
For non-unicast destinations, pick the first candidate that can carry the IP version (not 802.15.4 for IPv4) and has an address of that family. If none can, return None so the send fails with `Unaddressable`.
