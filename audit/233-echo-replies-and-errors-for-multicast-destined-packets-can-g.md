# 233. Echo replies and errors for multicast-destined packets can go out from ::1 when the interface has no IPv6 address

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1829](../src/stack.rs#L1829), [src/stack.rs:2114](../src/stack.rs#L2114), [src/iface/mod.rs:1066](../src/iface/mod.rs#L1066) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Replies to multicast-destined packets take their source from `get_source_address_ipv6`. It returns `::1` when the interface has no IPv6 address. ff02::1 is always accepted, so an interface with no IPv6 address answers a ping to ff02::1 from `::1`.

## Details
src/iface/mod.rs:1066:
```rust
let Some((mut candidate, mut candidate_cidr)) = self.ip_addrs.iter().find_map(ipv6_candidate) else {
    return Ipv6Addr::LOCALHOST;
};
```
src/stack.rs:1829 (echo reply) and 2114 (`transmit_icmpv6_error`, the `allow_multicast_dst` case) use it for non-unicast destinations. `has_multicast_group` always accepts `IPV6_LINK_LOCAL_ALL_NODES`. IP-medium interfaces get no automatic link-local, and a user can remove the Ethernet one.

## Failure scenario
An IP-medium interface has only an IPv4 address. A neighbor pings ff02::1. The stack sends an echo reply with source `::1`.

## RFC reference
RFC 4443 §4.2: "the source address of the reply MUST be a unicast address belonging to the interface on which the Echo Request message was received."
RFC 4291 §2.5.3: "The loopback address must not be used as the source address in IPv6 packets that are sent outside of a single node."

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
fn vt_echo_mcast_from_loopback() {
    let driver = TestDevice::new(Medium::Ip);
    let (rx, tx) = (driver.rx.clone(), driver.tx.clone());
    let mut stack = Stack::new(1, Instant::ZERO);
    let h = driver.install(&mut stack, HardwareAddress::Ip);
    stack.iface(h).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    stack.poll(Instant::ZERO);
    tx.borrow_mut().clear();
    let remote = Ipv6Addr::new(0xfe80,0,0,0,0,0,0,5);
    let req = icmpv6_echo(Icmpv6Message::EchoRequest, 1, 1, b"hi", remote, IPV6_LINK_LOCAL_ALL_NODES);
    inject(&mut stack, &rx, ipv6_packet(remote, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol::Icmpv6, &req));
    let tx = tx.borrow();
    assert_eq!(tx.len(), 1);
    let mut b = tx[0].clone();
    let ip = Ipv6Packet::new_checked(&mut b[..]).unwrap();
    println!("VT3 src={} dst={}", ip.src_addr(), ip.dst_addr());
    assert_eq!(ip.src_addr(), Ipv6Addr::LOCALHOST);
}
```
Output: `VT3 src=::1 dst=fe80::5`, test passes.

## Suggested fix
Drop the reply when the selected source is `::1`. Or don't accept IPv6 multicast on an interface with no IPv6 address.
