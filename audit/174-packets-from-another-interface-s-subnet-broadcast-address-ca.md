# 174. Packets from another interface's subnet-broadcast address cause echo replies, ICMP errors and RSTs to be broadcast on that other interface

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/iface/mod.rs:902](../src/iface/mod.rs#L902), [src/stack.rs:1388](../src/stack.rs#L1388), [src/stack.rs:1580](../src/stack.rs#L1580), [src/stack.rs:2063](../src/stack.rs#L2063), [src/stack.rs:398](../src/stack.rs#L398) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`is_unicast_v4` only knows the arrival interface's prefixes. A packet arriving on interface A with source equal to interface B's directed broadcast passes as unicast. The reply is routed on-link to B and sent there to the broadcast address. Only multi-homed setups are affected, and amplification is 1:1.

## Details
src/stack.rs:1386-1391, the source check uses the arrival interface only:
```rust
let iface = self.ifaces.get(iface.index());
if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
```
The echo reply guard (src/stack.rs:1580) and the ICMP error guard (src/stack.rs:2063) do the same. `route_reply` (src/stack.rs:398) then calls `self.route(IfaceBinding::Any, dst_addr)`, which picks B on-link, with no unicast check on the egress interface. On Ethernet, `lookup_hardware_addr` sees `is_broadcast(dst)` on B and uses the broadcast MAC.

## Failure scenario
iface0 is 192.168.1.1/24, iface1 is 10.0.0.1/24. An attacker on network A sends pings or closed-port UDP/TCP with source 10.0.0.255. Each one makes the device broadcast an echo reply, port unreachable or RST onto network B.

## RFC reference
RFC 1122 §3.2.1.3: "(e) { <Network-number>, <Subnet-number>, -1 } Directed broadcast to the specified subnet. It MUST NOT be used as a source address."

RFC 1122 §3.2.2: an ICMP error message MUST NOT be sent as the result of receiving "a datagram whose source address does not define a single host -- e.g., a zero address, a loopback address, a broadcast address, a multicast address, or a Class E address."

## Reproduction
`stack` module test harness, scratch copy, IP medium:
```rust
#[test]
fn vfy_f3_bcast_src_other_iface() {
    let (mut stack, rx, tx) = test_stack_two_ifaces();
    let bcast_b = Ipv4Addr::new(10, 0, 0, 255);
    let echo = icmpv4_echo(Icmpv4Message::EchoRequest, 1, 1, b"x");
    inject(&mut stack, &rx[0], ipv4_packet(bcast_b, OUR_V4, IpProtocol::Icmp, &echo));
    let t1 = tx[1].borrow();
    for p in t1.iter() {
        let mut pc = p.clone();
        let ip = Ipv4Packet::new_unchecked(&mut pc[..]);
        println!("F3 iface1 out: {} -> {}", ip.src_addr(), ip.dst_addr());
    }
    assert!(t1.is_empty());
}
```
Output: `F3 iface1 out: 192.168.1.1 -> 10.0.0.255`, assertion failed. A closed-port UDP datagram from the same source gave a port unreachable on iface1 too.

## Suggested fix
Check sources against the broadcast addresses of all interfaces, or check the routed reply destination with the egress interface's `is_unicast_v4` in `route_reply`.
