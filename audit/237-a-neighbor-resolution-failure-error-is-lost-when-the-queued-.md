# 237. A neighbor resolution failure error is lost when the queued packet's source address belongs to another interface

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:2000](../src/stack.rs#L2000), [src/stack.rs:2037](../src/stack.rs#L2037), [src/stack.rs:1394](../src/stack.rs#L1394) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`deliver_neighbor_failure_error` feeds the synthesized Destination Unreachable into `process_ipv4`/`process_ipv6` on the interface where resolution failed. The destination check there only accepts that interface's addresses. Egress is weak-host (DESIGN.md §6), so the parked packet's source may belong to another interface. Then the error is dropped, and the fast failure DESIGN.md §6 promises does not happen.

## Details
src/stack.rs:2000 (IPv4), and the same at 2037 for IPv6:
```rust
self.process_ipv4(iface, None, reply);
```
src/stack.rs:1394:
```rust
if !iface.has_ip_addr(dst_addr.into())
    && !iface.has_multicast_group(dst_addr.into())
    && !iface.is_broadcast_v4(dst_addr)
```
Egress accepts a source on any interface (`has_ip_addr` over all interfaces in src/udp.rs and src/tcp/mod.rs).

## Failure scenario
iface0 is 192.168.1.1/24, iface1 is 10.0.0.1/24. A UDP socket bound to 10.0.0.1:5555 sends to 192.168.1.99, which is dead. Three ARP requests go out, then the error is dropped. `take_icmp_error()` returns `None`. A TCP connect in the same setup waits for its SYN retransmissions instead of failing after about 3 s.

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
fn vt_neighbor_failure_other_iface_src() {
    let mut stack = Stack::new(1, Instant::ZERO);
    let mut txs = Vec::new();
    for (i, addr) in [IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V4_B.into(), 24)].into_iter().enumerate() {
        let driver = TestDevice::new(Medium::Ethernet);
        txs.push(driver.tx.clone());
        let h = driver.install(&mut stack, HardwareAddress::Ethernet(EthernetAddress([2,0,0,0,0,0x10 + i as u8])));
        stack.iface(h).set_ip_addrs(core::iter::once(addr)).unwrap();
    }
    stack.poll(Instant::ZERO);
    let dead = Ipv4Addr::new(192,168,1,99);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(ListenSocketAddr { addr: Some(OUR_V4_B.into()), port: 5555 }, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(h).send_slice(b"x", (dead, 1000)).unwrap();
    for secs in 1..=5 { stack.poll(Instant::ZERO + Duration::from_secs(secs)); }
    let e = stack.udp_socket(h).take_icmp_error();
    println!("VT8 err={:?} tx0={}", e, txs[0].borrow().len());
    assert!(e.is_none());
}
```
Output: `VT8 err=None tx0=4`, test passes (the error was lost). The existing `test_neighbor_failure_reported_to_udp_socket` shows the error arrives when the source is on the egress interface.

## Suggested fix
Deliver the error directly to ICMP error handling (`deliver_icmp_error` plus the raw-socket offer), skipping the destination check. Or inject it on an interface that owns the source address.
