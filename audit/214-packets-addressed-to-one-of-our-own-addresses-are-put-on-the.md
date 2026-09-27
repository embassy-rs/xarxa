# 214. Packets addressed to one of our own addresses are put on the wire

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:364](../src/stack.rs#L364), [src/stack.rs:2512](../src/stack.rs#L2512) |
| Features | default |
| Verification | reproduced with a test |

## Summary
There is no loopback path. A send to one of our own addresses matches as on-link, so the stack sends an ARP request with sender and target IP both ours, or an NS for our own address. Nobody answers. The packet parks and the socket gets `HostUnreachable` after about 3 s. README and DESIGN.md don't mention the missing loopback.

## Details
src/stack.rs:364
```rust
if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
```
`in_same_network` matches our own address. Neighbor resolution then starts for it (src/stack.rs:2512-2523). On `Medium::Ip` the packet presumably goes straight out to the peer; that was not tested.

## Failure scenario
Ported code talks to another task on the device through its own IP. `send_slice` returns Ok, a gratuitous-ARP-looking frame is broadcast, and 3 s later the socket reports `HostUnreachable`. No datagram is delivered.

## Reproduction
Test in the `stack` module test harness:
```rust
#[test]
fn vtest_f3_send_to_self() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    let u = stack.add_udp_socket().unwrap();
    stack.udp_socket(u).bind(5000, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(u).send_slice(b"x", (OUR_V4, 5000));
    assert_eq!(r, Ok(()));
    assert_eq!(ethertype_of(&tx.borrow()[0]), EthernetProtocol::Arp);
    for t in 1..=4 { stack.poll(Instant::from_millis(t * 1000)); }
    println!("{:?}", stack.udp_socket(u).take_icmp_error());
}
```
Output: `F3 send to self: Ok(()), sent 1 frames, ethertype Arp`, `F3 icmp error after 4s: Some((HostUnreachable, SocketAddr { addr: V4(192.168.1.1), port: 5000 }))`.

## Suggested fix
Deliver packets for our own addresses through local ingress, as `deliver_neighbor_failure_error` does for errors. Or reject them in `route()` with `Unaddressable` and document it.
