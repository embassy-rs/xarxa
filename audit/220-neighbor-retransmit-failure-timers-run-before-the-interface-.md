# 220. Neighbor retransmit/failure timers run before the interface's RX queue is drained

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:1090](../src/stack.rs#L1090), [src/stack.rs:1093](../src/stack.rs#L1093) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`poll` runs `poll_neighbor_timers` for an interface before draining that interface's RX queue. A reply already queued is processed only after the timers acted. On a late poll that means a redundant solicitation. On the last probe the resolution fails, parked packets get host unreachable (TCP connects abort), and only then is the reply processed.

## Details
src/stack.rs:1090-1093:
```rust
self.poll_neighbor_timers(handle);
...
while let Some(mut buf) = self.ifaces.get_mut(index).driver.receive() {
```
On `ProbeEvent::Failed`, `poll_neighbor_timers` pops the parked packets and calls `deliver_neighbor_failure_error`. Every other timer consumer (DHCP, SLAAC, TCP, reassembly, pending expiry) runs after ingress.

It needs a poll at or after the deadline with a reply already queued: polling-only drivers, or a delayed runner. An RX-wake-driven runner would normally have polled on arrival.

## Failure scenario
The third ARP probe goes out at t=2 s. The reply arrives at 2.95 s, but the loop polls only at its deadline. `poll(3 s)` fails the resolution first: the parked datagram becomes a local host unreachable and a TCP connect would abort. Then the ARP reply fills the cache, too late.

## Reproduction
Test in the `stack.rs` test module:
```rust
#[test]
fn vtest_f10_neighbor_timer_before_rx() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let u = stack.add_udp_socket().unwrap();
    stack.udp_socket(u).bind(5000, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(u).send_slice(b"x", (REMOTE_V4, 5000)).unwrap();
    stack.poll(Instant::from_millis(1000));
    stack.poll(Instant::from_millis(2000));
    let n_before = tx.borrow().len();
    rx.borrow_mut().push_back(arp_request_from(EthernetAddress([0x02,0,0,0,0,0x02]), REMOTE_V4));
    stack.poll(Instant::from_millis(3000));
    let e = stack.udp_socket(u).take_icmp_error();
    let ipv4_sent = tx.borrow()[n_before..].iter().filter(|f| ethertype_of(f) == EthernetProtocol::Ipv4).count();
    assert!(e.is_some()); assert_eq!(ipv4_sent, 0);
}
```
Output: `error=Some((HostUnreachable, SocketAddr { addr: V4(192.168.1.2), port: 5000 })) ipv4 frames sent after answer=0`. The test passes.

## Suggested fix
Drain the interface's RX queue before `poll_neighbor_timers`, or run the neighbor timers after ingress for all interfaces.
