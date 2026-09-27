# 236. Neighbor-failure ICMP errors are generated for every parked non-initial fragment and demuxed on payload bytes read as ports

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:1942](../src/stack.rs#L1942), [src/stack.rs:1964](../src/stack.rs#L1964), [src/icmp_error.rs:88](../src/icmp_error.rs#L88) |
| Features | default |
| Verification | reproduced with a test |

## Summary
IPv4 fragments park on the pending queue one by one. When resolution fails, a Host Unreachable is built for each, non-initial fragments included. `parse_quoted_packet` reads that fragment's payload as ports and sequence number. The error can land on an unrelated socket with a bogus remote endpoint. Errors received from the network that quote a non-initial fragment hit the same parser gap.

## Details
src/stack.rs:1942:
```rust
while let Some(packet) = self.inner.pending.pop_matching(&(iface, addr)) {
    self.deliver_neighbor_failure_error(iface, packet.buf);
}
```
`deliver_neighbor_failure_error` (src/stack.rs:1964) never looks at the fragment offset. Its ICMP-type check reads `orig.get(header_len)`, which is payload for a non-initial fragment. `parse_quoted_packet` (src/icmp_error.rs:88) takes the 8 bytes after the IPv4 header as the L4 header without checking offset or MF. UDP `process_icmp_error` scores sockets on those bytes.

## Failure scenario
MTU 576. A socket on port 5555 sends a 1400-byte UDP datagram of repeating `ABCD` to a dead on-link host, giving 3 fragments. A second socket is bound to port 0x4142 (`AB`). After 3 s the second socket gets HostUnreachable with remote port 0x4344 (`CD`). Its next `recv` returns that error.

## RFC reference
RFC 1122 §3.2.2: "An ICMP error message MUST NOT be sent as the result of receiving: ... a datagram fragment other than the first fragment". The error is local here, but the reason holds: a non-initial fragment has no L4 header.

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
fn vt_frag_neighbor_failure() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ethernet, 576 + 14);
    let dead = Ipv4Addr::new(192,168,1,99);
    let h1 = stack.add_udp_socket().unwrap();
    stack.udp_socket(h1).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let h2 = stack.add_udp_socket().unwrap();
    stack.udp_socket(h2).bind(0x4142, ListenSocketAddr::UNSPECIFIED).unwrap();
    let payload: Vec<u8> = b"ABCD".iter().cycle().take(1400).cloned().collect();
    stack.udp_socket(h1).send_slice(&payload, (dead, 1000)).unwrap();
    for secs in 1..=5 { stack.poll(Instant::ZERO + Duration::from_secs(secs)); }
    let e1 = stack.udp_socket(h1).take_icmp_error();
    let e2 = stack.udp_socket(h2).take_icmp_error();
    println!("VT7 h1={:?} h2={:?} tx={}", e1, e2, tx.borrow().len());
    assert!(e2.is_some());
}
```
Output: `VT7 h1=Some((HostUnreachable, 192.168.1.99:1000)) h2=Some((HostUnreachable, SocketAddr { addr: V4(192.168.1.99), port: 17220 }))`, test passes.

## Suggested fix
In `deliver_neighbor_failure_error`, skip IPv4 packets with a non-zero fragment offset. In `parse_quoted_packet`, return `None` for a quoted IPv4 header with a non-zero fragment offset.
