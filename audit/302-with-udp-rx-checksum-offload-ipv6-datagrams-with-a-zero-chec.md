# 302. With UDP RX checksum offload, IPv6 datagrams with a zero checksum are accepted

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/udp.rs:994](../src/udp.rs#L994), [src/wire/udp.rs:104](../src/wire/udp.rs#L104) |
| Features | default, device with `checksum.udp.rx = true` |
| Verification | reproduced with a test |

## Summary
With `checksum_caps().udp.rx` set, `process_udp` skips `verify_checksum` entirely. The IPv6 zero-checksum rule lives only inside `verify_checksum`. An IPv6 UDP datagram with checksum 0 is delivered unless the MAC drops it itself, which many don't.

## Details
src/udp.rs:994:
```rust
if !self.ifaces.get(iface.index()).checksum_caps().udp.rx && !udp_packet.verify_checksum(&src_addr, &dst_addr) {
```
src/wire/udp.rs:104:
```rust
if self.checksum() == 0 {
    return matches!(src_addr, IpAddr::V4(_));
```

## Failure scenario
A MAC with UDP RX offload gets an IPv6 UDP datagram with checksum field 0 (corrupted or crafted). The stack queues it on the socket.

## RFC reference
RFC 8200 §8.1: "IPv6 receivers must discard UDP packets containing a zero checksum and should log the error."

## Reproduction
`udp.rs` test harness, scratch copy:
```rust
#[test] fn vfy_udp9_zero_csum_offload() {
    let mut caps = ChecksumCapabilities::default();
    caps.udp = ChecksumOffload { rx: true, tx: false };
    let (mut stack, rx, _tx) = test_stack_with_checksum(Medium::Ip, caps);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(1000, ListenSocketAddr::UNSPECIFIED).unwrap();
    let mut d = udp_datagram(REMOTE_V6.into(), 53, OUR_V6.into(), 1000, b"x");
    d[6] = 0; d[7] = 0;
    inject(&mut stack, &rx, ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Udp, &d));
    println!("offload zero csum v6 delivered: {}", stack.udp_socket(h).can_recv());
}
```
Output: `offload zero csum v6 delivered: true`

## Suggested fix
Drop IPv6 UDP with `checksum() == 0` in `process_udp` regardless of the offload flag. One compare.
