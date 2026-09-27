# 197. IPv6 raw protocol filter compares different next-header fields on send and on receive

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/raw.rs:236](../src/raw.rs#L236), [src/raw.rs:591](../src/raw.rs#L591), [src/stack.rs:1723](../src/stack.rs#L1723), [src/stack.rs:2670](../src/stack.rs#L2670), [src/fragmentation.rs:282](../src/fragmentation.rs#L282) |
| Features | raw-ip, ipv6 (DF part: raw-ip, ipv4, ipv4-fragmentation) |
| Verification | reproduced with a test |

## Summary
On receive, the `protocol` filter matches the header after any Hop-by-Hop header. On send, it is compared with the fixed header's Next Header. A socket bound to ICMPv6 receives MLD reports but cannot send one (`Malformed`). A socket bound to protocol 0 can send HbH packets but never receives any. Separately, raw IPv4 packets with DF set are fragmented instead of refused.

## Details
src/raw.rs:236
```rust
Some((packet.dst_addr().into(), packet.next_header()))
```
src/raw.rs:591
```rust
if version.is_some_and(|v| v != dst_addr.version()) || protocol.is_some_and(|p| p != next_header) {
```
Ingress (src/stack.rs:1723-1756) walks the HbH header and passes the inner next header to `process_raw_ip`. The `RawMode::Ip::protocol` doc says the same protocol governs send and receive.

DF: `transmit_ip` (src/stack.rs:2670) fragments any IPv4 packet over `ip_mtu()` without checking DF, and `fragment_ipv4` clears it (src/fragmentation.rs:282, `packet.set_dont_frag(false)`). Reachable when the device MTU is below the buffer size.

## Failure scenario
- An app implementing MLD binds `RawMode::Ip { version: Some(V6), protocol: Some(Icmpv6) }`. It receives queries fine. Sending an MLDv2 report, which must carry a HbH Router Alert, returns `Malformed`.
- A PMTU probe sends a 1400-byte DF packet over a 1280-MTU interface. It goes out fragmented.

## Reproduction
Added to `src/stack.rs` `mod test` in a scratch copy:
```rust
#[test]
fn vv_raw7_icmpv6_with_hbh_send() {
    let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
    let h = stack.add_raw_socket().unwrap();
    stack.raw_socket(h).bind(RawMode::Ip { version: Some(IpVersion::V6), protocol: Some(IpProtocol::Icmpv6) }).unwrap();
    let mut payload = vec![58u8, 0, 5, 2, 0, 0, 1, 0];
    payload.extend_from_slice(&[143, 0, 0, 0, 0, 0, 0, 0]);
    let pkt = ipv6_packet(OUR_V6, REMOTE_V6, IpProtocol::HopByHop, &payload);
    let r = stack.raw_socket(h).send_slice(&pkt);
    println!("raw7 result {:?}", r);
    assert!(r.is_ok());
}
```
`cargo test --lib vv_ -- --nocapture`:
```
raw7 result Err(Malformed) ... assertion failed: r.is_ok()
```

## Suggested fix
On send, skip a leading HbH header before comparing, as ingress does. For DF, return an error instead of fragmenting a raw IPv4 packet with DF set.
