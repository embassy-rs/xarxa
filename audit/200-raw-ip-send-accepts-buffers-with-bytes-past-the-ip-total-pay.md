# 200. Raw IP send transmits bytes past the IP total length, and fragments them as payload

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/raw.rs:588](../src/raw.rs#L588), [src/wire/ipv4.rs:263](../src/wire/ipv4.rs#L263), [src/wire/ipv6.rs:385](../src/wire/ipv6.rs#L385), [src/stack.rs:2668](../src/stack.rs#L2668), [src/fragmentation.rs:208](../src/fragmentation.rs#L208) |
| Features | raw-ip |
| Verification | reproduced with a test |

## Summary
A raw IP-mode send accepts a buffer longer than the IPv4 Total Length or the IPv6 header plus Payload Length. The buffer is never trimmed. The extra bytes go on the wire. If the buffer is over the MTU but the datagram is not, the datagram is fragmented with the trailing bytes included as payload.

## Details
`check_len` only rejects buffers that are too short.

src/wire/ipv4.rs:263
```rust
} else if len < self.total_len() as usize {
```

src/wire/ipv6.rs:385
```rust
if len < field::DST_ADDR.end || len < self.total_len() {
```

`send_with_meta` (src/raw.rs:588-612) validates with `parse_ip_headers` and passes the untrimmed `buf` to `transmit_raw_ip`. The MTU decision uses the buffer length.

src/stack.rs:2668
```rust
let total_ip_len = buf.len();
```

`fragment_ipv4` sets `frag.packet_len = total_ip_len` (src/fragmentation.rs:208). Over 6LoWPAN the compressor elides the IPv6 payload length, so the receiver takes the trailing bytes as payload.

## Failure scenario
An application reuses a 1500-byte scratch buffer and passes the whole slice to `send_slice`, relying on the IP length field (Linux trims IP_HDRINCL sends to tot_len). A 1000-byte datagram on an MTU 1200 link goes out as two fragments carrying 1475 payload bytes instead of 980. `send` returns `Ok`. The extra bytes are the caller's own, not stack memory.

## Reproduction
Test in the stack test harness (scratch copy):
```rust
#[test]
fn vv_raw6_trailing_bytes_fragmented() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ip, 1200);
    let h = stack.add_raw_socket().unwrap();
    stack.raw_socket(h).bind(RawMode::Ip { version: None, protocol: None }).unwrap();
    let mut pkt = ipv4_packet(OUR_V4, REMOTE_V4, IpProtocol(253), &[0xaa; 980]);
    assert_eq!(pkt.len(), 1000);
    pkt.resize(1495, 0xee);
    stack.raw_socket(h).send_slice(&pkt).unwrap();
    stack.poll(Instant::from_secs(0));
    let lens: Vec<usize> = tx.borrow().iter().map(|f| f.len()).collect();
    println!("raw6 frames: {:?}", lens);
    assert_eq!(lens, vec![1000]);
}
```
Output:
```
raw6 frames: [1196, 319]
assertion `left == right` failed
```

## Suggested fix
In the IP-mode branch, after validation, truncate the buffer to the IP length (IPv4 total_len, IPv6 40 + payload_len), as ingress does for padding. Or reject a mismatch as `Malformed`.
