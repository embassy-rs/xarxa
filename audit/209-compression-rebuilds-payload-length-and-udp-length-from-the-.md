# 209. Compression rebuilds Payload Length and UDP Length from the buffer size, so raw IP packets with trailing bytes change meaning

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/sixlowpan.rs:436](../src/sixlowpan.rs#L436), [src/raw.rs:223](../src/raw.rs#L223) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`ipv6_to_sixlowpan` compresses and sends every byte in the buffer. It only checks that the buffer holds at least 40 + Payload Length, and that UDP Length is at most the rest. The receiver infers both lengths from the frame. A raw IP packet with trailing bytes, or with a UDP Length shorter than its IP payload, arrives as a different packet with a bad checksum.

## Details
src/sixlowpan.rs:436
```rust
let packet = Ipv6Packet::new_checked(buf)?;
```
`new_checked` allows `buf.len() > total_len()`, and `UdpPacket::new_checked` allows UDP Length below the buffer length. There is no truncate to 40 + Payload Length. Raw IP sends (`parse_ip_headers`, src/raw.rs:223) accept such packets. On Ethernet the extra bytes are harmless padding.

## Failure scenario
A raw IP socket sends an ICMPv6 echo with Payload Length 8 and 2 trailing bytes on an 802.15.4 interface. `send_slice` returns Ok. The receiver rebuilds Payload Length 10 and the ICMPv6 checksum fails.

## RFC reference
RFC 6282 §3.2: "The IPv6 Payload Length field MUST always be elided and inferred from lower layers". §4.3.3: "The UDP Length field MUST always be elided and is inferred from lower layers".

## Reproduction
Test in the `sixlowpan` module test harness:
```rust
#[test]
fn vfy_trailing_bytes_change_payload_len() {
    let (mut stack, _iface, _rx, tx, _room, _udp) = reassembly_stack();
    let raw = stack.add_raw_socket().unwrap();
    stack.raw_socket(raw).bind(crate::raw::RawMode::Ip { version: None, protocol: None }).unwrap();
    let icmp = icmpv6_echo_bytes(); // 8-byte echo request, checksum filled
    let mut packet = ipv6_packet(OUR_LINK_LOCAL, PEER_LINK_LOCAL, IpProtocol::Icmpv6, &icmp);
    packet.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(stack.raw_socket(raw).send_slice(&packet), Ok(()));
    let mut out = ipv6_of_frame(&tx.borrow()[0]);
    let ip = Ipv6Packet::new_checked(&mut out[..]).unwrap();
    assert_eq!(ip.payload_len(), 8);
}
```
Output: `sent payload_len 8, received payload_len 10`, assertion `left: 10 right: 8`.

## Suggested fix
Truncate the buffer to 40 + Payload Length in `ipv6_to_sixlowpan`. Compress UDP only when UDP Length equals the rest of the IP payload, and send the UDP header inline otherwise.
