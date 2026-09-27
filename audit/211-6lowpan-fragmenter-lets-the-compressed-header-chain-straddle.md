# 211. 6LoWPAN fragmenter lets the compressed header chain straddle FRAG1

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/sixlowpan.rs:775](../src/sixlowpan.rs#L775), [src/sixlowpan.rs:449](../src/sixlowpan.rs#L449) |
| Features | sixlowpan-fragmentation |
| Verification | reproduced with a test |

## Summary
Compression ignores fragmentation, and `fragment_sixlowpan` sizes FRAG1 by the MTU alone. If the compressed chain (IPHC + NHC extension headers + UDP NHC) is longer than `frag1_size`, part of it lands in a FRAGN. FRAG1 can't be decompressed, and the FRAGN offsets assume the whole chain was in FRAG1. No receiver can deliver the datagram, xarxa included.

## Details
src/sixlowpan.rs:775
```rust
let frag1_size = (mtu + header_diff)
    .checked_sub(ieee_len + SIXLOWPAN_FIRST_FRAGMENT_HEADER_SIZE)
    .map(|n| n / 8 * 8)
    .and_then(|n| n.checked_sub(header_diff))
    .unwrap_or(0);
```
`ipv6_to_sixlowpan` (src/sixlowpan.rs:449-475) compresses HBH, Routing and Destination Options headers up to 255 bytes regardless. Only raw IP sockets can produce such headers today. A failed FRAG1 also pins a reassembly slot on a xarxa receiver.

## Failure scenario
A raw IPv6 socket sends UDP behind a 160-byte Destination Options header over 802.15.4. `send_slice` returns Ok, 3 frames go out, and the 97 compressed bytes in FRAG1 return `Malformed` when decompressed alone.

## RFC reference
RFC 6282 §2: "When using the fragmentation mechanism described in Section 5.3 of [RFC4944], any header that cannot fit within the first fragment MUST NOT be compressed."

## Reproduction
Test in the `sixlowpan` module test harness:
```rust
#[test]
#[cfg(feature = "sixlowpan-fragmentation")]
fn vfy_big_ext_header_straddles_frag1() {
    let (mut stack, _iface, _rx, tx, _room, _udp) = reassembly_stack();
    let raw = stack.add_raw_socket().unwrap();
    stack.raw_socket(raw).bind(crate::raw::RawMode::Ip { version: None, protocol: None }).unwrap();
    let datagram = udp_datagram(OUR_LINK_LOCAL.into(), 1234, PEER_LINK_LOCAL.into(), 6969, &[0x55; 100]);
    let mut l4 = vec![17u8, 19, 1, 156];
    l4.resize(160, 0);
    l4.extend_from_slice(&datagram);
    let packet = ipv6_packet(OUR_LINK_LOCAL, PEER_LINK_LOCAL, IpProtocol::Ipv6Opts, &l4);
    assert_eq!(stack.raw_socket(raw).send_slice(&packet), Ok(()));
    stack.poll(Instant::ZERO);
    let frames = tx.borrow().clone();
    let (size, _tag, _offsets, compressed) = reassemble_frames(&frames);
    let (_, payload) = parse_frame(&frames[0]);
    let frag = SixlowpanFragRepr::parse(&payload).unwrap();
    let first = &payload[frag.buffer_len()..];
    let r = decompress(first, OUR_LL, PEER_LL, &[], 64, Some(size as usize));
    assert!(r.is_ok(), "first fragment cannot be decompressed");
}
```
Output: `3 frames`, `frag1 97 bytes, whole compressed 269 bytes: Err(Malformed)`, panicked: `first fragment cannot be decompressed`.

## Suggested fix
When fragmenting, check the compressed chain fits in `frag1_size`. If not, stop compressing at the last header that fits, carry the rest uncompressed (NH inline) and recompute `header_diff`. Or drop the packet.
