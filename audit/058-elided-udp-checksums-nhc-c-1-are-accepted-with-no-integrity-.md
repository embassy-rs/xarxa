# 058. Elided UDP checksums (NHC C=1) are accepted with no integrity check, and a computed zero checksum is written as 0

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/sixlowpan.rs:366](../src/sixlowpan.rs#L366), [src/sixlowpan.rs:146](../src/sixlowpan.rs#L146), [src/sixlowpan.rs:1380](../src/sixlowpan.rs#L1380), [src/wire/udp.rs:104](../src/wire/udp.rs#L104), [src/wire/sixlowpan/nhc.rs:185](../src/wire/sixlowpan/nhc.rs#L185) |
| Features | default (medium-ieee802154, ipv6, udp) |
| Verification | reproduced with a test |

## Summary

`sixlowpan_to_ipv6` accepts every unfragmented UDP NHC header with the checksum elided and computes a checksum for it from whatever arrived. RFC 6282 says the decompressor MUST drop such a packet unless it can confirm an additional integrity check. xarxa has none to confirm, since it drops every frame with link-layer security. Separately, a computed checksum of 0 is written as 0 instead of 0xffff, so UDP ingress then drops the datagram the code meant to accept.

## Details

src/sixlowpan.rs:366-390:

```rust
let checksum = match udp.checksum {
    Some(checksum) => checksum,
    // An elided checksum can only be computed over the whole datagram.
    None if total_len.is_some() => {
        debug!("6LoWPAN: elided UDP checksum on a fragmented packet");
        return Err(Malformed);
    }
    None => !checksum::combine(&[
        checksum::pseudo_header_v6(...),
        udp.src_port,
        udp.dst_port,
        udp_len as u16,
        checksum::data(&buf[dest + UDP_HEADER_LEN..]),
    ]),
};
...
udp_packet.set_checksum(checksum);
```

The UDP layer then verifies a checksum that was computed over the same bytes, so it always passes. Corrupted or forged datagrams reach the socket unchecked.

src/sixlowpan.rs:146 drops every frame with `security_enabled`, so no L2 MIC can be present. The existing `test_elided_udp_checksum` (src/sixlowpan.rs:1380) asserts that C=1 datagrams are delivered, so the acceptance is deliberate (inherited from smoltcp).

Second defect. When the one's-complement sum is 0xffff, `!combine(..)` is 0x0000 and is written as-is. `UdpPacket::fill_checksum` maps that to 0xffff (src/wire/udp.rs:160), this path does not. `verify_checksum` rejects a zero checksum on IPv6 (src/wire/udp.rs:104-109). About 1 in 65536 elided-checksum datagrams is dropped.

Minor: the public doc of `SixlowpanUdpNhcRepr::checksum` (src/wire/sixlowpan/nhc.rs:185) says "`None` when it is elided: the receiver must recompute it", and leaves out the drop requirement.

## Failure scenario

- Any node on the PAN sends IPHC + UDP NHC with C=1, or a frame is corrupted in a way the 16-bit FCS misses. The payload or the pseudo-header fields (addresses, ports) can be wrong. xarxa computes a matching checksum and delivers the datagram.
- A legitimate elided-checksum datagram whose computed checksum is 0x0000 is silently dropped by UDP ingress.

## RFC reference

RFC 6282 §4.3.2:

> A decompressor that expands a 6LoWPAN packet with the C bit set MUST compute the UDP Checksum on behalf of the source node and place that value in the restored UDP header as specified in the incumbent standards [RFC0768], [RFC2460]. The decompressor MUST unambiguously determine that an additional integrity check was put in place by the compressor and verify the integrity check ... If the decompressor cannot unambiguously determine the presence of an integrity check or verification fails, the decompressor MUST drop the packet.

"As specified in the incumbent standards" includes the RFC 768 rule that a computed zero is transmitted as all ones.

## Reproduction

Test in the `sixlowpan.rs` `mod test` harness, default features. It searches for a payload whose computed checksum is 0xffff when carried inline, so that `!combine` gives 0 when elided:

```rust
#[test]
fn zz_elided_checksum_zero() {
    let mut found = None;
    for v in 0..=u16::MAX {
        let mut data = b"zero".to_vec();
        data.extend_from_slice(&v.to_be_bytes());
        let mut d = udp_datagram(PEER_LINK_LOCAL.into(), 1234, OUR_LINK_LOCAL.into(), 6969, &data);
        if UdpPacket::new_checked(&mut d[..]).unwrap().checksum() == 0xffff {
            found = Some(data);
            break;
        }
    }
    let data = found.unwrap();
    let (mut stack, _iface, rx, _tx, _room) = test_stack(OUR_LL, Some(PAN));
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(6969, ListenSocketAddr::UNSPECIFIED).unwrap();
    let mut payload = vec![0x7e, 0x33, 0xf4];
    payload.extend_from_slice(&1234u16.to_be_bytes());
    payload.extend_from_slice(&6969u16.to_be_bytes());
    payload.extend_from_slice(&data);
    let mut out = decompress(&payload, PEER_LL, OUR_LL, &[], 0, None).unwrap();
    std::println!("restored udp checksum {:#x}", UdpPacket::new_checked(&mut out[40..]).unwrap().checksum());
    inject(&mut stack, &rx, frame(PEER_LL, OUR_LL, PAN, &payload));
    let r = stack.udp_socket(udp).recv().map(|p| p.to_vec());
    assert!(r.is_ok(), "elided-checksum datagram with computed checksum 0 dropped");
}
```

Output:

```
restored udp checksum 0x0
recv Err(Exhausted)
panicked ... elided-checksum datagram with computed checksum 0 dropped
```

The existing `test_elided_udp_checksum` passes on HEAD, which shows C=1 is accepted.

## Suggested fix

Drop UDP NHC packets with C=1 (return `Malformed`), since no L2 integrity check is supported. Update `test_elided_udp_checksum` and the nhc.rs doc. If elision is ever accepted behind an opt-in, map a computed 0x0000 to 0xffff.
