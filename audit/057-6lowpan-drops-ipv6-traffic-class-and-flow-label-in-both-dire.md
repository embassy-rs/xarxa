# 057. 6LoWPAN drops IPv6 Traffic Class and Flow Label in both directions

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/sixlowpan.rs:334](../src/sixlowpan.rs#L334), [src/sixlowpan.rs:509](../src/sixlowpan.rs#L509), [src/wire/sixlowpan/iphc.rs:205](../src/wire/sixlowpan/iphc.rs#L205), [src/wire/sixlowpan/iphc.rs:394](../src/wire/sixlowpan/iphc.rs#L394), [src/wire/sixlowpan/iphc.rs:60](../src/wire/sixlowpan/iphc.rs#L60) |
| Features | default (medium-ieee802154, ipv6) |
| Verification | reproduced with a test |

## Summary

Decompression always writes Traffic Class 0 and Flow Label 0, even when the IPHC header carried them inline and the parser read them. Compression always emits TF=11 ("both elided"), and never reads the packet's values. ECN marks, DSCP and flow labels are lost across every 802.15.4 hop. The stack's own packets use TC=0 and FL=0, so this affects peer traffic and raw IP sockets, and breaks the README promise that raw IP sockets keep all header fields.

## Details

Ingress, src/sixlowpan.rs:334-335, although `iphc_repr.ecn/dscp/flow_label` were parsed:

```rust
ipv6.set_traffic_class(0);
ipv6.set_flow_label(0);
```

Egress, src/sixlowpan.rs:509-511, in `ipv6_to_sixlowpan`:

```rust
ecn: None,
dscp: None,
flow_label: None,
```

src/wire/sixlowpan/iphc.rs:394-395, in `Repr::emit`:

```rust
// The traffic class and flow label are never carried.
iphc |= 0b11 << 11;
```

`emit`'s doc (iphc.rs:385) says TC and FL are always elided, so this is a documented limitation of the wire repr. The bug is that `ipv6_to_sixlowpan` uses it for packets whose TC or FL is non-zero, which misstates the header.

The public repr (`wire::SixlowpanIphcRepr`) has its own problems, iphc.rs:205-220:

```rust
0b00 => {
    let b = take(buf, &mut offset, 4)?;
    (
        Some(b[0] & 0b1100_0000),
        Some(b[0] & 0b11_1111),
        Some(u16::from_be_bytes([b[2], b[3]])),
    )
}
0b01 => {
    let b = take(buf, &mut offset, 3)?;
    (Some(b[0] & 0b1100_0000), None, Some(u16::from_be_bytes([b[1], b[2]])))
}
```

- `flow_label: Option<u16>` (iphc.rs:60) cannot hold the 20-bit field. TF=00 drops the nibble in `b[1] & 0x0f`, TF=01 drops `b[0] & 0x0f`.
- ECN is stored unshifted (values 0, 64, 128, 192).
- DSCP is correct.

README.md:110 on raw sockets: "IP headers are byte-copied instead of parsed+re-emitted, so all fields and options are kept, even those unsupported by _xarxa_."

## Failure scenario

1. A peer marks ECN CE, or sets a DSCP or flow label, and sends with TF other than 11. xarxa hands `process_ipv6` and any raw IP socket a header with TC=0 and FL=0. The congestion signal is lost.
2. An application sends IPv6 with DSCP EF or a flow label through a raw IP socket out an 802.15.4 interface. The frame says TF=11, so every receiver rebuilds TC=0 and FL=0.

## RFC reference

RFC 6282 §3.1.1:

> 00: ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
>
> 11: Traffic Class and Flow Label are elided.

RFC 6282 §3.2.1:

> the Traffic Class field is rotated right by 2 bits in the compressed IPv6 header

## Reproduction

Tests in the `sixlowpan.rs` `mod test` harness, default features:

```rust
#[test]
fn zz_tf_inline_decompress() {
    // IPHC TF=00, NH inline, HLIM=64, SAM=11 DAM=11; inline TF EE 0A BC DE; NH=59
    let payload = [0x62, 0x33, 0xEE, 0x0A, 0xBC, 0xDE, 0x3b];
    let (repr, _) = SixlowpanIphcRepr::parse(&payload, Some(PEER_LL), Some(OUR_LL), &[]).unwrap();
    std::println!("repr ecn={:?} dscp={:?} fl={:x?}", repr.ecn, repr.dscp, repr.flow_label);
    let mut out = decompress(&payload, PEER_LL, OUR_LL, &[], 0, None).unwrap();
    let ip = Ipv6Packet::new_checked(&mut out[..]).unwrap();
    assert_eq!(ip.traffic_class(), 0xbb, "traffic class lost");
}

#[test]
fn zz_tf_roundtrip() {
    let mut packet = ipv6_packet(PEER_LINK_LOCAL, OUR_LINK_LOCAL, IpProtocol(59), &[]);
    {
        let mut ip = Ipv6Packet::new_unchecked(&mut packet[..]);
        ip.set_traffic_class(0xbb);
        ip.set_flow_label(0xabcde);
    }
    let (compressed, _) = compress(&packet, PEER_LL, OUR_LL, 0);
    let mut out = decompress(&compressed, PEER_LL, OUR_LL, &[], 0, None).unwrap();
    let ip = Ipv6Packet::new_checked(&mut out[..]).unwrap();
    assert_eq!((ip.traffic_class(), ip.flow_label()), (0xbb, 0xabcde));
}
```

Output:

```
repr ecn=Some(192) dscp=Some(46) fl=Some(bcde)
tc=0x0 fl=0x0
assertion failed: traffic class lost  left: 0  right: 187

iphc [7a, 33]
tc=0x0 fl=0x0
left: (0, 0)  right: (187, 703710)
```

`0x7a` is IPHC byte 0 with TF=11.

## Suggested fix

- In `ipv6_to_sixlowpan`, read `traffic_class()` and `flow_label()` and pick TF=00/01/10/11 by which parts are non-zero. Teach `Repr::emit` to write the inline forms (ECN|DSCP, pad, 20-bit FL).
- In `sixlowpan_to_ipv6`, write the parsed values back, rotated to `DSCP << 2 | ECN`.
- Make `flow_label` a 20-bit value (`u32`) and store ECN shifted down.
