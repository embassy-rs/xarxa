# 324. NHC extension headers with EID 4, 5, 6 or 7 decompress as Hop-by-Hop

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/wire/sixlowpan/nhc.rs:62](../src/wire/sixlowpan/nhc.rs#L62), [src/sixlowpan.rs:266](../src/sixlowpan.rs#L266), [src/sixlowpan.rs:402](../src/sixlowpan.rs#L402) |
| Features | default (`medium-ieee802154`) |
| Verification | reproduced with a test |

## Summary
`From<ExtHeaderId> for IpProtocol` maps Mobility (EID 4), Reserved (5/6) and IPv6 Header (7) to protocol 0. The decompressor then writes an IPv6 packet whose next header says Hop-by-Hop, built from the NHC's length and data bytes. For EID 7 those bytes are really an inner IPHC header. `process_ipv6` walks the fabricated HBH header and may emit an ICMPv6 Parameter Problem. Mobility should decompress to 135, and EID 5/6/7 should be rejected (or 7 decoded as nested IPHC).

## Details
src/wire/sixlowpan/nhc.rs:62-64:
```rust
ExtHeaderId::MobilityHeader => Self::from(0),
ExtHeaderId::Header => Self::from(0),
ExtHeaderId::Reserved => Self::from(0),
```
`ExtHeaderRepr::parse` (nhc.rs:106-114) accepts EID 4..7. The parse loop in `sixlowpan_to_ipv6` (src/sixlowpan.rs:266-283) and `decompress_next_header` (src/sixlowpan.rs:402-413) treat them as length-prefixed extension headers with that mapping.

## Failure scenario
IPHC + NHC `0xe8` or `0xee` with inline NH 17, length 2, data `aa bb` decompresses to next header 0 and an HBH header `11 00 aa bb 01 02 00 00`. Option type 0xaa has high bits 10, so the stack drops the packet and sends a Parameter Problem.

## RFC reference
RFC 6282 §4.2:
> 4: IPv6 Mobility Header [RFC6275]
> 5: Reserved
> 6: Reserved
> 7: IPv6 Header

> When the identified next header is an IPv6 Header (EID=7), the NH bit of the LOWPAN_NHC encoding is unused and MUST be set to zero. The following bytes MUST be encoded using LOWPAN_IPHC as defined in Section 3.

## Reproduction
Added to `src/sixlowpan.rs` in a scratch copy:
```rust
#[cfg(test)]
mod vtest {
    use super::*;
    #[test]
    fn vtest_nhc_eid() {
        for nhc in [0xe8u8, 0xee] {
            let mut buf = PacketBuf::try_new().unwrap();
            buf.reserve(100);
            let bytes = [0x7f, 0x33, nhc, 17, 2, 0xaa, 0xbb, 1, 2, 3, 4];
            buf.set_len(bytes.len());
            buf[..].copy_from_slice(&bytes);
            let src = Ieee802154Address::Extended([1, 2, 3, 4, 5, 6, 7, 8]);
            let dst = Ieee802154Address::Extended([1, 2, 3, 4, 5, 6, 7, 9]);
            let r = sixlowpan_to_ipv6(&mut buf, Some(src), Some(dst), &[], None);
            println!("nhc {nhc:#x}: {:?} {:02x?}", r, &buf[..]);
        }
    }
}
```
`cargo test --lib vtest -- --nocapture`:
```
nhc 0xe8: Ok(()) [60, 00, 00, 00, 00, 0c, 00, ff, fe, 80, ..., 11, 00, aa, bb, 01, 02, 00, 00, 01, 02, 03, 04]
nhc 0xee: Ok(()) [60, 00, 00, 00, 00, 0c, 00, ff, ..., 11, 00, aa, bb, 01, 02, 00, 00, 01, 02, 03, 04]
```
Byte 6 (next header) is 00 in both.

## Suggested fix
Map `MobilityHeader` to 135. Return `Malformed` for `Reserved` and `Header`, or implement nested IPHC for EID 7. The compressor side was not checked.
