# 309. 802.15.4-2015 sequence number suppression and IE Present bits are ignored

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/wire/ieee802154.rs:353](../src/wire/ieee802154.rs#L353), [src/wire/ieee802154.rs:364](../src/wire/ieee802154.rs#L364), [src/sixlowpan.rs:156](../src/sixlowpan.rs#L156) |
| Features | medium-ieee802154 |
| Verification | reproduced with a test |

## Summary
`Repr::parse` accepts frame version 2015 but ignores frame control bit 8 (Sequence Number Suppression) and bit 9 (IE Present). A frame with a suppressed sequence number parses as `Ok` with every field shifted by one byte. Header IEs are handed to the 6LoWPAN dispatcher as payload. Only ingress is affected; the emitter uses 2003 frames.

## Details
The frame control decode (src/wire/ieee802154.rs:309-317) reads bits 0-6 and 10-15 only. Data frames always take the sequence number from `buf[2]` (line 353), and addressing starts at `let mut offset = 3;` (line 364). No code skips IEs, so `process_ieee802154` pulls too short a header.

Separate but related: 2015 ext/ext frames with compression=1 carry no PAN, so `dst_pan_id` is `None` and src/sixlowpan.rs:156 drops them when the interface has a PAN id configured.

## Failure scenario
A TSCH/6TiSCH neighbor sends 2015 data frames with header IEs or a suppressed sequence number. xarxa reads wrong PAN and link-layer addresses and dispatches IE bytes as 6LoWPAN. Usually dropped as `Malformed`, but a wrong `ll_src` could in principle be used for IID reconstruction or the neighbor refresh.

## RFC reference
IEEE 802.15.4-2015 Figure 7-2 (bit 8 Sequence Number Suppression, bit 9 IE Present). Not in rfcs/, not checked locally.

## Reproduction
Test module of src/wire/ieee802154.rs, scratch copy, `cargo test --lib zz_ -- --nocapture`:
```rust
#[test]
fn zz_seq_suppressed() {
    let fc: u16 = 0b001 | (1<<6) | (1<<8) | (0b10<<10) | (0b10<<12) | (0b11<<14);
    let mut f = fc.to_le_bytes().to_vec();
    f.extend_from_slice(&[0xcd, 0xab, 0xff, 0xff, 1,2,3,4,5,6,7,8, 0x41]);
    let (repr, len) = Repr::parse(&f).unwrap();
    assert_eq!(repr.dst_pan_id, Some(Pan(0xabcd)), "len {}", len);
}
```
Output: `assertion left == right failed: len 15, left: Some(Pan(65451)), right: Some(Pan(43981))`. Correct header length is 14.

## Suggested fix
For version 2015, honour bit 8. Skip IEs when bit 9 is set, or return `Malformed`. Document the supported subset on `Repr::parse`.
