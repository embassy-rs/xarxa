# 308. 802.15.4 PAN ID presence wrong for 2015 src-only compressed frames and 2003/2006 address-less frames

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/wire/ieee802154.rs:243](../src/wire/ieee802154.rs#L243), [src/wire/ieee802154.rs:230](../src/wire/ieee802154.rs#L230), [src/sixlowpan.rs:156](../src/sixlowpan.rs#L156) |
| Features | medium-ieee802154 |
| Verification | plausible, not demonstrated |

## Summary
For frame version 2015, dst absent + src present + PAN ID compression=1 is parsed as carrying a source PAN. For 2003/2006, dst absent + src absent is parsed as carrying a source PAN. Both shift the rest of the header by 2 bytes. The parser behavior is reproduced. That it is wrong rests on IEEE 802.15.4-2006/2015 text, which is not in rfcs/ and was not checked locally.

## Details
src/wire/ieee802154.rs:242-243 give the same result regardless of compression:
```rust
(ABSENT, src, false) if src != ABSENT => (false, ABSENT, true, src),
(ABSENT, src, true) if src != ABSENT => (false, ABSENT, true, src),
```
Table 7-2 of 802.15.4-2015 (as implemented by Contiki-NG `frame802154_has_panid`) has no PAN fields for the compression=1 row. src/wire/ieee802154.rs:230 for 2003/2006:
```rust
(ABSENT, src) => Some((false, ABSENT, true, src)),
```
also matches `src == ABSENT`.

Related: with a PAN set, 2015 ext/ext frames with compression=1 have `dst_pan_id == None` and fail the `dst_pan_id != pan_id` check at src/sixlowpan.rs:156, so they are dropped.

## Failure scenario
A 2015 frame to the PAN coordinator (dst absent, src extended, compression=1) arrives. Two address bytes are read as a PAN, the source address is wrong, and the 6LoWPAN payload starts 2 bytes late. These frame shapes are uncommon on 6LoWPAN links.

## RFC reference
Not in rfcs/. As cited by the finder, IEEE 802.15.4-2006 §7.2.1.5: "This field shall be included in the MAC frame only if the Source Addressing Mode and PAN ID Compression subfields of the Frame Control field are nonzero and equal to zero, respectively." §7.2.1.1.5: "If neither address is present, this subfield shall be set to zero, and the frame shall not contain either PAN identifier field."

## Reproduction
Test module of src/wire/ieee802154.rs, scratch copy:
```rust
#[test]
fn vfy_2015_src_only_pidc() {
    let f = [0x41u8, 0xe0, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb];
    let (repr, len) = Ieee802154Repr::parse(&f).unwrap();
    let g = [0x01u8, 0x00, 0x01, 0x34, 0x12, 0xaa];
    println!("{:?}", Ieee802154Repr::parse(&g));
    assert_eq!(len, 11);
}
```
Output: the 2003 absent/absent frame parses with `src_pan_id: Some(Pan(4660))`, header length 5. The 2015 frame fails with `left: 13, right: 11`.

## Suggested fix
2015: `(ABSENT, src, true) => (false, ABSENT, false, src)`. 2003/2006: no PANs, or `Malformed`, for absent/absent.
