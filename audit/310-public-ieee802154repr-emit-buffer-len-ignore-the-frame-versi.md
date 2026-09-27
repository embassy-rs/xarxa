# 310. Ieee802154Repr::emit and buffer_len ignore PAN presence rules, so emit then parse does not round-trip

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ieee802154.rs:418](../src/wire/ieee802154.rs#L418), [src/wire/ieee802154.rs:461](../src/wire/ieee802154.rs#L461) |
| Features | medium-ieee802154 |
| Verification | reproduced with a test |

## Summary
`buffer_len` and `emit` always write a destination PAN, and write a source PAN whenever `pan_id_compression` is false. They never consult `addr_present_flags`, which `parse` uses. `security_enabled` sets the bit but no auxiliary security header is written. The public doc does not state the supported subset. The stack's own use (2003, both addresses, compression on) is unaffected.

## Details
src/wire/ieee802154.rs:418 computes `3 + 2 + dst + if !self.pan_id_compression { 2 } else { 0 } + src`. `emit` writes `buf[3..5]` unconditionally (line 461) and a source PAN when compression is off. Mismatching cases:
- 2015, compression off, ext/ext: emit writes both PANs, parse expects only the destination PAN.
- 2006, dst Short, src None, compression off: emit writes 2 extra bytes that parse does not consume.
- `security_enabled: true`: parse reads payload bytes as a security control field.

## Reproduction
Test module of src/wire/ieee802154.rs, scratch copy:
```rust
#[test]
fn zz_emit_roundtrip() {
    let repr = Repr { frame_type: FrameType::Data, security_enabled: false, frame_pending: false, ack_request: false,
        sequence_number: Some(1), pan_id_compression: false, frame_version: FrameVersion::Ieee802154_2006,
        dst_pan_id: Some(Pan(0xabcd)), dst_addr: Some(Address::Short([1,2])), src_pan_id: None, src_addr: None };
    let mut b = [0u8; 32];
    let n = repr.buffer_len();
    repr.emit(&mut b);
    let (_r2, l2) = Repr::parse(&b[..n+4]).unwrap();
    assert_eq!(n, l2);
}
```
Output: `left: 9, right: 7`.

## Suggested fix
Drive `buffer_len`/`emit` from `addr_present_flags`, and reject or emit security. Otherwise document the subset: 2003/2006, both addresses, no security.
