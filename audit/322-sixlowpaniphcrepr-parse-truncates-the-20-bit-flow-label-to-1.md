# 322. SixlowpanIphcRepr::parse truncates the 20-bit flow label to 16 bits and returns ECN unshifted

| | |
|---|---|
| Severity | low |
| Category | wire-correctness |
| Location | [src/wire/sixlowpan/iphc.rs:209](../src/wire/sixlowpan/iphc.rs#L209), [src/wire/sixlowpan/iphc.rs:216](../src/wire/sixlowpan/iphc.rs#L216), [src/wire/sixlowpan/iphc.rs:58](../src/wire/sixlowpan/iphc.rs#L58) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
For TF=00 and TF=01 the inline flow label is 20 bits. The public field is `flow_label: Option<u16>`, and `parse` reads only the last two inline bytes, dropping the top nibble. `ecn` is returned as `b[0] & 0b1100_0000` instead of 0..=3. `ecn`, `dscp` and `flow_label` have no docs. The stack's compressor and decompressor don't use these fields, so only users of the public repr (loggers, sniffers) are affected.

## Details
src/wire/sixlowpan/iphc.rs:205-217:
```rust
// TF=00
(Some(b[0] & 0b1100_0000), Some(b[0] & 0b11_1111), Some(u16::from_be_bytes([b[2], b[3]])))
// TF=01
(Some(b[0] & 0b1100_0000), None, Some(u16::from_be_bytes([b[1], b[2]])))
```
The high nibble of the flow label is the low nibble of `b[1]` (TF=00) or `b[0]` (TF=01).

## Failure scenario
TF=01 with inline bytes `0x0A 0xBC 0xDE` (ECN 0, flow label 0xABCDE) parses as `flow_label = Some(0xBCDE)`. With ECN=CE the result is `ecn = Some(0xC0)` rather than 3.

## RFC reference
RFC 6282 §3.1.1:
> 00: ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
> 01: ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.
> 10: ECN + DSCP (1 byte), Flow Label is elided.

§3.2.1 Figure 4: `|ECN|   DSCP    |  rsv  |             Flow Label                |` (flow label bits 12-31). Figure 5: `|ECN|rsv|             Flow Label                |` (bits 4-23).

## Suggested fix
Make `flow_label` an `Option<u32>` with all 20 bits, shift ECN down to 0..=3, and document the units of all three fields.
