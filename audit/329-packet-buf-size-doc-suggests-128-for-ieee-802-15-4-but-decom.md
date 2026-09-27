# 329. PACKET_BUF_SIZE doc suggests 128 for 802.15.4, but full frames don't fit once decompressed

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [xarxa-driver/src/config.rs:65](../xarxa-driver/src/config.rs#L65), [src/sixlowpan.rs:316](../src/sixlowpan.rs#L316), [xarxa-driver/src/buf.rs:307](../xarxa-driver/src/buf.rs#L307) |
| Features | medium-ieee802154 |
| Verification | confirmed against the code |

## Summary
The doc lists 128 as a valid buffer size for 802.15.4 without fragmentation. Decompression grows headers in place, and the grown packet must fit the buffer. A near-full frame from a standard peer then fails `ensure_headroom` and is dropped as `Malformed`, with only a debug log.

## Details
xarxa-driver/src/config.rs:65:
```rust
/// - 128 or 256 for IEEE 802.15.4 without 6LoWPAN fragmentation. 256 leaves
///   room for the headers to grow when they are decompressed.
```
src/sixlowpan.rs:315:
```rust
let grow = uncompressed_len.checked_sub(compressed_len).ok_or(Malformed)?;
if !buf.ensure_headroom(grow) {
    return Err(Malformed);
}
```
xarxa-driver/src/buf.rs:307 fails when `headroom + len > PACKET_BUF_SIZE`.

xarxa's own `sixlowpan::ip_mtu` caps what it sends, so two xarxa nodes interoperate. Other stacks that fill frames do not.

## Failure scenario
Build with `packet-buf-size-128`. A peer sends a 125-byte frame, 9-byte MAC header (short addresses, PAN ID compression), 2-byte IPHC, 4-byte UDP NHC. That is 116 bytes of 6LoWPAN, `grow = 48 - 6 = 42`, so 158 bytes are needed. The frame is dropped.

## Suggested fix
Recommend 256 for 802.15.4, or state the worst-case decompressed size and that 128 drops large compressed frames.
