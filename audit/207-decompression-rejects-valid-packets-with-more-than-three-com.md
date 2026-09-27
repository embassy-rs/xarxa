# 207. 6LoWPAN decompression rejects packets with more than three compressed extension headers

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/sixlowpan.rs:276](../src/sixlowpan.rs#L276), [src/sixlowpan.rs:30](../src/sixlowpan.rs#L30) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`sixlowpan_to_ipv6` returns `Malformed` on a fourth NHC extension header. RFC 8200 allows chains like HBH, DestOpts, Routing, DestOpts, and RFC 6282 lets a peer compress all of them. xarxa drops such packets. They are rare in practice.

## Details
src/sixlowpan.rs:30
```rust
const MAX_NHC_EXT_HEADERS: usize = 3;
```
src/sixlowpan.rs:276-278
```rust
if n_ext == MAX_NHC_EXT_HEADERS {
    return Err(Malformed);
}
```
The compressor handles the limit by carrying the rest inline (line 457), but the decompressor cannot accept another implementation's fully compressed chain.

## Failure scenario
A peer sends HBH + DestOpts + Routing (RPL source route) + DestOpts, all NHC-compressed. xarxa drops it as `Malformed`.

## RFC reference
RFC 8200 §4.1: "Each extension header should occur at most once, except for the Destination Options header, which should occur at most twice (once before a Routing header and once before the upper-layer header)."

RFC 6282 §2: "A compliant implementation of [RFC4944] as updated by this document MUST be able to properly process a packet received that makes use of the provisions of this document."

## Reproduction
Added to the `src/sixlowpan.rs` test module (scratch copy):
```rust
#[test]
fn vfy_four_nhc_ext_headers() {
    let mut c = vec![0x7f, 0x33];
    c.extend_from_slice(&[0xe1, 6, 1, 4, 0, 0, 0, 0]);
    c.extend_from_slice(&[0xe7, 6, 1, 4, 0, 0, 0, 0]);
    c.extend_from_slice(&[0xe3, 6, 253, 0, 0, 0, 0, 0]);
    c.extend_from_slice(&[0xe6, 59, 6, 1, 4, 0, 0, 0, 0]);
    let r = decompress(&c, PEER_LL, OUR_LL, &[], 64, None);
    let mut c3 = vec![0x7f, 0x33];
    c3.extend_from_slice(&[0xe1, 6, 1, 4, 0, 0, 0, 0]);
    c3.extend_from_slice(&[0xe7, 6, 1, 4, 0, 0, 0, 0]);
    c3.extend_from_slice(&[0xe2, 59, 6, 253, 0, 0, 0, 0, 0]);
    let r3 = decompress(&c3, PEER_LL, OUR_LL, &[], 64, None);
    assert!(r3.is_ok());
    assert!(r.is_ok(), "4 compressed ext headers rejected");
}
```
`cargo test --lib vfy_ -- --nocapture` output:
```
4 ext: Err(Malformed)
3 ext: Ok(64)
panicked: 4 compressed ext headers rejected
```

## Suggested fix
Raise the limit to the longest RFC 8200 chain (HBH, DestOpts, Routing, Fragment, DestOpts), or decode the rest without an ExtInfo slot.
