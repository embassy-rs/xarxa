# 208. Valid IPHC/NHC encodings longer than the uncompressed headers are rejected

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/sixlowpan.rs:315](../src/sixlowpan.rs#L315) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`sixlowpan_to_ipv6` returns `Malformed` when the compressed header chain is longer than the uncompressed one. The comment says this can't happen, but IPHC can be 41 bytes (`MAX_HEADER_LEN` in iphc.rs), one more than the IPv6 header. Compressed extension headers with an inline next header can also be longer than their IPv6 form. Legal packets are dropped.

## Details
src/sixlowpan.rs:312
```rust
// Make room. The uncompressed chain is always longer: the IPHC header
// alone frees at least 38 bytes, and a compressed extension header is at
// most 1 byte shorter than its IPv6 form.
let grow = uncompressed_len.checked_sub(compressed_len).ok_or(Malformed)?;
```
IPHC with CID=1, TF=00, NH inline, HLIM inline, SAM=00, DAM=00 is 2+1+4+1+1+16+16 = 41 bytes. The in-place write pass assumes `grow >= 0`.

## Failure scenario
A peer has a context configured, so it sets CID, but carries both addresses in full with TF and HLIM inline. xarxa drops the packet.

## RFC reference
RFC 6282 §2: "A compliant implementation of [RFC4944] as updated by this document MUST be able to properly process a packet received that makes use of the provisions of this document."

## Reproduction
Test in the `sixlowpan` module test harness:
```rust
#[test]
fn vfy_iphc_41_bytes() {
    let body = |cid: bool| {
        let mut c = vec![0x60, if cid { 0x80 } else { 0x00 }];
        if cid { c.push(0x00); }
        c.extend_from_slice(&[0, 0, 0, 0]);
        c.push(58); c.push(64);
        c.extend_from_slice(&PEER_LINK_LOCAL.octets());
        c.extend_from_slice(&OUR_LINK_LOCAL.octets());
        c.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
        c
    };
    let r40 = decompress(&body(false), PEER_LL, OUR_LL, &[], 64, None);
    let r41 = decompress(&body(true), PEER_LL, OUR_LL, &[], 64, None);
    assert!(r40.is_ok());
    assert!(r41.is_ok(), "41-byte IPHC rejected");
}
```
Output: `40: Ok(48) 41: Err(Malformed)`, panicked: `41-byte IPHC rejected`.

## Suggested fix
Handle a negative grow: write the uncompressed chain, then pull the front (or move the payload forward). Fix the comment.
