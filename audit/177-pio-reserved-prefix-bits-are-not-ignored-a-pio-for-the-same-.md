# 177. PIO reserved prefix bits are not ignored, so a duplicate entry's expiry removes a valid SLAAC address

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/slaac.rs:258](../src/iface/slaac.rs#L258), [src/iface/slaac.rs:207](../src/iface/slaac.rs#L207), [src/iface/slaac.rs:219](../src/iface/slaac.rs#L219), [src/iface/slaac.rs:467](../src/iface/slaac.rs#L467) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`process_prefix` builds the cidr without masking the bits after the prefix length. Prefix lookups compare whole `Ipv6Cidr` values. Two PIOs that differ only in reserved bits become two entries that form the same address. When the second one expires, sync removes the address the first, still valid, entry formed.

## Details
src/iface/slaac.rs:258:
```rust
let cidr = Ipv6Cidr::new(prefix.prefix, prefix.prefix_len);
```
`Ipv6Cidr::try_new` (src/wire/ipv6.rs:250) stores the address as given. `add_prefix` and `expire_prefix` match with `.find(|(c, _)| c == cidr)` (lines 207, 219). The address is formed from the first 64 bits only, so both entries form the same address. In `sync_slaac_state` the valid entry refreshes the address, then the expired entry removes it (src/iface/slaac.rs:461-467). `update_slaac_state` then drops the expired entry and clears `sync_required`, so nothing reinstalls the address until the next RA.

The same mismatch lets a withdrawal (valid lifetime 0) with nonzero reserved bits miss the prefix it means. The duplicate also takes one of the `SLAAC_PREFIX_COUNT` slots.

## Failure scenario
RA with 2001:db8::/64 (valid 7200 s) installs 2001:db8::ff:fe00:1. Then an RA with 2001:db8::1/64 (valid 5 s). At t=8 s the address is gone while the 2001:db8::/64 entry is still valid.

## RFC reference
RFC 4861 §4.6.2, Prefix: "The bits in the prefix after the prefix length are reserved and MUST be initialized to zero by the sender and ignored by the receiver."

RFC 4862 §5.5.3 d): "'equal' means the two prefix lengths are the same and the first prefix-length bits of the prefixes are identical"

## Reproduction
In the `slaac` module tests of a scratch copy:
```rust
#[test]
fn vfy_f7_reserved_bits() {
    let mut slaac = Slaac::new(SlaacConfig::default(), Instant::ZERO);
    advertise(&mut slaac, Duration::ZERO, Some(PREFIX), Instant::ZERO);
    let mut p2 = PREFIX; p2.prefix = Ipv6Addr::new(0x2001,0xdb8,0,0,0,0,0,1);
    advertise(&mut slaac, Duration::ZERO, Some(p2), Instant::ZERO);
    assert_eq!(slaac.prefix.len(), 1);
}
```
Output: 2 entries, test fails.

## Suggested fix
Mask the prefix to `prefix_len` before building the cidr, for example with a `network()` helper on `Ipv6Cidr`.
