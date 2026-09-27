# 175. Non-/64 autoconf prefixes use prefix-table slots, and a full table drops new prefixes with no eviction

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/slaac.rs:106](../src/iface/slaac.rs#L106), [src/iface/slaac.rs:202](../src/iface/slaac.rs#L202), [src/iface/slaac.rs:378](../src/iface/slaac.rs#L378), [src/iface/mod.rs:509](../src/iface/mod.rs#L509) |
| Features | slaac without alloc (table-full part); default for the unbounded-growth part |
| Verification | reproduced with a test |

## Summary
`is_valid_prefix_info` accepts any prefix length up to 128. Only /64 prefixes form an address, but the others are still stored. Without `alloc` the table has 2 slots (`SLAAC_PREFIX_COUNT`), and when it is full new prefixes are dropped with a warning and nothing is evicted. With `alloc` the table is unbounded, so any on-link RA source can grow it. The `set_slaac` doc says every advertised prefix becomes an address.

## Details
src/iface/slaac.rs:106:
```rust
self.prefix_len <= 128
```
src/iface/slaac.rs:209-210, in `add_prefix`:
```rust
} else if self.prefix.push((*cidr, prefix_info)).is_err() {
    warn!("slaac: prefix table full (slaac-prefix-count), ignoring a prefix");
```
src/iface/slaac.rs:378, `from_link_prefix` skips the rest:
```rust
if link_prefix.prefix_len() != 64 {
```
src/iface/mod.rs:509-511, `set_slaac`: "Every prefix a router advertises for autoconfiguration becomes an address on the interface".

Without `alloc`, deprecated entries are not evicted either. With `alloc`, prefixes and routes from RAs are stored without bound, with lifetimes up to `Duration::MAX`.

## Failure scenario
No-alloc build, 2 slots. The router advertises fd00::/64, the old 2001:db8:1::/64 (preferred 0, valid 1 day) and the new 2001:db8:2::/64. The new prefix is dropped. The node has only a deprecated global address for up to a day. A misconfigured A=1 /56 takes a slot the same way.

## RFC reference
RFC 4862 §5.5.3 d): "If the sum of the prefix length and interface identifier length does not equal 128 bits, the Prefix Information option MUST be ignored."

## Reproduction
`iface::slaac` module test harness, scratch copy:
```rust
#[test]
fn vfy_f5_non64() {
    let mut slaac = Slaac::new(SlaacConfig::default(), Instant::ZERO);
    let mut p = PREFIX; p.prefix_len = 56;
    advertise(&mut slaac, Duration::ZERO, Some(p), Instant::ZERO);
    let mut p = PREFIX; p.prefix_len = 48; p.prefix = Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0);
    advertise(&mut slaac, Duration::ZERO, Some(p), Instant::ZERO);
    advertise(&mut slaac, Duration::ZERO, Some(PREFIX), Instant::ZERO);
    assert!(slaac.prefix.iter().any(|(c, _)| c.prefix_len() == 64));
}
```
`cargo test --lib --no-default-features --features std,log,async,icmp-ping-reply,icmp-errors,medium-ethernet,medium-ip,ipv4,ipv6,udp,tcp,slaac,multicast vfy_f5`

Output: entries `[2001:db8::/56, 2001:db9::/48]`, test failed. With default features (alloc) it passes with 3 entries.

## Suggested fix
Reject `prefix_len != 64` in `is_valid_prefix_info`. On a full table, evict a deprecated entry or the one with the earliest valid_until in favour of a new preferred prefix. Bound the tables with `alloc` too. Fix the `set_slaac` doc.
