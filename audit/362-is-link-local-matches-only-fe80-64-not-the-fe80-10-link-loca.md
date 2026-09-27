# 362. `is_link_local` matches only fe80::/64, not the fe80::/10 link-local range

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/wire/ipv6.rs:140](../src/wire/ipv6.rs#L140), [src/stack.rs:404](../src/stack.rs#L404), [src/stack.rs:1896](../src/stack.rs#L1896), [src/iface/mod.rs:1011](../src/iface/mod.rs#L1011) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The pub(crate) `Ipv6AddrExt::is_link_local` requires the first 64 bits to be exactly fe80:0:0:0. An address in fe80::/10 outside that /64 is not treated as link-local and gets scope Unknown. Conforming peers are always in fe80::/64 (RFC 4291 §2.5.6), so only a non-conforming peer triggers this. The same file defines `LINK_LOCAL_PREFIX` as /10, so the two definitions disagree.

## Details
src/wire/ipv6.rs:140:
```rust
fn is_link_local(&self) -> bool {
    self.octets()[0..8] == [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}
```
Callers that make scope decisions with it:
- src/stack.rs:404, `route_reply` pinning replies to the arrival interface.
- src/stack.rs:1896 (and the report arm after it), MLD reception checks.
- src/iface/mod.rs:1011, RFC 6724 candidate filtering.
- slaac.rs and `link_local_ipv6_address` (iface/mod.rs:993).

The exact /64 test is correct for 6LoWPAN IPHC stateless compression (wire/sixlowpan/iphc.rs:119, :151), so it cannot just be widened.

## Failure scenario
A peer uses source fe80:0:0:1::5. A reply to it is not pinned to the arrival interface, goes through the routing table, and can leave the wrong interface or be dropped. An MLD query from it is ignored.

## RFC reference
RFC 4291 §2.4: "Link-Local unicast   1111111010           FE80::/10       2.5.6"

## Reproduction
Added to src/wire/ipv6.rs in a scratch copy, run with `cargo test --lib vtest -- --nocapture`:
```rust
#[cfg(test)] mod vtest { use super::*; #[test] fn vtest_ll() {
    let a = Address::new(0xfe80,0,0,1,0,0,0,5);
    println!("fe80:0:0:1::5 ll={} scope={:?}", a.is_link_local(), a.x_multicast_scope());
} }
```
Output: `fe80:0:0:1::5 ll=false scope=Unknown`

## Suggested fix
Use fe80::/10 for scope decisions. Keep the exact fe80::/64 check as a separate predicate for IPHC compression.
