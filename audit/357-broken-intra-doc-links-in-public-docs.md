# 357. Broken intra-doc links in public docs

| | |
|---|---|
| Severity | info |
| Category | doc-mismatch |
| Location | [src/udp.rs:506](../src/udp.rs#L506), [src/udp.rs:676](../src/udp.rs#L676), [src/udp.rs:800](../src/udp.rs#L800), [src/iface/mod.rs:6](../src/iface/mod.rs#L6), [src/iface/mod.rs:8](../src/iface/mod.rs#L8), [src/iface/mod.rs:46](../src/iface/mod.rs#L46), [src/route.rs:108](../src/route.rs#L108), [src/stack.rs:635](../src/stack.rs#L635) |
| Features | default, and reduced builds |
| Verification | reproduced with a test |

## Summary
With default features, `cargo doc` warns about `crate::Iface::join_multicast_group` at src/udp.rs:506. `Iface` lives at `crate::iface::Iface`. Reduced builds also break links to cfg'd-out items.

## Details
src/udp.rs:506:
```rust
/// Multicast groups are not joined automatically, you must call [`Iface::join_multicast_group`](crate::Iface::join_multicast_group) yourself.
```
With `--no-default-features --features medium-ip,ipv4,udp`, links are unresolved at src/iface/mod.rs:6:68, 6:82, 8:61, 46:25 (`dhcpv4`, `slaac`, `dhcpv4_server`, `Stack::add_iface`), src/route.rs:108:7 (`Routes::add_default_ipv6_route`), src/stack.rs:635:41 (`Self::add_iface`), src/udp.rs:676:49 (`take_icmp_error`) and src/udp.rs:800:11 (`Stack::poll_tx_timestamp`).

## Reproduction
```
cargo doc --no-deps
cargo doc --no-deps --no-default-features --features medium-ip,ipv4,udp
```
Default output: `warning: unresolved link to crate::Iface::join_multicast_group --> src/udp.rs:506:102 ... no item named Iface in module xarxa`.

## Suggested fix
Use `crate::iface::Iface::join_multicast_group`. Gate or reword links to optional items.
