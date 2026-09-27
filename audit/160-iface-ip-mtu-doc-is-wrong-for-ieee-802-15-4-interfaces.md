# 160. Iface::ip_mtu doc is wrong for IEEE 802.15.4 interfaces

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:317](../src/iface/mod.rs#L317), [src/iface/mod.rs:735](../src/iface/mod.rs#L735), [src/sixlowpan.rs:38](../src/sixlowpan.rs#L38) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The doc says the IP MTU is "the device MTU minus the link-layer header". That is only true for Ethernet and IP. On 802.15.4 with `sixlowpan-fragmentation` (default) it is always 1280. Without it, it is the frame MTU plus 40 minus the worst-case MAC and IPHC header lengths.

## Details
src/iface/mod.rs:317:
```rust
/// The interface's IP-layer MTU: the device MTU minus the link-layer header,
/// clamped to what a [`PacketBuf`](crate::driver::PacketBuf) can carry.
```
src/iface/mod.rs:735:
```rust
Medium::Ieee802154 => crate::sixlowpan::ip_mtu(caps.max_transmission_unit),
```
src/sixlowpan.rs:38:
```rust
#[cfg(feature = "sixlowpan-fragmentation")]
{ let _ = link_mtu; IPV6_MIN_MTU }
#[cfg(not(feature = "sixlowpan-fragmentation"))]
{ (link_mtu + IPV6_HEADER_LEN).saturating_sub(IEEE802154_MAX_HEADER_LEN + IPHC_MAX_EMITTED_LEN) }
```
The 1280 value is intended (DESIGN.md §6). The doc is what is wrong.

## Suggested fix
Document the 802.15.4 cases: 1280 with `sixlowpan-fragmentation`, otherwise what fits in one frame after worst-case compression.
