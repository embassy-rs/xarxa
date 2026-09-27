# 307. Ieee802154Address::is_unicast returns true for Absent

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/wire/ieee802154.rs:103](../src/wire/ieee802154.rs#L103), [src/neighbor.rs:362](../src/neighbor.rs#L362), [src/wire/ieee802154.rs:461](../src/wire/ieee802154.rs#L461) |
| Features | medium-ieee802154 |
| Verification | confirmed against the code |

## Summary
`is_unicast` is `!self.is_broadcast()`, so `Address::Absent` counts as unicast. `HardwareAddress::is_unicast` forwards to it. The public `NeighborCache::insert` accepts an absent 802.15.4 address, and egress then emits malformed frames.

## Details
src/wire/ieee802154.rs:103:
```rust
pub fn is_unicast(&self) -> bool {
    !self.is_broadcast()
}
```
src/neighbor.rs:362:
```rust
if !addr.is_unicast() || !hardware_addr.is_unicast() {
    return Err(NotUnicast);
}
```
With `dst_addr: Some(Absent)`, `Repr::emit` sets dst mode Absent in frame control (line 442) but still writes the dst PAN at `buf[3..5]` (line 461).

## Failure scenario
`NeighborCache::insert(iface, fe80::1, HardwareAddress::Ieee802154(Ieee802154Address::Absent), ..)` succeeds. Every packet to fe80::1 goes out as a malformed frame. Only reachable through the public API; no network path stores Absent.

## Suggested fix
`matches!(self, Short(_) | Extended(_)) && !self.is_broadcast()`.
