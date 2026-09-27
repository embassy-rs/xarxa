# 176. Every RA, even an identical refresh, runs config_changed and reprograms the multicast filter

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/iface/slaac.rs:531](../src/iface/slaac.rs#L531), [src/iface/slaac.rs:215](../src/iface/slaac.rs#L215), [src/iface/slaac.rs:241](../src/iface/slaac.rs#L241), [src/iface/mod.rs:708](../src/iface/mod.rs#L708) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`add_prefix` and `add_route` set `sync_required` on every refresh, by design. `sync_slaac_state` then always ends with `config_changed()`. That bumps `config_generation`, wakes the iface waker and, on Ethernet interfaces, calls `Driver::set_multicast_filter`. So every RA with a known PIO or a nonzero router lifetime costs a filter rewrite and a spurious config change, even when nothing changed.

## Details
src/iface/slaac.rs:213-215:
```rust
// Unlike the original, a refreshed lifetime also syncs
self.sync_required = true;
```
`add_route` does the same at line 241. src/iface/slaac.rs:530-531:
```rust
self.update_slaac_state(timestamp);
self.config_changed();
```
`config_changed` (src/iface/mod.rs:708) runs `update_solicited_node_groups`, `sync_multicast_filter`, `config_generation.wrapping_add(1)` and `waker.wake()`. The `config_generation` doc says it goes up when the configuration changes. DESIGN §4 accepts a filter call per change "at configuration-change cadence". RA refreshes are packet cadence and any on-link host sets the rate.

Refreshing `expires_at` on a route is legitimate. Only the unconditional `config_changed` is waste.

## Failure scenario
- An on-link host sends 1000 valid RAs/s (link-local source, hop limit 255, a known PIO). The node reprograms its multicast filter 1000 times a second. On cyw43 each one is a firmware iovar round trip.
- On a normal LAN, an app that re-announces itself when `config_generation` changes does so on every periodic RA.

## Suggested fix
Call `config_changed` only when an address or route was added or removed. A pure lifetime refresh needs no filter update and no generation bump.
