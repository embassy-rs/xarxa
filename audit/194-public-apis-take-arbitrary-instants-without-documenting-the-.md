# 194. Public APIs take arbitrary Instants without documenting the 24.8-day range, and Route::preferred_until does nothing

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/neighbor.rs:355](../src/neighbor.rs#L355), [src/route.rs:61](../src/route.rs#L61), [src/route.rs:64](../src/route.rs#L64) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`NeighborCache::insert(.., expires_at)` and `Route::expires_at` accept any `Instant`. One more than 2^31 ms ahead compares as already past, so the entry turns Stale or the route is removed at the next poll. The docs do not mention the limit. `Route::preferred_until` is public and documented as "`None` means forever", but nothing reads it.

## Details
`Instant` is a wrapping u32 compared by sign of difference (DESIGN.md §4 "Time"). The `insert` doc only says "`expires_at` is when the entry stops being used. There are no static entries."

src/route.rs:60-61
```rust
/// `None` means "forever".
pub preferred_until: Option<Instant>,
```
It is only constructed (with `None`, in route.rs and dhcpv4.rs, and in tests). The only `preferred_until` read in the stack is `IfaceAddr`'s (src/iface/mod.rs:230).

## Failure scenario
- A user adds a static neighbor with `now + Duration::MAX + Duration::MAX`. It is Stale from the next poll and the stack keeps resolving it.
- A user sets `Route::preferred_until` expecting deprecation. Nothing happens.

## Suggested fix
Document that deadlines must be at most `Duration::MAX` ahead of now. Remove `Route::preferred_until`, or document that it has no effect.
