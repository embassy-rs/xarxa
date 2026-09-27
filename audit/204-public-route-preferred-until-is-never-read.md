# 204. Public Route::preferred_until is never read

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/route.rs:61](../src/route.rs#L61), [src/route.rs:279](../src/route.rs#L279), [src/route.rs:310](../src/route.rs#L310) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`Route` is public and has a public `preferred_until: Option<Instant>` field, documented only as "`None` means forever". Nothing reads it. Setting it has no effect.

## Details
src/route.rs:60-61
```rust
/// `None` means "forever".
pub preferred_until: Option<Instant>,
```
The field is only written: constructors (lines 76, 89), SLAAC (slaac.rs:521, `None`) and tests. `Routes::lookup` (line 279) filters on `via_router`, `expires_at`, the binding and the prefix. `remove_expired` (line 310) looks only at `expires_at`.

Also, the `expires_at` doc does not repeat the 2^31 ms limit from the `Instant` docs. An expiry set further ahead compares as passed and the route is removed at the next poll. `cidr` and `via_router` have no doc comments.

## Failure scenario
The user sets `preferred_until` on a backup default route to phase it out. Lookup keeps using it exactly as before.

## Suggested fix
Remove the field, or implement and document it. Document that `expires_at` must be within `Duration::MAX` of now.
