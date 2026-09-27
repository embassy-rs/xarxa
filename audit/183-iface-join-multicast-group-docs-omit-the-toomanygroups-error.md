# 183. Iface::join_multicast_group docs omit the TooManyGroups error

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/multicast.rs:157](../src/multicast.rs#L157), [src/multicast.rs:206](../src/multicast.rs#L206) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The `# Errors` list on `join_multicast_group` names only `Unaddressable`. The implementation also returns `MulticastError::TooManyGroups` when the group table is full, which happens without `alloc` at `MULTICAST_GROUP_COUNT`. The variant's own doc describes this, the method doc does not.

## Details
src/multicast.rs:206:
```rust
.map_err(|_| MulticastError::TooManyGroups)?;
```

## Suggested fix
Add "`TooManyGroups`: the group table is full. Only possible without `alloc`." to the Errors list.
