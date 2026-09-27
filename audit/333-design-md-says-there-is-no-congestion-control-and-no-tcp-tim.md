# 333. DESIGN.md says no congestion control and no TCP timestamps by default, but defaults enable both

| | |
|---|---|
| Severity | info |
| Category | doc-mismatch |
| Location | [Cargo.toml:55](../Cargo.toml#L55), [Cargo.toml:56](../Cargo.toml#L56), DESIGN.md §7 |
| Features | default |
| Verification | confirmed against the code |

## Summary
DESIGN.md §7 says "with neither, TCP does no congestion control at all, which is the default" and, for `tcp-timestamps`, "That cost on every segment is why the feature is off by default." Cargo.toml's `default` list has `tcp-cubic` (line 55) and `tcp-timestamps` (line 56). The public feature docs match Cargo.toml. Only DESIGN.md is wrong, and it is untracked.

## Failure scenario
Someone reasoning from DESIGN.md assumes a default build has no f64 CUBIC code and full-size segment payloads, and misjudges code size, soft-float cost and per-segment payload.

## Suggested fix
Update DESIGN.md §7 to match the defaults, or change the defaults.
