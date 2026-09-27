# 104. Cargo feature docs invite enabling tcp-reno or defmt, but both fail to compile with the default features

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [Cargo.toml:141](../Cargo.toml#L141), [Cargo.toml:163](../Cargo.toml#L163), [src/lib.rs:29](../src/lib.rs#L29), [src/fmt.rs:7](../src/fmt.rs#L7) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The congestion control docs say to enable one of `tcp-reno` / `tcp-cubic`, and that no feature means no congestion control. But `tcp-cubic` is in `default`, so `features = ["tcp-reno"]` fails to build. `defmt` conflicts with the default `log` feature the same way. Neither doc says `default-features = false` is needed.

## Details
Cargo.toml:141-143:
```toml
#! ### TCP congestion control
#! Enable one of these features to enable congestion control. No feature enabled means
#! no congestion control. You may enable at most one.
```
`default` contains `"log"` (Cargo.toml:29) and `"tcp-cubic"` (Cargo.toml:55). Cargo.toml:163 documents `defmt` as "Log with the `defmt` crate." The comment at Cargo.toml:25 calls `defmt` non-default but does not mention the conflict.

src/lib.rs:29:
```rust
compile_error!("The features tcp-reno and tcp-cubic are mutually exclusive.");
```
src/fmt.rs:7:
```rust
compile_error!("You may not enable both `defmt` and `log` features.");
```
`cargo check --features tcp-reno` also emits E0428 (duplicate `Congestion`).

The DESIGN.md claims that no congestion control and no `tcp-timestamps` are the default are covered by a separate finding (tcp-buffers-cc-14).

## Failure scenario
A user writes `xarxa = { version = "...", features = ["defmt"] }` or picks Reno as the docs suggest. The build fails with the compile_error, and for Reno also with a duplicate-definition error.

## Suggested fix
In the `tcp-reno`/`tcp-cubic` and `defmt` docs, say that the conflicting default feature must be turned off with `default-features = false`. Or drop `tcp-cubic` and `log` from `default`.
