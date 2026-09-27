# 327. build.rs scripts use env::vars(), which panics on any non-UTF-8 environment variable

| | |
|---|---|
| Severity | low |
| Category | build |
| Location | [xarxa-driver/build.rs:42](../xarxa-driver/build.rs#L42), [build.rs:73](../build.rs#L73), [xarxa-driver/build.rs:66](../xarxa-driver/build.rs#L66) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Both build scripts iterate `env::vars()`, which panics when any variable name or value is not UTF-8. An unrelated variable in the environment fails the build of everything depending on xarxa-driver. Separately, the "multiple values" check for conflicting size features depends on environment order: it panics only if both features are seen before the `XARXA_` variable. Otherwise the env var wins silently.

## Details
xarxa-driver/build.rs:42:
```rust
for (var, value) in env::vars() {
```
xarxa-driver/build.rs:66-74 panics on a second feature only while `!cfg.seen_env`.

## Reproduction
In a scratch copy:
```
env $'BADVAR=\xff' CARGO_TARGET_DIR=<fresh> cargo check -p xarxa-driver
```
Output:
```
thread 'main' panicked at .../library/std/src/env.rs:168:83: called `Result::unwrap()` on an `Err` value: "\xFF"
```

## Suggested fix
Use `env::vars_os()` and skip non-UTF-8 entries, or query the known names with `env::var`. Collect features and env vars first, then apply the precedence rules.
