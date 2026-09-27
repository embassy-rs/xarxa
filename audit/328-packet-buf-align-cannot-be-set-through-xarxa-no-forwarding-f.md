# 328. packet-buf-align cannot be set through xarxa, and XARXA_PACKET_BUF_ALIGN is silently ignored

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [xarxa-driver/src/config.rs:16](../xarxa-driver/src/config.rs#L16), [build.rs:71](../build.rs#L71), [xarxa-driver/build.rs:46](../xarxa-driver/build.rs#L46), [xarxa-driver/src/buf.rs:42](../xarxa-driver/src/buf.rs#L42) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The xarxa-driver config docs and DESIGN §4 say `xarxa` forwards the driver's features of the same name. `xarxa` forwards `packet-buf-count-*` and `packet-buf-size-*`, but no `packet-buf-align-*`. The default alignment is 1, while DESIGN §3 says the storage is 8-byte aligned. An application can only get DMA alignment by depending on `xarxa-driver` directly.

## Details
xarxa-driver/src/config.rs:16:
```rust
//! The `xarxa` crate forwards the features of the same name to this crate, and
```
xarxa-driver/Cargo.toml:44-48 defines `packet-buf-align-{2,4,8,16,32}`. The root Cargo.toml has no `align` feature.

build.rs:71 whitelists the env var as a driver knob and skips it:
```rust
let driver_configs = ["PACKET_BUF_COUNT", "PACKET_BUF_SIZE", "PACKET_BUF_ALIGN"];
```
xarxa-driver/build.rs:46 does not know it and skips unknown names:
```rust
let Some(cfg) = configs.get_mut(name) else { continue };
```
So `XARXA_PACKET_BUF_ALIGN=8` builds fine and does nothing. config.rs:40 does say alignment is feature-only, so the env var no-op contradicts xarxa's whitelist, not the driver doc. The default falls through to xarxa-driver/src/buf.rs:42:
```rust
_ => { #[repr(C, align(1))] struct Data([u8; PACKET_BUF_SIZE]); }
```

## Failure scenario
- `xarxa = { features = ["packet-buf-align-8"] }` is a cargo error.
- A user sets `XARXA_PACKET_BUF_ALIGN=8` in `.cargo/config.toml` like the other knobs. The build succeeds with 1-byte alignment.
- An stm32 eth driver relying on DESIGN's "8-byte aligned" gets misaligned buffers. The MAC treats that as undefined behaviour.

## Suggested fix
Add forwarding `packet-buf-align-N` features to xarxa. Make xarxa's build.rs reject `XARXA_PACKET_BUF_ALIGN` with a message pointing to the features, or support it in the driver build.rs. Fix DESIGN §3 about the default.
