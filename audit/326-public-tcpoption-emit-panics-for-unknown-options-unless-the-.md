# 326. TcpOption::emit panics for Unknown options unless the buffer is exactly the option's length

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/wire/tcp.rs:587](../src/wire/tcp.rs#L587) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`emit` writes the option at the front of `buffer` and returns the rest, so the other variants accept a larger buffer. The `Unknown` arm copies into `buffer[2..]`, which panics unless `buffer.len() == 2 + data.len()`. `length as u8` also truncates silently for data over 253 bytes. The stack never emits `Unknown`, so only external users of the public `xarxa::wire::TcpOption` are affected.

## Details
src/wire/tcp.rs:585-588:
```rust
&TcpOption::Unknown { kind, data: provided } => {
    buffer[0] = kind;
    buffer[2..].copy_from_slice(provided)
}
```
Compare src/wire/tcp.rs:577:
```rust
buffer[2..length].copy_from_slice(blocks);
```

## Failure scenario
User code builds TCP options by hand for a raw socket: an MSS option, then an experimental Unknown option into the remaining slice. The program panics.

## Reproduction
Added to `src/wire/tcp.rs` in a scratch copy, run with `cargo test --lib vt_`:
```rust
#[test]
fn vt_unknown_emit() {
    let mut buf = [0u8; 8];
    TcpOption::Unknown { kind: 30, data: &[1, 2] }.emit(&mut buf);
}
```
Output: `panicked at src/wire/tcp.rs:587:37`.

## Suggested fix
Use `buffer[2..length].copy_from_slice(provided)`. Document that `emit` panics if the buffer is shorter than `buffer_len()`.
