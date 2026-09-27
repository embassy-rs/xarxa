# 260. A 1 GiB receive buffer (the documented maximum) produces window scale shift 15

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:615](../src/tcp/mod.rs#L615), [src/tcp/mod.rs:642](../src/tcp/mod.rs#L642), [src/tcp/mod.rs:752](../src/tcp/mod.rs#L752), [src/stack.rs:879](../src/stack.rs#L879) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`rx_capacity == 1 << 30` is accepted (the check is `> (1 << 30)`, and the `add_tcp_socket` docs say it panics only above 1 GiB). The shift is bit length minus 16, which is 15 for exactly 2^30. The SYN advertises WS=15. The peer clamps to 14 and sees half the real window. Only exactly 2^30 is affected.

## Details
src/tcp/mod.rs:615:
```rust
if rx_capacity > (1 << 30) {
```
src/tcp/mod.rs:642 (same formula in `reset` at 752):
```rust
remote_win_shift: rx_cap_log2.saturating_sub(16) as u8,
```
The shift is sent as-is in the SYN (mod.rs:1985, `syn.window_scale = Some(self.remote_win_shift);`).

## Failure scenario
A hosted build calls `add_tcp_socket(1 << 30, ..)`. The SYN carries window scale 15. The peer logs it, uses 14, and the effective receive window is halved. No corruption.

## RFC reference
RFC 7323 §2.3: "Thus, the shift count MUST be limited to 14 (which allows windows of 2^30 = 1 GiB)."

## Reproduction
Test in the `src/tcp/mod.rs` `mod test` harness, scratch copy:
```rust
#[test]
fn zz_ws15() {
    let s = socket_syn_sent_with_buffer_sizes(64, 1 << 30);
    std::println!("remote_win_shift for 1GiB rx: {}", s.remote_win_shift);
    assert!(s.remote_win_shift <= 14);
}
```
Output:
```
remote_win_shift for 1GiB rx: 15
panicked: assertion failed: s.remote_win_shift <= 14
```

## Suggested fix
Clamp the shift with `.min(14)`, or reject capacities >= 2^30 and fix the docs.
