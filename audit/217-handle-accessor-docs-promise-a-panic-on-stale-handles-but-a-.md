# 217. Handle accessor docs promise a panic on stale handles, but a reused slot silently addresses a different object

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/stack.rs:737](../src/stack.rs#L737), [src/stack.rs:750](../src/stack.rs#L750), [src/stack.rs:813](../src/stack.rs#L813), [src/stack.rs:822](../src/stack.rs#L822), [src/iface/mod.rs:41](../src/iface/mod.rs#L41) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`Stack::iface`, `udp_socket`, `raw_socket`, `tcp_socket`, `tcp_listener` and the `remove_*` methods say "Panics if the handle is stale". Slabs reuse the first free slot and handles carry no generation. After a slot is reused, a stale handle does not panic. It operates on the new interface or socket.

## Details
The same wording appears at src/stack.rs:322, 332, 455, 737, 750, 813, 822, 850, 859, 942, 951, 981, 990. `Slab::add_with` picks the first free slot (src/storage/slab.rs). The handle type docs (src/iface/mod.rs:41-44, src/udp.rs:32-37, and the raw, tcp and listener equivalents) do not mention reuse. With a slab count of 1 the handle is `()`, so any handle is always valid.

No generation counter is a documented decision (DESIGN.md §2). The problem is the public docs describe a safety net that only works until the next add.

## Failure scenario
A task keeps handle `a` after `remove_udp_socket(a)`. Another task adds a socket and gets `b == a`. The first task calls `remove_udp_socket(a)` or sends on it. It silently destroys or uses the second task's socket.

## Reproduction
Test in the `stack.rs` test module:
```rust
#[test]
fn vtest_f8_stale_handle_no_panic() {
    let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
    let a = stack.add_udp_socket().unwrap();
    stack.remove_udp_socket(a);
    let b = stack.add_udp_socket().unwrap();
    assert_eq!(a, b);
    let _ = stack.udp_socket(a); // documented to panic
    stack.remove_udp_socket(a); // removes b
}
```
The test passes with no panic.

## Suggested fix
Reword to "Panics if no socket exists at this handle. Handles are reused: after removal, a later add may return the same handle." Say the same on each handle type.
