# 153. DhcpConfig / DhcpServerConfig outgoing options that don't fit panic inside Stack::poll

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/iface/dhcpv4.rs:553](../src/iface/dhcpv4.rs#L553), [src/iface/dhcpv4_server.rs:737](../src/iface/dhcpv4_server.rs#L737), [src/wire/dhcpv4.rs:90](../src/wire/dhcpv4.rs#L90) |
| Features | default (`dhcpv4`, `dhcpv4-server`) |
| Verification | reproduced with a test |

## Summary
`OptionWriter::emit` returns `Malformed` for an option with more than 255 data bytes or when the options run out of space. The client and server `unwrap!` that result. A too-long user option or parameter request list panics at the next DHCP transmission. `set_dhcpv4` and `set_dhcpv4_server` don't validate, and the public docs don't mention the limit. This is API misuse, not network input.

## Details
src/wire/dhcpv4.rs:90:
```rust
if option.data.len() > u8::MAX as _ {
```
src/iface/dhcpv4.rs:553:
```rust
unwrap!(result, "DHCP message does not fit in a packet");
```
src/iface/dhcpv4_server.rs:737:
```rust
unwrap!(result, "DHCP reply does not fit in a packet");
```
The public doc at src/iface/dhcpv4.rs:269 only says "Extra options added to every outgoing packet." Space for options is `ip_mtu - 28 - 240`, so a small interface MTU can overflow even with modest options.

## Failure scenario
The user sets `outgoing_options` to a 300-byte option 60 and calls `set_dhcpv4`. The first poll panics while building DISCOVER, and the device crash-loops.

## Reproduction
Test in the `src/iface/dhcpv4.rs` test module:
```rust
#[test]
fn vv_big_option_panics() {
    static BLOB: [u8; 300] = [0; 300];
    static OPTS: [DhcpOption<'static>; 1] = [DhcpOption { kind: 60, data: &BLOB }];
    let (mut stack, _rx, _tx) = test_stack();
    let mut cfg = DhcpConfig::default();
    cfg.outgoing_options = &OPTS;
    stack.iface(IFACE).set_dhcpv4(Some(cfg)).unwrap();
    stack.poll(at(0));
}
```
Output: `panicked at src/iface/dhcpv4.rs:553:9: unwrap of `result` failed: DHCP message does not fit in a packet: Malformed`.

The server path was traced, not tested.

## Suggested fix
Reject options over 255 bytes in `set_dhcpv4` / `set_dhcpv4_server`. Drop options that don't fit with a warning instead of panicking. Document the limit.
