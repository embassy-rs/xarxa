# 033. DHCP `outgoing_options` that do not fit panic, and for the server any received DISCOVER or REQUEST triggers it

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/iface/dhcpv4_server.rs:737](../src/iface/dhcpv4_server.rs#L737), [src/iface/dhcpv4.rs:553](../src/iface/dhcpv4.rs#L553), [src/iface/dhcpv4_server.rs:74](../src/iface/dhcpv4_server.rs#L74), [src/iface/dhcpv4.rs:269](../src/iface/dhcpv4.rs#L269), [src/iface/mod.rs:582](../src/iface/mod.rs#L582) |
| Features | `dhcpv4-server` (server), `dhcpv4` (client) |
| Verification | reproduced with a test |

## Summary
`Server::build_reply` and `Client::build` emit the configured `outgoing_options` and `unwrap!` the result. An option longer than 255 bytes, or options that together exceed the packet, panic. Nothing validates this at config time and the public docs don't mention a limit. For the server the panic fires while processing any client's DISCOVER or REQUEST.

## Details
src/iface/dhcpv4_server.rs:724:
```rust
for option in self.config.outgoing_options {
    options.emit(*option)?;
}
...
unwrap!(result, "DHCP reply does not fit in a packet");
```

src/iface/dhcpv4.rs:548 is the same pattern, ending in `unwrap!(result, "DHCP message does not fit in a packet");`.

`OptionWriter::emit` (src/wire/dhcpv4.rs:89) returns `Err(Malformed)` if `option.data.len() > 255`, and also if the option doesn't fit the remaining space. The option space is the buffer minus the link, IP and UDP headers and the 240-byte DHCP header: about 1232 bytes at the default 1514, about 308 at the smallest allowed 590.

`Iface::set_dhcpv4_server` (src/iface/mod.rs:582) checks only the medium and the pool order. `set_dhcpv4` (src/iface/mod.rs:495) checks only the medium. The public docs say only "Extra options added to every OFFER and ACK." (dhcpv4_server.rs:74) and "Extra options added to every outgoing packet." (dhcpv4.rs:269). The internal comments claiming "only an absurd `outgoing_options`" can panic (dhcpv4_server.rs:647, dhcpv4.rs:472) understate it: one 256-byte option is enough, and options 43, 119 and 121 routinely get large.

For the client, the panic comes from its DISCOVER timer in the first `Stack::poll` after `set_dhcpv4`, not from network input.

## Failure scenario
A server is configured with `outgoing_options = &[DhcpOption { kind: 119, data: &[..; 256] }]`. Any host on the link broadcasts a DISCOVER and `Stack::poll` panics. With `packet-buf-size-590`, roughly 260 bytes of valid options in total is enough.

## Reproduction
Tests added to the test module of src/iface/dhcpv4_server.rs, in a scratch copy of HEAD:
```rust
#[test]
fn vfy_big_outgoing_options_panic() {
    let (mut stack, rx, _tx) = test_stack();
    let mut config = test_config();
    static DATA: [u8; 255] = [0x41; 255];
    static OPTS: [DhcpOption<'static>; 5] = [
        DhcpOption { kind: 43, data: &DATA }, DhcpOption { kind: 119, data: &DATA },
        DhcpOption { kind: 121, data: &DATA }, DhcpOption { kind: 224, data: &DATA },
        DhcpOption { kind: 225, data: &DATA },
    ];
    config.outgoing_options = &OPTS;
    stack.iface(IFACE).set_dhcpv4_server(Some(config)).unwrap();
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
}

#[test]
fn vfy_256_byte_option_panic() {
    let (mut stack, rx, _tx) = test_stack();
    let mut config = test_config();
    static DATA: [u8; 256] = [0x41; 256];
    static OPTS: [DhcpOption<'static>; 1] = [DhcpOption { kind: 119, data: &DATA }];
    config.outgoing_options = &OPTS;
    stack.iface(IFACE).set_dhcpv4_server(Some(config)).unwrap();
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
}
```

`cargo test --lib vfy_ -- --nocapture`, both tests:
```
panicked at src/iface/dhcpv4_server.rs:737:9:
unwrap of `result` failed: DHCP reply does not fit in a packet: Malformed
```

## Suggested fix
Validate `outgoing_options` in `set_dhcpv4` and `set_dhcpv4_server` (each option at most 255 bytes, total within the space left after the fixed options) and return an error. Or skip options that don't fit with a warning. Document the limit on both fields.
