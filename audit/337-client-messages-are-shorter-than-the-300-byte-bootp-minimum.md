# 337. DHCP client messages are shorter than the 300-byte BOOTP minimum

| | |
|---|---|
| Severity | info |
| Category | interop |
| Location | [src/iface/dhcpv4.rs:554](../src/iface/dhcpv4.rs#L554) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the code |

## Summary
Client messages end right after the END option. A DISCOVER is about 262 bytes of DHCP payload, a SELECTING REQUEST about 274. busybox udhcpc, dhcpcd and the Linux kernel ipconfig pad to 300 bytes because some relays and old servers drop shorter BOOTP messages. RFC 2131 has no such minimum and RFC 951/1542 are not in `rfcs/`, so this is an interop hardening note.

## Details
src/iface/dhcpv4.rs:554:
```rust
let len = DHCP_HEADER_LEN + options.written();
buf.set_len(len);
```
240 bytes of header, then message type (3), client id (9), max size (4), PRL (5), END (1). No padding.

## Failure scenario
A legacy relay or server that enforces the 300-byte minimum drops every client message. The device never gets an address there. No concrete such server was identified.

## Suggested fix
Pad with PAD (0) options up to a 300-byte DHCP payload.
