# 304. DHCPv4 option overload (52) is ignored and repeated options are not concatenated

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/dhcpv4.rs:396](../src/wire/dhcpv4.rs#L396), [src/wire/dhcpv4.rs:432](../src/wire/dhcpv4.rs#L432), [src/iface/dhcpv4.rs:357](../src/iface/dhcpv4.rs#L357), [src/iface/dhcpv4.rs:613](../src/iface/dhcpv4.rs#L613) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`Packet::options` walks only the options field. Nothing reads option 52, so options carried in `file` or `sname` are never seen. `Packet::option` returns the first instance of an option, so split options are truncated. A lost lease time falls back to 120 s. A lost server identifier makes the client ignore the message.

## Details
src/wire/dhcpv4.rs:396 iterates only `field::OPTIONS` (`buffer[240..]`). src/wire/dhcpv4.rs:432:
```rust
pub fn option(&self, kind: u8) -> Option<&[u8]> {
    self.options().find(|opt| opt.kind == kind).map(|opt| opt.data)
}
```
`OPT_OPTION_OVERLOAD` (src/wire/dhcpv4.rs:267) has no users. The client reads subnet mask, lease time, router, DNS, T1, T2 and server identifier through `option()`. Lease time defaults to `DEFAULT_LEASE_DURATION` (120 s, src/iface/dhcpv4.rs:40). The DHCP server (`dhcpv4-server`) reads client options the same way, with less impact.

## Failure scenario
A server puts option 51 and option 6 in `file` with option 52 = 1. The client installs a 120 s lease with no DNS servers. In practice overload is rare, since the client advertises a max message size of at least 576.

## RFC reference
RFC 2131 §4.1: "The options in the 'options' field MUST be interpreted first, so that any 'option overload' options may be interpreted. The 'file' field MUST be interpreted next (if the 'option overload' option indicates that the 'file' field contains DHCP options), followed by the 'sname' field."

RFC 2131 §4.1: "Options may appear only once, unless otherwise specified in the options document. The client concatenates the values of multiple instances of the same option into a single parameter list for configuration." (Descriptive, not a MUST.)

## Suggested fix
When option 52 is present, iterate `file` and then `sname` after the options field. Concatenate repeated instances, at least for list options such as 3 and 6.
