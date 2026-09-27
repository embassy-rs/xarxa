# 149. A /31 subnet with the server on the upper address can lease nothing

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/dhcpv4_server.rs:768](../src/iface/dhcpv4_server.rs#L768), [src/wire/ipv4.rs:166](../src/wire/ipv4.rs#L166) |
| Features | dhcpv4-server |
| Verification | reproduced with a test |

## Summary
`addr_valid` always excludes the network address. On an RFC 3021 /31 both addresses are host addresses. With the server on x.x.x.1/31, the only other address x.x.x.0 is rejected, so DISCOVERs get no OFFER and a REQUEST for it gets a NAK. Nothing reports why.

## Details
src/iface/dhcpv4_server.rs:764-770:
```rust
addr.x_is_unicast()
    && server_cidr.contains_addr(&addr)
    && addr != server_cidr.address()
    && addr != server_cidr.network().address()
    && server_cidr.broadcast() != Some(addr)
```
`Ipv4Cidr::broadcast` returns None for /31 and /32 (src/wire/ipv4.rs:166), but the network-address check applies at every prefix length. The REQUEST path also calls `addr_valid`, so a REQUEST for x.x.x.0 is NAKed as not on this network.

## Failure scenario
A USB-Ethernet gadget is configured as 10.0.0.1/31 with pool 10.0.0.0-10.0.0.0. The host's DISCOVER gets no OFFER.

## Reproduction
Scratch test `vv_f9_slash31` in the dhcpv4_server test module: replace 192.168.1.1/24 with 10.0.0.1/31, `DhcpServerConfig::new(10.0.0.0, 10.0.0.0)`, then DISCOVER.

```
F9 replies 0
```

## Suggested fix
Skip the network-address exclusion when the prefix length is 31.
