# 340. SLAAC interface identifiers are the modified EUI-64 of the MAC

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/iface/slaac.rs:383](../src/iface/slaac.rs#L383) |
| Features | default (`ipv6`, SLAAC) |
| Verification | confirmed against the code |

## Summary
`from_link_prefix` always forms the IID from the hardware address's modified EUI-64. The MAC is in every global address, so the device can be tracked across networks and its vendor read from the OUI. This is documented in the `set_slaac` doc comment (src/iface/mod.rs:509-511). RFC 7217 and RFC 8981 are the alternatives. Neither is a MUST.

## Details
src/iface/slaac.rs:383:
```rust
bytes[8..16].copy_from_slice(&hardware_addr.as_eui_64()?);
```

## Failure scenario
The same device gets 2001:db8:a::<EUI64(mac)> on one network and 2001:db8:b::<EUI64(mac)> on another. Any remote server can correlate them.

## RFC reference
RFC 7217 §1 (motivation): embedding link-layer addresses in IIDs allows "the tracking of a host as it moves around the network".

## Suggested fix
Add an RFC 7217 stable opaque IID option to `SlaacConfig` with the planned autoconf work.
