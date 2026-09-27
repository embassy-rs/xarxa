# 339. Broadcast recognition is limited to 255.255.255.255 and each prefix's all-ones address

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/iface/mod.rs:885](../src/iface/mod.rs#L885) |
| Features | default (`ipv4`) |
| Verification | confirmed against the RFC text |

## Summary
`is_broadcast_v4` recognizes the limited broadcast and the all-ones broadcast of each configured CIDR. The classful directed and all-subnets directed forms (MUST) and the 4.2BSD 0-forms (SHOULD) are not recognized. Classful addressing is obsolete, and the prefix-based subnet-directed broadcast works, so this is informational.

## Details
src/iface/mod.rs:885-897:
```rust
if address.is_broadcast() {
    return true;
}
self.cidrs()
    .filter_map(|own_cidr| match own_cidr {
        IpCidr::V4(own_ip) => Some(own_ip.broadcast()?),
```

## Failure scenario
With 10.1.2.3/24, datagrams to 10.255.255.255, 10.1.2.0 or 0.0.0.0 are dropped as not for us.

## RFC reference
RFC 1122 §3.3.6: "All-Subnets Directed Broadcast: {<Network-number>,-1,-1} ... A host MUST recognize any of these forms in the destination address of an incoming datagram." And: "All hosts SHOULD recognize and accept any of these non-standard broadcast addresses" (0 substituted for -1).

## Suggested fix
None needed. Optionally document that only CIDR-based broadcast forms are recognized.
