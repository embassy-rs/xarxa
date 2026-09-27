# 349. Neighbor cache can be overwritten by spoofed ARP or NA with Override (unauthenticated ND)

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/stack.rs:2313](../src/stack.rs#L2313), [src/stack.rs:2360](../src/stack.rs#L2360), [src/stack.rs:2173](../src/stack.rs#L2173) |
| Features | default |
| Verification | confirmed against the code |

## Summary
An NA with the Override flag replaces the cached address of a known target, as RFC 4861 §7.2.5 requires. ARP fills the cache from any request or reply aimed at us with an in-subnet source. The hop limit 255 check limits NA spoofing to on-link attackers. This is how unauthenticated ND and ARP work, and SEND is out of scope. Not an RFC violation.

## Details
src/stack.rs:2360:
```rust
if !flags.contains(NdiscNeighborFlags::OVERRIDE) && lladdr != cached {
    // §7.2.5 I: the cache keeps its address.
    return;
}
if lladdr != cached || flags.contains(NdiscNeighborFlags::SOLICITED) {
    self.fill_neighbor(iface, ip_addr, lladdr);
}
```
`process_arp` calls `fill_neighbor` for any ARP packet aimed at us (src/stack.rs:2211-2219).

## Failure scenario
An on-link attacker sends an NA (hop limit 255, Override) for the gateway's address with its own MAC. Traffic to the gateway goes to the attacker.

## Suggested fix
Document that the neighbor cache trusts unauthenticated ARP/ND. Optionally require NUD confirmation before accepting an Override that changes the address.
