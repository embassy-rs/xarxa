# 061. On-link determination uses assigned address prefixes and ignores the RA on-link (L) flag

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:364](../src/stack.rs#L364), [src/iface/mod.rs:811](../src/iface/mod.rs#L811), [src/iface/slaac.rs:253](../src/iface/slaac.rs#L253), [src/iface/slaac.rs:384](../src/iface/slaac.rs#L384) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary

`route()` treats any destination inside the prefix of an assigned address as on-link. SLAAC installs a /64 address from any PIO with the A flag set and never reads the L flag. So a prefix advertised with A=1, L=0 becomes on-link anyway. Traffic to other hosts in that prefix does address resolution on the link instead of going to the default router.

## Details

src/stack.rs:364, the on-link step of `route()`:

```rust
if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
```

src/iface/mod.rs:811:

```rust
pub(crate) fn in_same_network(&self, addr: &IpAddr) -> bool {
    self.cidrs().any(|cidr| cidr.contains_addr(addr))
}
```

src/iface/slaac.rs:253 only checks ADDRCONF:

```rust
fn process_prefix(&mut self, prefix: PrefixInformation, now: Instant) {
    if !prefix.flags.contains(NdiscPrefixInfoFlags::ADDRCONF) {
        return;
    }
```

src/iface/slaac.rs:384, `from_link_prefix` returns the address as a /64 cidr:

```rust
Some(Ipv6Cidr::new(Ipv6Addr::from_octets(bytes), 64))
```

`NdiscPrefixInfoFlags::ON_LINK` is never read outside `src/wire` and one test in src/stack.rs. Nothing records whether a prefix was advertised on-link.

The converse also holds: a PIO with L=1, A=0 never makes its prefix on-link. Those destinations go via the router. That works but is suboptimal, since Redirects are not processed.

Manually configured addresses have the same prefix-equals-on-link behavior. There the prefix length the user chose can reasonably count as manual on-link configuration, which RFC 5942 allows.

## Failure scenario

1. The router advertises 2001:db8:1::/64 with A=1, L=0. This is common on client-isolated Wi-Fi and some ISP and cellular networks. RFC 6775 requires L=0 for 6LoWPAN-ND.
2. The device configures 2001:db8:1::a/64 via SLAAC.
3. The app sends UDP to 2001:db8:1::b.
4. `route()` picks the destination itself as next hop. The packet is parked and an NS goes to the solicited-node group. Nobody answers.
5. After about 3 s the resolution fails and the socket gets an unreachable error. The router would have forwarded the packet.

## RFC reference

RFC 5942 §4, rule 1:

> The assignment of an IPv6 address -- whether through IPv6 stateless address autoconfiguration [RFC4862], DHCPv6 [RFC3315], or manual configuration -- MUST NOT implicitly cause a prefix derived from that address to be treated as on-link and added to the Prefix List. A host considers a prefix to be on-link only through explicit means, such as those specified in the on-link definition in the Terminology section of [RFC4861] (as modified by this document) or via manual configuration.

RFC 4861 §4.6.2:

> L 1-bit on-link flag. When set, indicates that this prefix can be used for on-link determination. When not set the advertisement makes no statement about on-link or off-link properties of the prefix.

RFC 6775 §6.1:

> A router MUST NOT set the L (on-link) flag in the PIOs, since that might trigger hosts to send multicast NSs.

(xarxa does not implement 6LoWPAN-ND. The quote shows such networks exist.)

## Suggested fix

Keep the on-link property separate from the address. Install SLAAC addresses as /128, or flag them as not on-link, unless the PIO had L=1. Keep a list of on-link prefixes from PIOs with L=1, with their valid lifetime, and use it in the on-link check.
