# 041. SLAAC address is installed as a /64, so an A=1/L=0 prefix becomes on-link

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:253](../src/iface/slaac.rs#L253), [src/iface/slaac.rs:483](../src/iface/slaac.rs#L483), [src/stack.rs:364](../src/stack.rs#L364), [src/iface/mod.rs:811](../src/iface/mod.rs#L811) |
| Features | default (`slaac`) |
| Verification | reproduced with a test |

## Summary

SLAAC never reads the PIO on-link (L) flag. The formed address goes into `ip_addrs` with a /64 cidr, and `TxContext::route` treats any destination inside an interface address's cidr as on-link. So forming an address from an A=1, L=0 prefix makes the whole /64 on-link, which RFC 5942 §4 forbids. The reverse also holds: an L=1 prefix without A=1 (or not /64) is ignored, so on-link neighbors in it go through the router.

## Details

`process_prefix` only looks at ADDRCONF. `NdiscPrefixInfoFlags::ON_LINK` is defined in `src/wire/ndiscoption.rs:29` and used nowhere outside tests.

src/iface/slaac.rs:253
```rust
fn process_prefix(&mut self, prefix: PrefixInformation, now: Instant) {
    if !prefix.flags.contains(NdiscPrefixInfoFlags::ADDRCONF) {
        return;
    }
```

`sync_slaac_state` installs the address formed by `from_link_prefix`, which is prefix + EUI-64 with prefix length 64:

src/iface/slaac.rs:483
```rust
let new_addr = IfaceAddr {
    cidr: IpCidr::V6(address),
    origin: AddrOrigin::Slaac,
    preferred_until: Some(prefixinfo.preferred_until),
};
```

Routing then sends anything inside that /64 straight to the link:

src/stack.rs:364
```rust
if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
    return Some(EgressRoute {
        iface: iface.handle,
        next_hop: *dst_addr,
```

src/iface/mod.rs:811
```rust
pub(crate) fn in_same_network(&self, addr: &IpAddr) -> bool {
    self.cidrs().any(|cidr| cidr.contains_addr(addr))
}
```

This matches DESIGN.md's rule (on-link means inside one of the interface's address prefixes). That rule also covers manually configured addresses, which RFC 5942 addresses too. That part is documented design and not part of this finding. The SLAAC case is where the stack itself derives on-link state from an RA that said otherwise.

## Failure scenario

- An 802.15.4 interface has SLAAC on (`set_slaac` accepts Ethernet and 802.15.4). The border router advertises 2001:db8:1::/64 with A=1, L=0, as RFC 6775 §6.1 requires. The node forms 2001:db8:1::<eui64>/64. A UDP send to 2001:db8:1::abcd, two radio hops away, is treated as on-link. The node sends an NS instead of forwarding to the router. Nobody answers, resolution fails after about 3 s, and the socket gets HostUnreachable. Every multi-hop peer in the prefix is unreachable.
- On Ethernet, networks that advertise A=1, L=0 (client isolation, NBMA or access-concentrator setups, RFC 5942 §5) break the same way for same-prefix peers.
- A link advertising L=1, A=0 (addresses from DHCPv6 or manual config): on-link neighbors in that prefix go through the router, or are Unaddressable with no default router.

On typical Ethernet LANs L=1 and A=1 are set together, which limits the impact there.

## RFC reference

RFC 5942 §4, rule 1:
> The assignment of an IPv6 address -- whether through IPv6 stateless address autoconfiguration [RFC4862], DHCPv6 [RFC3315], or manual configuration -- MUST NOT implicitly cause a prefix derived from that address to be treated as on-link and added to the Prefix List.

RFC 4861 §6.3.4:
> a Prefix Information option with the on-link flag set to zero conveys no information concerning on-link determination

> For each Prefix Information option with the on-link flag set, a host does the following: ... create a new entry for the prefix and initialize its invalidation timer to the Valid Lifetime value

RFC 6775 §6.1:
> A router MUST NOT set the L (on-link) flag in the PIOs, since that might trigger hosts to send multicast NSs.

## Reproduction

Added to the `src/stack.rs` test module in a scratch copy:

```rust
#[test]
#[cfg(feature = "slaac")]
fn verify_slaac_l0_is_onlink() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    let router_ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
    let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    stack.poll(Instant::from_secs(1));
    let mut frame = router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix,
        Duration::from_secs(7200), Duration::from_secs(3600));
    let off = 14 + 40 + 16 + 8 + 3; // PIO flags
    assert_eq!(frame[off], 0xc0);
    frame[off] = 0x40; // A=1, L=0
    {
        let mut ra = Icmpv6Packet::new_unchecked(&mut frame[54..]);
        ra.fill_checksum(&router_ll, &IPV6_LINK_LOCAL_ALL_NODES);
    }
    rx.borrow_mut().push_back(frame);
    stack.poll(Instant::from_secs(6));
    let n = tx.borrow().len();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp)
        .send_slice(b"hi", (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x55), 1000))
        .unwrap();
    let frame = tx.borrow()[n].clone();
    let mut eth_bytes = frame.clone();
    let eth = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
    assert_eq!(eth.dst_addr(), router_hw, "L=0 prefix peer should go via router");
}
```

Output:
```
addrs: [..., IfaceAddr { cidr: V6(Cidr { address: 2001:db8::ff:fe00:1, prefix_len: 64 }), origin: Slaac, .. }]
dst mac: Address([51, 51, 255, 0, 0, 85])
panicked: assertion `left == right` failed: L=0 prefix peer should go via router
  left: Address([51, 51, 255, 0, 0, 85])
 right: Address([2, 0, 0, 0, 0, 2])
```

The send went out as a solicited-node multicast NS (33:33:ff:00:00:55), not to the router.

## Suggested fix

- Keep L=1 prefixes (any length) in a SLAAC-owned on-link list with their own valid lifetime, for example as a gatewayless route consulted by `route()`.
- Install SLAAC addresses without implying on-link for their /64 when L=0, for example as /128, or with a flag that `in_same_network` skips.
- At minimum, document that A=1/L=0 is treated as on-link.
