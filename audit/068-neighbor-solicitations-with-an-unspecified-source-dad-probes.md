# 068. Neighbor solicitations from :: (DAD probes) are dropped, so the stack never defends its addresses

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:1689](../src/stack.rs#L1689), [src/stack.rs:2245](../src/stack.rs#L2245), [src/stack.rs:2287](../src/stack.rs#L2287), [src/stack.rs:2300](../src/stack.rs#L2300), [src/iface/mod.rs:1005](../src/iface/mod.rs#L1005), [src/wire/ipv6.rs:161](../src/wire/ipv6.rs#L161) |
| Features | default (`ipv6`, `medium-ethernet` or `medium-ieee802154`) |
| Verification | reproduced with a test |

## Summary

`process_ipv6` drops every packet whose source is not unicast, and `x_is_unicast` excludes `::`. DAD neighbor solicitations are sent from `::`, so they never reach `process_ndisc_solicit`. The stack never sends the all-nodes NA that RFC 4861 §7.2.4 requires. Another node running DAD for one of our addresses sees no answer and configures it too. IPv6 raw sockets never see these probes either, so an application cannot work around it.

README lists our own DAD as not implemented. Answering other nodes' DAD is a separate receive-side duty.

## Details

src/stack.rs:1689:
```rust
if !src_addr.x_is_unicast() {
    // Discard packets with non-unicast source addresses.
    debug!("non-unicast source address");
    return;
}
```

src/wire/ipv6.rs:131:
```rust
fn x_is_unicast(&self) -> bool {
    !(self.is_multicast() || self.is_unspecified())
}
```

The check runs before the raw-socket offer, so raw ICMPv6 sockets miss the probe too.

`process_ndisc_solicit` (src/stack.rs:2245) has no branch for an unspecified source. It always answers with S=1, unicast to `src_addr` (src/stack.rs:2287, 2300):
```rust
na.set_neighbor_flags(NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE);
...
self.transmit_ndisc(iface, reply, target_addr, src_addr);
```

Latent hazard for a fix: relaxing only the source check would send the NA to `::`. Resolving `::` reaches `get_source_address_ipv6`, which asserts `!dst_addr.is_unspecified()` (src/iface/mod.rs:1005), and `solicited_node`, which asserts `self.x_is_unicast()` (src/wire/ipv6.rs:161). That would be a remotely triggered panic. The §7.1.1 validity checks for this case (solicited-node destination, no SLLA option) are also missing, since the case never reaches that code today.

## Failure scenario

The stack owns fdaa::1 on Ethernet. A new host configured with fdaa::1 runs DAD: NS with src `::`, dst ff02::1:ff00:1, target fdaa::1, hop limit 255, no options. xarxa drops it at the IP layer and transmits nothing. The new host concludes the address is unique and uses it. Traffic to fdaa::1 is split between the two hosts.

## RFC reference

RFC 4861 §7.2.4:
> If the source of the solicitation is the unspecified address, the node MUST set the Solicited flag to zero and multicast the advertisement to the all-nodes address.

RFC 4861 §7.2.3:
> If the Source Address is the unspecified address, the node MUST NOT create or update the Neighbor Cache entry.

RFC 4861 §7.1.1 (validity of an NS from `::`):
> If the IP source address is the unspecified address, the IP destination address is a solicited-node multicast address.
> If the IP source address is the unspecified address, there is no source link-layer address option in the message.

RFC 4862 §5.4.3:
> If the target address is not tentative (i.e., it is assigned to the receiving interface), the solicitation is processed as described in [RFC4861].

## Reproduction

Test in the `src/stack.rs` test module of a scratch copy:

```rust
#[test]
#[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
fn vv_dad_ns_not_answered() {
    let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    for (src, with_opt) in [(Ipv6Addr::new(0xfe80,0,0,0,0,0xff,0xfe00,0x2), true), (Ipv6Addr::UNSPECIFIED, false)] {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let dst = OUR_V6.solicited_node();
        let mut icmp = vec![0; if with_opt { 32 } else { 24 }];
        {
            let mut ns = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            ns.set_msg_type(Icmpv6Message::NeighborSolicit);
            ns.set_msg_code(0);
            ns.clear_reserved();
            ns.set_target_addr(OUR_V6);
            if with_opt {
                let mut opt = NdiscOption::new_unchecked(ns.payload_mut());
                opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
                opt.set_data_len(1);
                opt.set_link_layer_addr(RawHardwareAddress::from(remote_hw));
            }
            ns.fill_checksum(&src, &dst);
        }
        let mut ip = ipv6_packet(src, dst, IpProtocol::Icmpv6, &icmp);
        Ipv6Packet::new_unchecked(&mut ip[..]).set_hop_limit(255);
        let frame = eth_frame_from(remote_hw, EthernetAddress([0x33,0x33,0xff,0,0,1]), EthernetProtocol::Ipv6, &ip);
        inject(&mut stack, &rx, frame);
        std::println!("NS from {src}: {} frames sent", tx.borrow().len());
        if src.is_unspecified() { assert_eq!(tx.borrow().len(), 0); } else { assert_eq!(tx.borrow().len(), 1); }
    }
}
```

Output:
```
NS from fe80::ff:fe00:2: 1 frames sent
NS from ::: 0 frames sent
ok
```

## Suggested fix

Let ICMPv6 NS packets with source `::` past the source check. In `process_ndisc_solicit`, for that case:
- require a solicited-node destination and no SLLA option (§7.1.1),
- skip `fill_neighbor`,
- send the NA with S=0 to ff02::1, never to `src_addr`.
