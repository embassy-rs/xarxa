# 044. IGMP messages are sent without the IP Router Alert option

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/multicast.rs:515](../src/multicast.rs#L515), [src/multicast.rs:539](../src/multicast.rs#L539), [src/stack.rs:2786](../src/stack.rs#L2786) |
| Features | default (`multicast`, `ipv4`) |
| Verification | reproduced with a test |

## Summary

IGMP reports and leaves are built with `push_ipv4_header`, which always writes a bare 20-byte header. RFC 2236 requires the Router Alert option (RFC 2113) in every IGMPv2 message. MLD already adds its Router Alert (`push_mldv2_router_alert`), IGMP has no equivalent. Routers or snooping switches that apply the RFC 2236 §9 hardening ignore our reports.

## Details

src/multicast.rs:515
```rust
fn igmp_report_packet(&self, version: IgmpVersion, group_addr: Ipv4Addr) -> Option<PacketBuf> {
    let iface_addr = self.ipv4_addr()?;
    let mut pkt = PacketBuf::try_new()?;
    pkt.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
```

`igmp_leave_packet` (src/multicast.rs:539) is the same. Both end in `crate::stack::push_ipv4_header`:

src/stack.rs:2795
```rust
buf.push_front(IPV4_HEADER_LEN);
let mut packet = Ipv4Packet::new_unchecked(buf);
packet.set_version(4);
packet.set_header_len(IPV4_HEADER_LEN as u8);
packet.set_dscp(0);
```

## Failure scenario

A router or snooping switch configured to drop IGMP reports without Router Alert ignores every join and report from xarxa. The host never receives the group. That hardening is optional and uncommon, so the impact is limited.

## RFC reference

RFC 2236 §2:
> All IGMP messages described in this document are sent with IP TTL 1, and contain the IP Router Alert option [RFC 2113] in their IP header.

RFC 2236 §10:
> The IGMPv2 spec requires the presence of the IP Router Alert option [RFC 2113] in all packets described in this memo.

RFC 2236 §9 lets routers "Ignore Report messages without Router Alert options [RFC 2113]".

RFC 2236 uses "requires", not the BCP 14 MUST. Only IGMPv1/v2 is implemented, so RFC 3376's TOS 0xc0 requirement does not apply. v1 reports (RFC 1112) needed no Router Alert. The gap is in v2 reports and Leave messages.

## Reproduction

Added to the `src/multicast.rs` test module in a scratch copy:

```rust
#[test]
fn verify_igmp_no_router_alert() {
    let medium = Medium::Ip;
    let (mut stack, _rx, tx, _link) = test_stack(medium);
    let group = Ipv4Addr::new(224, 0, 0, 22);
    stack.iface(IFACE).join_multicast_group(group).unwrap();
    stack.poll(Instant::ZERO);
    let mut n = 0;
    for mut p in recv_all(medium, &tx) {
        let ip = Ipv4Packet::new_checked(&mut p[..]).unwrap();
        if ip.next_header() == IpProtocol::Igmp {
            println!("IGMP header_len={} dscp={}", ip.header_len(), ip.dscp());
            n += 1;
            assert_eq!(ip.header_len(), 24, "no router alert option");
        }
    }
    assert!(n > 0);
}
```

Output:
```
IGMP header_len=20 dscp=0
assertion `left == right` failed: no router alert option
  left: 20
 right: 24
```

## Suggested fix

For IGMP, reserve and write a 24-byte IPv4 header with the Router Alert option (type 0x94, length 4, value 0). A variant of `push_ipv4_header` that takes options, or an IGMP-specific helper like `push_mldv2_router_alert`, would do.
