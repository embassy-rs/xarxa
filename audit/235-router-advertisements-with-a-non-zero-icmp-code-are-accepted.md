# 235. Router advertisements with a non-zero ICMP code are accepted; NS/RA are dropped over malformed options they must ignore

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1904](../src/stack.rs#L1904), [src/iface/slaac.rs:406](../src/iface/slaac.rs#L406), [src/stack.rs:2999](../src/stack.rs#L2999), [src/wire/ndiscoption.rs:175](../src/wire/ndiscoption.rs#L175) |
| Features | default (`slaac` for the RA part) |
| Verification | reproduced with a test (RA code); confirmed against the code (option lengths) |

## Summary
The RouterAdvert guard does not check the ICMP code, and neither does `slaac_process_advertisement`. An RA with code != 0 configures addresses and routes. Separately, a PrefixInformation or RedirectedHeader option shorter than its type minimum fails `NdiscOption::new_checked` in any message. That drops a whole NS or RA, where the RFC says to ignore options not used by the message.

## Details
src/stack.rs:1904:
```rust
Icmpv6Message::RouterAdvert
    if hop_limit == 0xff
        && ll_src.is_some()
        && src_addr.is_link_local()
        && (dst_addr == IPV6_LINK_LOCAL_ALL_NODES || dst_addr.is_link_local()) =>
```
NS and NA do check `msg_code() == 0`.

src/wire/ndiscoption.rs:175:
```rust
Type::PrefixInformation if data_range.end >= field::PREFIX.end => Ok(()),
Type::RedirectedHeader if data_range.end >= field::REDIR_MIN_SZ => Ok(()),
Type::PrefixInformation | Type::RedirectedHeader => Err(Malformed),
```
src/stack.rs:2999 (`ndisc_lladdr_option`, used for NS/NA):
```rust
let opt = NdiscOption::new_checked(&mut options[offset..])?;
```
The RA first pass in src/iface/slaac.rs:406 returns on the same error.

## Failure scenario
- A future RA variant with a different code is processed as a normal RA and changes addressing.
- An NS carrying a 1-unit type-4 option is dropped, so address resolution towards us fails.

## RFC reference
RFC 4861 §6.1.2: "A node MUST silently discard any received Router Advertisement messages that do not satisfy all of the following validity checks: ... ICMP Code is 0." and "The contents of any defined options that are not specified to be used with Router Advertisement messages MUST be ignored and the packet processed as normal."
§7.1.1: "The contents of any defined options that are not specified to be used with Neighbor Solicitation messages MUST be ignored and the packet processed as normal."

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
#[cfg(feature = "slaac")]
fn vt_ra_nonzero_code() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let router_hw = EthernetAddress([0x02,0,0,0,0,0x02]);
    let router_ll = Ipv6Addr::new(0xfe80,0,0,0,0,0xff,0xfe00,0x2);
    let prefix = Ipv6Addr::new(0x2001,0xdb8,0,0,0,0,0,0);
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    stack.poll(Instant::from_secs(1));
    let mut f = router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix, Duration::from_secs(3600), Duration::from_secs(3600));
    { let icmp = &mut f[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN..];
      let mut ra = Icmpv6Packet::new_unchecked(icmp);
      ra.set_msg_code(1);
      ra.fill_checksum(&router_ll, &IPV6_LINK_LOCAL_ALL_NODES); }
    rx.borrow_mut().push_back(f);
    stack.poll(Instant::from_secs(2));
    let our = Ipv6Addr::new(0x2001,0xdb8,0,0,0,0xff,0xfe00,0x1);
    let has = stack.iface(iface).has_ip_addr(our);
    println!("VT5 installed={} default_route={}", has, stack.routes().default_ipv6_route().is_some());
    assert!(has);
}
```
Output: `VT5 installed=true default_route=true`, test passes. The option-length part was checked by code trace only.

## Suggested fix
Add `icmp_packet.msg_code() == 0` to the RA guard. In the NDISC option walkers, check only the generic type/length, and apply type-specific size checks only to options the message uses.
