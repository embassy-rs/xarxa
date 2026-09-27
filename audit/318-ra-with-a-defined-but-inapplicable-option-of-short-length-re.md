# 318. RA or NS/NA with a short Redirected Header option is discarded whole

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/ndiscoption.rs:176](../src/wire/ndiscoption.rs#L176), [src/iface/slaac.rs:406](../src/iface/slaac.rs#L406), [src/stack.rs:2991](../src/stack.rs#L2991) |
| Features | default (`slaac` for the RA path) |
| Verification | reproduced with a test |

## Summary
`NdiscOption::check_len` rejects a Redirected Header option shorter than 48 bytes and a PIO shorter than 32 bytes. The RA option walk returns on the first error, so the whole RA is dropped: no prefix, no default route. RFC 4861 says options not specified for RAs MUST be ignored. `ndisc_lladdr_option` in NS/NA processing has the same strictness. The PIO half is weaker, since RFC 4861 does not clearly say what to do with a short PIO. The Redirected Header case is the clear violation.

## Details
src/wire/ndiscoption.rs:175-177:
```rust
Type::PrefixInformation if data_range.end >= field::PREFIX.end => Ok(()),
Type::RedirectedHeader if data_range.end >= field::REDIR_MIN_SZ => Ok(()),
Type::PrefixInformation | Type::RedirectedHeader => Err(Malformed),
```
src/iface/slaac.rs:406-409:
```rust
let Ok(opt) = NdiscOption::new_checked(&mut options[offset..]) else {
    trace!("ndisc: malformed router advertisement option");
    return;
};
```

## Failure scenario
A router or middlebox adds an 8-byte type-4 option to its RA. xarxa ignores that router's RAs and never configures an address or default route. An unknown option type of the same length is accepted.

## RFC reference
RFC 4861 §6.1.2: "All included options have a length that is greater than zero." ... "The contents of any defined options that are not specified to be used with Router Advertisement messages MUST be ignored and the packet processed as normal." §7.1.1 and §7.1.2 say the same for NS and NA.

## Reproduction
Added to `mod test` in src/stack.rs:
```rust
#[test] #[cfg(feature = "slaac")]
fn vv_ra_with_short_redirected_header_ignored() { vv_ra_opt(4); }
#[test] #[cfg(feature = "slaac")]
fn vv_ra_control_unknown_opt() { vv_ra_opt(200); }
#[cfg(feature = "slaac")]
fn vv_ra_opt(ty: u8) {
    let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    let router_ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
    let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    stack.poll(Instant::from_secs(1));
    let frame = router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix, Duration::from_secs(7200), Duration::from_secs(3600));
    let mut icmp = frame[ETHERNET_HEADER_LEN + 40..].to_vec();
    icmp.extend_from_slice(&[ty, 1, 0, 0, 0, 0, 0, 0]);
    { let mut ra = Icmpv6Packet::new_unchecked(&mut icmp[..]); ra.fill_checksum(&router_ll, &IPV6_LINK_LOCAL_ALL_NODES); }
    let mut ip = ipv6_packet(router_ll, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol::Icmpv6, &icmp);
    Ipv6Packet::new_unchecked(&mut ip[..]).set_hop_limit(255);
    let mut f = frame[..ETHERNET_HEADER_LEN].to_vec();
    f.extend_from_slice(&ip);
    rx.borrow_mut().push_back(f);
    stack.poll(Instant::from_secs(2));
    assert!(stack.iface(iface).ip_addrs().iter().any(|a| a.origin == AddrOrigin::Slaac),
        "RA with an 8-byte Redirected Header option was discarded");
}
```
Output:
```
test stack::test::vv_ra_control_unknown_opt ... ok
test stack::test::vv_ra_with_short_redirected_header_ignored ... FAILED
```

## Suggested fix
In the RA and NS/NA option walks, apply per-type minimums only to the types the message uses (SLLA/TLLA, PIO, MTU). For other types, only check length > 0 and that the option fits, then skip it. Skip a malformed PIO rather than the whole RA.
