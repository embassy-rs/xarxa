# 036. set_ip_addrs / remove_ip_addr drop the DHCPv4 lease address, and renewals never put it back

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/iface/mod.rs:431](../src/iface/mod.rs#L431), [src/iface/mod.rs:411](../src/iface/mod.rs#L411), [src/iface/dhcpv4.rs:675](../src/iface/dhcpv4.rs#L675), [src/iface/dhcpv4.rs:853](../src/iface/dhcpv4.rs#L853) |
| Features | default (`dhcpv4`) |
| Verification | reproduced with a test |

## Summary

`Iface::set_ip_addrs` keeps only the IPv6 link-local address and replaces everything else, including the address the running DHCPv4 client installed. `remove_ip_addr` can do the same for the leased address. The client is not told and stays bound. A renewal with an unchanged lease installs nothing, so the interface has no IPv4 address until the lease is lost or changes. The DHCP default route stays in place the whole time.

## Details

src/iface/mod.rs:431, `set_ip_addrs` rebuilds the table from the given CIDRs plus `LinkLocal` entries only:

```rust
for a in self.state().ip_addrs.iter() {
    if a.origin == AddrOrigin::LinkLocal && !addrs.iter().any(|n| n.cidr.address() == a.cidr.address()) {
        addrs.push(*a).map_err(|_| AddrError::Full)?;
    }
}
```

`Dhcpv4` and `Slaac` entries are dropped. It then calls `invalidate()`, which purges the interface's neighbor cache entries.

src/iface/dhcpv4.rs:675, on a renew ACK the lease is only reapplied if it changed:

```rust
if state.lease != lease {
    let (new, old) = (lease.installed(), state.lease.installed());
    state.lease = lease;
    self.dhcpv4_apply(inner, Some(new), Some(old));
}
```

src/iface/dhcpv4.rs:853, and even then the address is only pushed when it changed:

```rust
if old_addr != new_addr {
    self.remove_ip_addrs(AddrOrigin::Dhcpv4);
    if let Some(cidr) = new_addr {
```

Nothing checks that the leased address is still on the interface. Recovery only comes from a lost or changed lease, a NAK, or `restart_dhcpv4`.

The unicast renewal at T1 also does not go out in practice. With the address gone and the neighbor cache purged, nothing is transmitted between T1 and T2 in the test. The likely cause is that ARP for the server cannot be sourced without an IPv4 address (inferred from the test, not traced line by line). The client only reaches the server with the broadcast REBIND at T2, sent from 192.168.1.50, which is no longer assigned. The ACK to that rebind still does not reinstall the address.

Related: `add_ip_addr` on the leased address with another prefix turns it into a `Manual` address, which is not removed when the lease ends.

SLAAC has the same drop, but the next RA refresh re-adds the address, so that outage is bounded by the RA interval.

The docs for `set_ip_addrs` ("Equivalent to removing every address and adding the given ones. The automatic IPv6 link-local address is kept.") and `remove_ip_addr` say nothing about autoconfigured addresses.

## Failure scenario

1. The app enables DHCPv4 and gets 192.168.1.50/24 with a 24 h lease.
2. The app calls `set_ip_addrs([fd00::10/64])` to add a static IPv6 address.
3. 192.168.1.50 is gone. `dhcpv4_lease()` still reports it.
4. The renewal at T1 is not sent. The rebind at T2 is ACKed with the same address. `dhcpv4_apply` is not called, or does nothing.
5. IPv4 sends fail with `Unaddressable` until the lease is lost, possibly about 24 h. The default route via the DHCP router is still there, so the cause is not obvious.

## Reproduction

Added to the `mod test` of src/iface/dhcpv4.rs in a scratch copy of HEAD:

```rust
#[test]
fn vfy_set_ip_addrs_drops_lease_forever() {
    let mut config = DhcpConfig::default();
    config.max_lease_duration = Some(Duration::from_secs(60));
    let (mut stack, rx, tx, _link) = bound_stack_with(config);
    rx.borrow_mut().push_back(arp_request_from_server());
    stack.poll(at(3));
    assert!(stack.iface(IFACE).has_ip_addr(OFFERED_IP));
    stack.iface(IFACE).set_ip_addrs([IpCidr::new(crate::wire::Ipv6Addr::new(0xfd00,0,0,0,0,0,0,1).into(), 64)]).unwrap();
    assert!(!stack.iface(IFACE).has_ip_addr(OFFERED_IP));
    let n = tx.borrow().len();
    for t in 31..60 { stack.poll(at(t)); if tx.borrow().len() > n { std::println!("sent at {}", t); break; } }
    let mut sent = parse_sent(tx.borrow().last().unwrap());
    let (s_, d_) = (sent.src_ip, sent.dst_ip); std::println!("src={:?} dst={:?} type={:?}", s_, d_, message_type(&mut sent));
    rx.borrow_mut().push_back(reply(DhcpMessageType::Ack, XID, OFFERED_IP, &ack_options()));
    stack.poll(at(60));
    let l = stack.iface(IFACE).dhcpv4_lease().map(|x| std::format!("{:?}", x)); std::println!("lease={:?} addrs={:?}", l, stack.iface(IFACE).ip_addrs());
    assert!(stack.iface(IFACE).dhcpv4_lease().is_some());
    assert!(stack.iface(IFACE).has_ip_addr(OFFERED_IP), "lease address not reinstalled after renewal");
}
```

Output:

```
sent at 55
src=192.168.1.50 dst=255.255.255.255 type=Request
lease=Some("DhcpLease { ... address: 192.168.1.50/24, router: Some(192.168.1.1) ... }") addrs=[fd00::1/64 Manual, fe80::ff:fe00:1/64 LinkLocal]
panicked: lease address not reinstalled after renewal
```

T1 is 30 s and T2 is 52.5 s with the 60 s lease. The first transmission after the address was removed is the broadcast rebind at 55 s.

## Suggested fix

Either:
- keep `Dhcpv4` and `Slaac` origin addresses in `set_ip_addrs`, as is done for `LinkLocal`, and decide what `remove_ip_addr` should do with them, or
- have `dhcpv4_apply` (or the ACK path) check that the leased address is present and reinstall it if not.

Document what happens to autoconfigured addresses in both methods.
