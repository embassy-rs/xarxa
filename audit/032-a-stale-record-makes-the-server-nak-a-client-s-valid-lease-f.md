# 032. A stale record makes the DHCP server NAK a client's valid lease from another server (INIT-REBOOT and REBINDING)

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4_server.rs:567](../src/iface/dhcpv4_server.rs#L567), [src/iface/dhcpv4_server.rs:537](../src/iface/dhcpv4_server.rs#L537), [src/iface/dhcpv4_server.rs:312](../src/iface/dhcpv4_server.rs#L312) |
| Features | `dhcpv4-server` |
| Verification | reproduced with a test |

## Summary
`handle_request` NAKs any client it has a record for when the requested address differs from the record. `find_by_client` also matches `Released` and `Expired` records. So a client that once got an OFFER from us, then took a lease from another server on the same subnet, is NAKed at every INIT-REBOOT and every REBINDING. Without a record, the code stays silent for the same request, which is clearly the intent.

## Details
When a client picks another server, the record is kept as `Released`.

src/iface/dhcpv4_server.rs:537:
```rust
if server_id.is_some_and(|s| s != server_cidr.address()) {
    // The client selected another server (RFC 2131 §3.1 step 4): what it
    // held with us is dead, only the record stays.
    if let Some(i) = self.find_by_client(id) {
        debug!("DHCP server: {} chose another server", chaddr);
        self.leases[i].state = DhcpServerLeaseState::Released;
    }
    return None;
}
```

src/iface/dhcpv4_server.rs:312:
```rust
fn find_by_client(&self, id: &ClientId<'_>) -> Option<usize> {
    self.leases
        .iter()
        .position(|lease| !matches!(lease.state, DhcpServerLeaseState::Declined { .. }) && lease.matches_client(id))
}
```

src/iface/dhcpv4_server.rs:566:
```rust
match self.find_by_client(id) {
    Some(i) if self.leases[i].address == addr && self.available_for(addr, id, now) => Answer::Ack,
    Some(_) => Answer::Nak("requested address does not match the lease"),
    None if init_reboot => Answer::Silent,
    ...
    None if !self.in_pool(addr) => Answer::Silent,
```

Any record hits `Some(_)` and never reaches the silent arms. An `Expired` record does the same: a client that got an OFFER, never requested it, and later holds a lease from another server is NAKed too.

## Failure scenario
xarxa serves .10-.11 and a router serves .100-.200 on the same /24. A laptop DISCOVERs, gets both OFFERs and picks the router. xarxa marks its record `Released`. When the laptop reboots and sends INIT-REBOOT for .100, xarxa broadcasts a NAK. If it arrives before the router's ACK, the laptop drops its address (RFC 2131 §3.2) and restarts discovery. The same happens each time the lease reaches REBINDING.

## RFC reference
RFC 2131 §4.3.2, INIT-REBOOT:

> If the DHCP server has no record of this client, then it MUST remain silent, and MAY output a warning to the network administrator. This behavior is necessary for peaceful coexistence of non-communicating DHCP servers on the same wire.

A record that only says the client went elsewhere is not a record of the address it now holds. For REBINDING the RFC says only:

> The DHCP server SHOULD check 'ciaddr' for correctness before replying to the DHCPREQUEST.

An out-of-pool address is not ours to judge, which is what the `None` arm already says.

## Reproduction
Test added to the test module of src/iface/dhcpv4_server.rs, in a scratch copy of HEAD:
```rust
#[test]
fn vfy_released_record_naks_other_servers_lease() {
    let (mut stack, rx, tx) = test_stack();
    let other_lease = Ipv4Addr::new(192, 168, 1, 100);
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Request, CLIENT_HW).server_id(OTHER_SERVER_IP).requested_ip(other_lease), 1);
    assert_eq!(leases(&mut stack)[0].state(), DhcpServerLeaseState::Released);
    let before = tx.borrow().len();
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Request, CLIENT_HW).requested_ip(other_lease), 2);
    let n1 = tx.borrow().len();
    let t1 = if n1 > before { let mut s = last_sent(&tx); Some(message_type(&mut s)) } else { None };
    println!("INIT-REBOOT with Released record: {:?}", t1);
    let mut msg = Msg::new(DhcpMessageType::Request, CLIENT_HW);
    msg.ciaddr = other_lease; msg.src_ip = other_lease;
    send(&mut stack, &rx, msg, 3);
    let n2 = tx.borrow().len();
    let t2 = if n2 > n1 { let mut s = last_sent(&tx); Some(message_type(&mut s)) } else { None };
    println!("REBINDING with Released record: {:?}", t2);
    send(&mut stack, &rx, Msg::new(DhcpMessageType::Request, CLIENT2_HW).requested_ip(other_lease), 4);
    let n3 = tx.borrow().len();
    println!("INIT-REBOOT with no record: replies={}", n3 - n2);
    assert_eq!(t1, None, "NAKed INIT-REBOOT for another server's lease");
}
```

`cargo test --lib vfy_ -- --nocapture`:
```
INIT-REBOOT with Released record: Some(Nak)
REBINDING with Released record: Some(Nak)
INIT-REBOOT with no record: replies=0
panicked: assertion failed: NAKed INIT-REBOOT for another server's lease (left: Some(Nak), right: None)
```

## Suggested fix
NAK on a mismatch only when the record is active (`Offered`/`Bound`) or the requested address is in our pool. Otherwise fall through to the same answers as the no-record case.
