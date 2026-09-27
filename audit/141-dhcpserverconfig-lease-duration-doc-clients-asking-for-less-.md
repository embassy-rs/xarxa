# 141. DhcpServerConfig::lease_duration doc: clients asking for less than 60 s don't get it

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/dhcpv4_server.rs:68](../src/iface/dhcpv4_server.rs#L68), [src/iface/dhcpv4_server.rs:385](../src/iface/dhcpv4_server.rs#L385), [src/iface/dhcpv4_server.rs:48](../src/iface/dhcpv4_server.rs#L48) |
| Features | `dhcpv4-server` |
| Verification | reproduced with a test |

## Summary
The public field doc says "Clients asking for a shorter lease get it." `lease_duration()` raises a requested lease to `MIN_LEASE_DURATION` (60 s) first. The doc also doesn't say the value saturates at `Duration::MAX` (about 12.4 days), or that `Duration::ZERO` is accepted.

## Details
src/iface/dhcpv4_server.rs:385
```rust
Some(d) => d.max(MIN_LEASE_DURATION).min(self.config.lease_duration),
```
src/iface/dhcpv4_server.rs:48 cites RFC 2132 §9.2 for the minimum, but that section defines none. The `Duration::MAX` cap is not in this function: `Duration::from_secs` saturates when the config is built. `set_dhcpv4_server` (src/iface/mod.rs:590-597) does not validate `lease_duration`, so `Duration::ZERO` makes every ACK carry lease time 0.

## Failure scenario
A test client asks for a 10 s lease to exercise renewal, following the doc. It gets 60 s.

## Reproduction
Test added to `src/iface/dhcpv4_server.rs` `mod test` in a scratch copy:
```rust
#[test]
fn vv_f1_short_lease_floor() {
    let (mut stack, rx, tx) = test_stack();
    send(&mut stack, &rx,
        Msg::new(DhcpMessageType::Discover, CLIENT_HW)
            .opt(field::OPT_IP_LEASE_TIME, &10u32.to_be_bytes()), 0);
    let mut sent = last_sent(&tx);
    println!("F1 offered lease = {:?}",
        DhcpPacket::new_checked(&mut sent.dhcp).unwrap().option(field::OPT_IP_LEASE_TIME));
}
```
`cargo test --lib vv_ -- --nocapture`:
```
F1 offered lease = Some([0, 0, 0, 60])
```

## Suggested fix
Document the 60 s floor and the `Duration::MAX` cap on the field, and fix the RFC citation. Optionally reject a zero `lease_duration` in `set_dhcpv4_server`.
