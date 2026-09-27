# 158. Lease time 0, or a server that always NAKs, causes a DISCOVER/REQUEST loop with no backoff

| | |
|---|---|
| Severity | low |
| Category | hang-stall |
| Location | [src/iface/dhcpv4.rs:771](../src/iface/dhcpv4.rs#L771), [src/iface/dhcpv4.rs:839](../src/iface/dhcpv4.rs#L839), [src/iface/dhcpv4.rs:681](../src/iface/dhcpv4.rs#L681) |
| Features | default (`dhcpv4`) |
| Verification | reproduced with a test |

## Summary
A lease time of 0 (or `max_lease_duration` of zero) gives `expires_at == now`. The same poll installs the lease, expires it, resets, and sends a new DISCOVER. The address is never usable. A server that NAKs every REQUEST loops the same way. The rate is set by the server's replies, not a local busy loop.

## Details
src/iface/dhcpv4.rs:771:
```rust
if clock.expired(state.expires_at) {
```
followed by `self.dhcpv4_reset(inner)`, which sets:
```rust
ClientState::Discovering(DiscoverState { retry_at: inner.now }),
```
at line 839. `parse_ack` accepts a lease of 0. Each cycle also calls `config_changed` (waker wake, multicast filter sync) and `purge_iface_link_state`.

## Failure scenario
A rogue or misconfigured server hands out lease 0, or a second authoritative server NAKs every REQUEST. The device sends DISCOVER/REQUEST at the server's response rate, never gets an address, and wakes the interface waker every cycle.

## Reproduction
Test in the `src/iface/dhcpv4.rs` test module:
```rust
#[test]
fn vv_lease_zero_loop() {
    let (mut stack, rx, tx) = test_stack();
    let mut opts = ack_options();
    opts[3] = DhcpOption { kind: field::OPT_IP_LEASE_TIME, data: &[0, 0, 0, 0] };
    stack.poll(at(0));
    for i in 0..3u32 {
        rx.borrow_mut().push_back(reply(DhcpMessageType::Offer, XID, OFFERED_IP, &opts));
        stack.poll(at(1 + 2 * i));
        rx.borrow_mut().push_back(reply(DhcpMessageType::Ack, XID, OFFERED_IP, &opts));
        let d = stack.poll(at(2 + 2 * i));
        println!("cycle {} sent={} lease={:?} deadline_ms_ahead={}", i, tx.borrow().len(),
            stack.iface(IFACE).dhcpv4_lease().is_some(), (d - at(2 + 2 * i)).as_millis());
    }
    assert!(stack.iface(IFACE).dhcpv4_lease().is_some(), "lease never usable");
}
```
Output:
```
cycle 0 sent=3 lease=false deadline_ms_ahead=10000
cycle 1 sent=5 lease=false
cycle 2 sent=7 lease=false
panicked: lease never usable
```

## Suggested fix
Enforce a minimum lease (tens of seconds). Back off restarting discovery after a NAK or an immediate expiry.
