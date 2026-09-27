# 157. NAK or ACK received in BOUND (before T1) is acted on: a stray NAK drops a valid lease

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:681](../src/iface/dhcpv4.rs#L681), [src/iface/dhcpv4.rs:665](../src/iface/dhcpv4.rs#L665) |
| Features | default (`dhcpv4`) |
| Verification | reproduced with a test |

## Summary
`ClientState::Renewing` covers BOUND, RENEWING and REBINDING, and keeps the last REQUEST's xid after the ACK. A NAK with that xid arriving in BOUND resets the client and drops the lease. A duplicate ACK restarts the lease timers. RFC 2131 says to discard both in BOUND.

## Details
src/iface/dhcpv4.rs:681-685:
```rust
(ClientState::Requesting(_) | ClientState::Renewing(_), DhcpMessageType::Nak) => {
    if !ignore_naks {
        self.dhcpv4_reset(inner);
    }
}
```
Nothing distinguishes "before renew_at" from RENEWING/REBINDING.

## Failure scenario
A rebind REQUEST is broadcast. Server A ACKs it. A misconfigured authoritative server B NAKs the same xid a few ms later. The client drops the lease it just renewed, removes the address and route, and restarts discovery.

## RFC reference
RFC 2131 Figure 5, BOUND state: "DHCPOFFER, DHCPACK, DHCPNAK/Discard".

## Reproduction
Test in the `src/iface/dhcpv4.rs` test module:
```rust
#[test]
fn vv_nak_in_bound() {
    let (mut stack, rx, _tx) = bound_stack();
    rx.borrow_mut().push_back(reply(DhcpMessageType::Nak, XID, OFFERED_IP, &[]));
    stack.poll(at(5));
    assert!(stack.iface(IFACE).dhcpv4_lease().is_some(), "NAK in BOUND dropped the lease");
}
```
Output: `panicked: NAK in BOUND dropped the lease`.

## Suggested fix
Track BOUND separately, or change the xid once an ACK is accepted, so replies to a finished transaction are discarded.
