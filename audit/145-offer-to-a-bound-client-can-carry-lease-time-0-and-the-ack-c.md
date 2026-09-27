# 145. OFFER to a bound client can carry lease time 0, and the ACK contradicts the OFFER's lease time

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/dhcpv4_server.rs:491](../src/iface/dhcpv4_server.rs#L491), [src/iface/dhcpv4_server.rs:699](../src/iface/dhcpv4_server.rs#L699), [src/iface/dhcpv4_server.rs:584](../src/iface/dhcpv4_server.rs#L584) |
| Features | dhcpv4-server |
| Verification | reproduced with a test |

## Summary
A DISCOVER from a client with a running lease is offered the remaining time, truncated to whole seconds. With under 1 s left the OFFER says lease time 0. The ACK to the following REQUEST always grants a full `lease_duration`, so the ACK conflicts with the OFFER for any bound client, not only in the sub-second case.

## Details
src/iface/dhcpv4_server.rs:491:
```rust
let duration = match time_left {
    Some(time_left) if requested_lease.is_none() => time_left,
    _ => self.lease_duration(requested_lease),
};
```

src/iface/dhcpv4_server.rs:699 writes `&duration.as_secs().to_be_bytes()`. `as_secs` truncates, so 600 ms becomes 0.

src/iface/dhcpv4_server.rs:584: the ACK uses `self.lease_duration(...)` and ignores the time left, which extends the lease.

Related: a `DhcpServerConfig::lease_duration` below 1 s, including zero, is accepted. It gives ACKs with lease time 0 and a Bound record that is inactive at once.

## Failure scenario
A client whose lease is about to end reboots and sends DISCOVER. It gets an OFFER with lease 0. Some clients reject it and retry. One that accepts it then gets an ACK with a full lease, contradicting the OFFER.

## RFC reference
RFC 2131 §4.3.1: "IF the client has not requested a specific lease in the DHCPDISCOVER message and the client already has an assigned network address, the server returns the lease expiration time previously assigned to that address (note that the client must explicitly request a specific lease to extend the expiration time on a previously assigned address)"

RFC 2131 §4.3.2: "Any configuration parameters in the DHCPACK message SHOULD NOT conflict with those in the earlier DHCPOFFER message"

Both are SHOULD-level or non-normative.

## Reproduction
Scratch test `vv_f5_offer_zero` in the dhcpv4_server test module: `bind_first_client` at t=0 (Bound until 301 s, lease 300 s). DISCOVER polled at 300.6 s, then a SELECTING REQUEST at 300.7 s.

```
F5 offer lease = Some([0, 0, 0, 0])
F5 ack type Ack lease = Some([0, 0, 1, 44])
```

## Suggested fix
Round the remaining time up to at least 1 s, or offer `lease_duration` when little remains. Make the ACK match the OFFER, or always offer `lease_duration`. Reject a `lease_duration` below 1 s in `set_dhcpv4_server`.
