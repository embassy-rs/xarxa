# 151. Lease timers start at ACK arrival, not when the DHCPREQUEST was sent

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:450](../src/iface/dhcpv4.rs#L450), [src/iface/dhcpv4.rs:623](../src/iface/dhcpv4.rs#L623) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`parse_ack` computes renew, rebind and expiry times from `inner.now` at ACK reception. RFC 2131 says to measure from when the REQUEST was sent. `RequestState` and `RenewState` store no send time. Usually the error is just one-way latency. It grows to the retransmit gap when a late ACK answers an earlier REQUEST with the same xid.

## Details
src/iface/dhcpv4.rs:623: `let now = inner.now;`

src/iface/dhcpv4.rs:450-452:
```rust
let renew_at = now + renew_duration;
let rebind_at = now + rebind_duration;
let expires_at = now + lease_duration;
```
The worst-case offset is bounded by the REQUEST retry schedule (5, 5, 10, 10, 20 s).

## Failure scenario
Lease of 60 s. The ACK to the first REQUEST is delayed several seconds at a relay, or answers the first REQUEST after later retransmissions. The client keeps using the address after the server considers the lease expired, and the server may have given it away.

## RFC reference
RFC 2131 §4.4.1: "The client records the lease expiration time as the sum of the time at which the original request was sent and the duration of the lease from the DHCPACK message."

RFC 2131 §4.4.5: "the client computes the lease expiration time as the sum of the time at which the client sent the DHCPREQUEST message and the duration of the lease in the DHCPACK message."

## Suggested fix
Record when the first REQUEST of the transaction was sent and compute the timers from it.
