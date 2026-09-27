# 156. After rebinding to a different server, the lease keeps the old server

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/dhcpv4.rs:667](../src/iface/dhcpv4.rs#L667), [src/iface/dhcpv4.rs:788](../src/iface/dhcpv4.rs#L788) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the code |

## Summary
An ACK in RENEWING/REBINDING is parsed with `state.lease.server`, ignoring its server identifier and source. If server B answers a rebind broadcast after A died, later T1 renewals still go to A and fail until T2 every cycle. `DhcpLease::server` keeps reporting A. The Requesting arm also accepts an ACK whose server identifier differs from the selected server.

## Details
src/iface/dhcpv4.rs:665-667:
```rust
(ClientState::Renewing(state), DhcpMessageType::Ack) => {
    let Some(...) =
        Client::parse_ack(now, &packet, max_lease_duration, state.lease.server)
```
Because the server field is copied from the old lease, the `state.lease != lease` change check cannot see a server change either. The renewal destination at line 788 is `state.lease.server.address`.

## Failure scenario
Server A is decommissioned and B takes over the pool. The client rebinds to B at T2. Each following cycle, T1 renewals go unanswered to A, and the lease is only extended by broadcast at T2. 3/8 of every lease runs degraded.

## RFC reference
RFC 2131 §4.4.5: "T1 is the time at which the client enters the RENEWING state and attempts to contact the server that originally issued the client's network address."

## Suggested fix
In the Renewing ACK arm, take the server info from the ACK. In Requesting, drop ACKs whose server identifier is not `state.server.identifier`.
