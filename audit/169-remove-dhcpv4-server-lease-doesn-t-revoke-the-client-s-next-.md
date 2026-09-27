# 169. remove_dhcpv4_server_lease doesn't revoke: the client's next renewal is ACKed again

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:612](../src/iface/mod.rs#L612), [src/iface/dhcpv4_server.rs:300](../src/iface/dhcpv4_server.rs#L300), [src/iface/dhcpv4_server.rs:573](../src/iface/dhcpv4_server.rs#L573) |
| Features | dhcpv4-server |
| Verification | confirmed against the code |

## Summary
The doc says the client "keeps using the address until it next renews", which implies the renewal fails. It doesn't. The RENEWING REQUEST hits the "no record but the address is free" arm and gets an ACK with a fresh Bound record. Removal only takes the address away if another client grabs it first.

## Details
src/iface/mod.rs:615:
```rust
/// The client is not told: it keeps using the address until it next renews.
```

`remove_lease` (src/iface/dhcpv4_server.rs:300) only drops the record. For the renewal (ciaddr set, no server id), `find_by_client` returns `None`, and src/iface/dhcpv4_server.rs:573 matches:
```rust
None if self.in_pool(addr) && self.available_for(addr, id, now) => Answer::Ack,
```
This arm is deliberate: it is how leases survive a server reboot. The problem is the doc.

## Failure scenario
An operator removes a client's lease to kick it off. At T1 the client renews and gets a full new lease. The removal had no effect.

## Suggested fix
Document that removal only frees the address and that a client still online gets it back on renewal. If revocation is wanted, keep a tombstone that makes the next REQUEST get a NAK.
