# 223. Link-up throws away a still-valid DHCP lease at once, breaking live traffic during rediscovery

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:1133](../src/stack.rs#L1133), [src/iface/dhcpv4.rs:834](../src/iface/dhcpv4.rs#L834), [src/iface/dhcpv4.rs:717](../src/iface/dhcpv4.rs#L717), [src/dns.rs:614](../src/dns.rs#L614) |
| Features | dhcpv4 (default) |
| Verification | confirmed against the code |

## Summary
On every Down to Up edge, `poll` calls `dhcpv4_reset`. If the client was bound, this removes the leased address and default route at once, purges the interface's neighbor cache and parked packets, and restarts from a DISCOVER that does not request the old address. During rediscovery TCP segments are dropped under RTO backoff, UDP sends fail, and `DnsClient` queries fail permanently.

## Details
src/iface/dhcpv4.rs:834-845:
```rust
let old = core::mem::replace(&mut client.state, ClientState::Discovering(...));
if let ClientState::Renewing(state) = old {
    self.dhcpv4_apply(inner, None, Some(state.lease.installed()));
}
```
`dhcpv4_apply` removes `AddrOrigin::Dhcpv4` addresses, calls `purge_iface_link_state` and removes the DHCP route. The DISCOVER (src/iface/dhcpv4.rs:717-730) passes `requested_ip = None`.

Effects:
- TCP: the source is no longer ours, so segments are dropped at emit while the RTO doubles.
- UDP: `Unaddressable`. `DnsClient::dispatch` treats it as permanent and fails the query (src/dns.rs:614-620).
- If the server assigns a different address, pinned sockets never recover. TCP sockets with a timeout fail at the timeout.

A client that was still Discovering or Requesting just restarts. The reset is deliberate ("The link may have moved to a different network").

## Failure scenario
A link bounces for 1 s during a TCP upload and a DNS lookup. On link-up the address is gone until DISCOVER/OFFER/REQUEST/ACK completes, which takes seconds if the server ping-checks. The DNS query fails and TCP stalls in backoff.

## RFC reference
RFC 2131 §3.2: "If a client remembers and wishes to reuse a previously allocated network address, a client may choose to omit some of the steps described in the previous section."

RFC 2131 §4.4.2 (INIT-REBOOT only, which this client never uses): "The client MUST insert its known network address as a 'requested IP address' option".

Reuse is optional, so this is not an RFC violation. Common clients (dhcpcd, systemd-networkd) keep or re-request the address after a carrier bounce.

## Suggested fix
On link-up keep the lease installed and verify it with an INIT-REBOOT REQUEST carrying requested-IP, or at least put requested-IP in the DISCOVER. Uninstall only on NAK, expiry, or failed verification.
