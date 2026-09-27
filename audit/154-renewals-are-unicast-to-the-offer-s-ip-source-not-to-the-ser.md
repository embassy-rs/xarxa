# 154. Renewals are unicast to the OFFER's IP source, not to the server identifier

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:643](../src/iface/dhcpv4.rs#L643), [src/iface/dhcpv4.rs:788](../src/iface/dhcpv4.rs#L788) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the RFC text |

## Summary
On an OFFER the client stores `server.address = src_ip` and unicasts RENEWING requests there. Behind a relay, that is the relay's address, not the server's. The RFC requires the server identifier. Renewal then often succeeds only at T2 via broadcast rebind. This is a documented choice (DhcpServerInfo doc, comment at lines 630-631), inherited from smoltcp.

## Details
src/iface/dhcpv4.rs:642-645:
```rust
server: DhcpServerInfo {
    address: src_ip,
    identifier: server_identifier,
},
```
src/iface/dhcpv4.rs:785-789:
```rust
let dst_addr = if state.rebinding {
    Ipv4Addr::BROADCAST
} else {
    state.lease.server.address
};
```
The comment at line 630-631 cites RFC 2131 §4.1 as justification, but that section requires the opposite.

## Failure scenario
The server is behind a relay. OFFER/ACK come from 192.168.1.254 with server identifier 192.168.1.1. At T1 the client ARPs for 192.168.1.254 and sends the renewal to the relay. A helper-address relay usually drops it (ISC dhcrelay forwards it). The lease is only extended at T2.

## RFC reference
RFC 2131 §4.1: "DHCP clients MUST use the IP address provided in the 'server identifier' option for any unicast requests to the DHCP server."

RFC 2132 §9.7: "DHCP clients use the contents of the 'server identifier' field as the destination address for any DHCP messages unicast to the DHCP server."

RFC 2131 §4.3.2: "This message will be unicast, so no relay agents will be involved in its transmission."

## Suggested fix
Unicast renewals to the server identifier. Drop `address`, or keep it only as a fallback.
