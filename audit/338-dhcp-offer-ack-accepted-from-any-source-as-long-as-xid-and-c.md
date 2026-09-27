# 338. DHCP ACK in REQUESTING is not checked against the selected server identifier

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/iface/dhcpv4.rs:649](../src/iface/dhcpv4.rs#L649), [src/iface/dhcpv4.rs:611](../src/iface/dhcpv4.rs#L611) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the code |

## Summary
`dhcpv4_process` accepts an OFFER from any source once magic, hardware type, chaddr and xid match. In REQUESTING, the ACK's server identifier is parsed but never compared with the server the client selected. The first matching ACK wins. This is hardening only: DHCP has no authentication, and an attacker who sees the broadcast DISCOVER can forge the server identifier too.

## Details
src/iface/dhcpv4.rs:611 parses `server_identifier` from every message. src/iface/dhcpv4.rs:649-651:
```rust
(ClientState::Requesting(state), DhcpMessageType::Ack) => {
    let Some((lease, renew_at, rebind_at, expires_at)) =
        Client::parse_ack(now, &packet, max_lease_duration, state.server)
```
`server_identifier` is not compared with `state.server.identifier`.

## Failure scenario
An attacker who knows the xid sends a forged ACK with the victim's chaddr and its own gateway and DNS. The client installs it. An off-path attacker would otherwise also need to guess the server's address, which is usually easy.

## RFC reference
RFC 2131 has no explicit MUST for this check in REQUESTING. The client records the server identifier from the selected OFFER (§4.4.1).

## Suggested fix
Drop an ACK in REQUESTING whose server identifier differs from the selected server. Cheap, but it does not stop an on-link attacker.
