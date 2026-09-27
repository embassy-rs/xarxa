# 155. No duplicate-address check, no DHCPDECLINE and no ARP announcement after binding

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:663](../src/iface/dhcpv4.rs#L663), [src/iface/dhcpv4.rs:850](../src/iface/dhcpv4.rs#L850) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the RFC text |

## Summary
On ACK the address is installed immediately. The client does not ARP-probe it, has no DHCPDECLINE builder, and sends no gratuitous ARP. Conflicts go unnoticed and peers keep stale ARP entries. README and DESIGN don't list this for the client (DESIGN §10 only mentions the server not probing).

## Details
The Requesting ACK arm (lines 650-662) sets the state to Renewing and calls `dhcpv4_apply`. `dhcpv4_apply` (line 850) transmits nothing. The probe and announcement are SHOULDs. The DECLINE MUST only applies after a detected conflict, which never happens.

## Failure scenario
A static host already uses the address the server hands out. Both answer ARP, and connections to the device break intermittently. The server is never told. After a lease change, peers with a cached old MAC send to the wrong host until their entries expire.

## RFC reference
RFC 2131 §4.4.1: "The client SHOULD perform a check on the suggested address to ensure that the address is not already in use. ... If the network address appears to be in use, the client MUST send a DHCPDECLINE message to the server. The client SHOULD broadcast an ARP reply to announce the client's new IP address and clear any outdated ARP cache entries in hosts on the client's subnet."

## Suggested fix
Optionally ARP-probe (RFC 5227 style) before installing, send DHCPDECLINE on conflict, and send a gratuitous ARP after binding. Or list it under "Not yet implemented".
