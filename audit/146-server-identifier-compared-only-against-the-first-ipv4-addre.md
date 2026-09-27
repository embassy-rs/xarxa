# 146. Server identifier compared only against the first IPv4 address

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4_server.rs:537](../src/iface/dhcpv4_server.rs#L537) |
| Features | dhcpv4-server |
| Verification | reproduced with a test |

## Summary
A SELECTING REQUEST whose server identifier is one of our addresses other than the interface's first IPv4 address is treated as choosing another server. The record is marked Released and no reply is sent. The server always advertises its first address, so this only triggers when that address changes between OFFER and REQUEST, or with an odd client.

## Details
src/iface/dhcpv4_server.rs:537:
```rust
if server_id.is_some_and(|s| s != server_cidr.address()) {
    // The client selected another server ...
    self.leases[i].state = DhcpServerLeaseState::Released;
    return None;
}
```
The hook's `for_us` check accepts every address of the interface, so the two checks disagree.

## Failure scenario
Interface has 192.168.1.1/24 and 192.168.1.2/24. An OFFER goes out with server-id .1. The application removes .1 before the REQUEST arrives. The REQUEST naming .1 is treated as foreign, the lease is Released, and the client times out and restarts discovery.

## RFC reference
RFC 2131 §4.1: "A server with multiple network addresses (e.g., a multi-homed host) MUST be prepared to to accept any of its network addresses as identifying that server in a DHCP message."

## Reproduction
Scratch test `vv_f6_second_addr` in the dhcpv4_server test module: add 192.168.1.2/24, DISCOVER, then REQUEST with `server_id(192.168.1.2)` and `requested_ip(POOL_START)`.

```
F6 replies 0, state Released
```

## Suggested fix
Treat the server identifier as ours if it is any IPv4 address of the interface (`has_ip_addr`).
