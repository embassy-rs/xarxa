# 147. REQUEST carrying our server identifier plus ciaddr but no requested-IP is silently dropped

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/dhcpv4_server.rs:546](../src/iface/dhcpv4_server.rs#L546), [src/iface/dhcpv4_server.rs:553](../src/iface/dhcpv4_server.rs#L553) |
| Features | dhcpv4-server |
| Verification | reproduced with a test |

## Summary
A server identifier alone classifies a REQUEST as SELECTING, and then ciaddr is never used. A renewal that carries option 54 (ours) and ciaddr but no option 50 is dropped as malformed. The client is the one breaking RFC 2131, so this is an interop issue affecting only non-conformant clients.

## Details
src/iface/dhcpv4_server.rs:546:
```rust
let selecting = server_id.is_some();
let addr = if let Some(addr) = requested {
    addr
} else if !selecting && ciaddr != Ipv4Addr::UNSPECIFIED {
    ciaddr
} else {
    trace!("DHCP server: malformed REQUEST from {}", chaddr);
    return None;
};
```
The server already knows the server id is its own and could handle the request as a renewal.

## Failure scenario
A client that includes option 54 in unicast renewals gets no answer. It retries until T2, rebinds (again unanswered if it keeps option 54), loses the address at lease expiry and restarts from DISCOVER, dropping its connections.

## RFC reference
RFC 2131 §4.3.2, DHCPREQUEST generated during RENEWING state: "'server identifier' MUST NOT be filled in, 'requested IP address' option MUST NOT be filled in, 'ciaddr' MUST be filled in".

## Reproduction
Scratch test `vv_f7_renew_with_sid` in the dhcpv4_server test module: `bind_first_client`, then `Msg::new(Request, CLIENT_HW).unicast_from(POOL_START).server_id(SERVER_IP)` at t=100.

```
F7 replies 0
```

## Suggested fix
When the server id is ours and no requested-IP option is present, fall back to ciaddr and handle it as a renewal.
