# 142. The lease table (8 slots by default) is exhausted by 8 spoofed DISCOVERs a minute, or 8 DISCOVER+DECLINE pairs per 10 minutes

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/iface/dhcpv4_server.rs:340](../src/iface/dhcpv4_server.rs#L340), [src/iface/dhcpv4_server.rs:416](../src/iface/dhcpv4_server.rs#L416) |
| Features | `dhcpv4-server` |
| Verification | reproduced with a test |

## Summary
Each DISCOVER from a new chaddr creates an Offered entry that holds a slot for 60 s, and `entry_for` reuses only inactive slots. With `DHCP_SERVER_LEASE_COUNT = 8`, 8 spoofed DISCOVERs a minute lock out every new client. A DECLINE is accepted for a lease that is only Offered, with no server id check, which turns the slot into a 10-minute hold. Starvation is inherent to unauthenticated DHCP. The issue is how few packets it takes.

## Details
src/iface/dhcpv4_server.rs:340
```rust
let i = self.leases.iter().position(|l| !l.is_active(now))?;
```
src/iface/dhcpv4_server.rs:416-423
```rust
if let Some(i) = self.find_by_client(&id)
    && self.leases[i].address == addr
{
    ...
    self.leases[i].state = DhcpServerLeaseState::Declined {
        expires_at: now + DECLINE_TIMEOUT,
    };
}
```
Keeping offers for 60 s is allowed by RFC 2131 §4.3.2. What is missing is an eviction policy when the table is full. The flood also overwrites inactive (Released/Expired) records of real clients, which defeats address stickiness. Bound leases are safe.

## Failure scenario
On an open segment served by xarxa, an attacker broadcasts 8 DISCOVERs with random chaddrs, then 8 DECLINEs, every 10 minutes. No new device gets an address. Clients with active leases can still renew.

## Reproduction
Scratch test `vv_f2_table_exhaust` in `src/iface/dhcpv4_server.rs` `mod test`: widen the pool to .10-.200, send `DHCP_SERVER_LEASE_COUNT` DISCOVERs from chaddr 02:00:00:00:01:i, then a DISCOVER from `CLIENT_HW`. Then DECLINE one Offered address, and retry at t=70 s.
```
F2 lease count = 8
F2 replies to new client after 8 spoofed discovers: 0
F2 state after decline of offered: Declined { expires_at: Instant { millis: 302000 } }
F2 replies at t=70: 1
```

## Suggested fix
- Accept DECLINE only for Bound leases.
- When the table is full, let a new DISCOVER evict the oldest Offered entry.
- Document the exposure next to `DHCP_SERVER_LEASE_COUNT`.
