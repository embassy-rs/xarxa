# 143. DHCP server pool is not validated against the subnet; a large out-of-subnet pool makes every DISCOVER scan up to 2^32 addresses

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/iface/dhcpv4_server.rs:372](../src/iface/dhcpv4_server.rs#L372), [src/iface/mod.rs:590](../src/iface/mod.rs#L590) |
| Features | `dhcpv4-server` |
| Verification | reproduced with a test |

## Summary
The documented precondition that the pool is inside the subnet is checked neither by `set_dhcpv4_server` nor when the interface is renumbered. `pick_addr`'s fallback walks the whole pool, skipping out-of-subnet addresses. With a pool much larger than the subnet and no free in-subnet address, every DISCOVER scans the whole pool inside `Stack::poll`. A remote host can then keep the CPU busy by sending DISCOVERs.

## Details
src/iface/dhcpv4_server.rs:369-377
```rust
// Bounded: there are at most DHCP_SERVER_LEASE_COUNT active leases, so a
// pool inside the subnet yields a free address within that many steps
// (plus the handful of reserved addresses), or is exhausted.
for bits in self.config.pool_start.to_bits()..=self.config.pool_end.to_bits() {
    let addr = Ipv4Addr::from_bits(bits);
    if addr_valid(addr, server_cidr) && self.available_for(addr, id, now) {
        return Some(addr);
    }
}
```
src/iface/mod.rs:590-595 checks only `pool_start <= pool_end`. The served subnet is the interface's first IPv4 address, and the public doc says "its subnet" without saying which one. Cost is linear in pool size: a /16 pool on a /24 is about 65k iterations times the lease table scan, milliseconds on an MCU. Only a full 2^32 pool reaches minutes.

## Failure scenario
The user configures pool 10.0.0.2..=10.0.255.254 with the interface at 10.0.0.1/24. Once the in-subnet addresses are taken (or all 8 lease slots are held, see 142), each DISCOVER from a new client scans about 65k addresses. A DISCOVER flood keeps `poll` busy. Renumbering the interface to another subnet has the same effect, and the server silently stops offering.

## Reproduction
Scratch test `vv_f3_scan` in `src/iface/dhcpv4_server.rs` `mod test` (debug build, host): interface 192.168.1.1/30, pool 192.168.1.2..192.169.255.255 (about 131k addresses), `CLIENT_HW` bound to .2, then a timed DISCOVER from `CLIENT2_HW`.
```
F3 scan of ~131k addresses took 2.363716ms, replies 0
```

## Suggested fix
Clamp the scan range to the intersection of the pool and the served subnet. Optionally reject an out-of-subnet pool in `set_dhcpv4_server` when an IPv4 address exists.
