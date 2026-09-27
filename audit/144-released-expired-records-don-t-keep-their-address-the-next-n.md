# 144. Released/Expired records don't keep their address: the next new client takes it even when the pool has unused addresses

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/dhcpv4_server.rs:372](../src/iface/dhcpv4_server.rs#L372), [src/iface/dhcpv4_server.rs:143](../src/iface/dhcpv4_server.rs#L143), [src/iface/dhcpv4_server.rs:320](../src/iface/dhcpv4_server.rs#L320), [src/iface/dhcpv4_server.rs:591](../src/iface/dhcpv4_server.rs#L591) |
| Features | dhcpv4-server |
| Verification | reproduced with a test |

## Summary
The docs of `DhcpServerLeaseState::Released` and `Expired` say the record is "Kept as a record so a returning client gets the same address". The free scan in `pick_addr` takes the lowest address with no *active* lease, which is usually the one just released. The ACK path then deletes the old holder's record. A returning client loses its address as soon as any new client comes by, while higher pool addresses were never used.

## Details
src/iface/dhcpv4_server.rs:320: `available_for` only considers `lease.is_active(now)`, so inactive records do not block an address.

src/iface/dhcpv4_server.rs:372:
```rust
for bits in self.config.pool_start.to_bits()..=self.config.pool_end.to_bits() {
    let addr = Ipv4Addr::from_bits(bits);
    if addr_valid(addr, server_cidr) && self.available_for(addr, id, now) {
        return Some(addr);
    }
}
```

src/iface/dhcpv4_server.rs:591:
```rust
self.leases.retain(|l| l.address != addr || l.matches_client(id));
```

RFC 2131 §4.3.1 prefers the previous address only "if that address is in the server's pool of available addresses and not already allocated", so once another client holds it the server is within the RFC. The problem is the public doc promise and the needless reuse while unused addresses exist (§2 describes reuse of expired addresses as an exhaustion measure).

## Failure scenario
Pool 192.168.1.10-200. Device A is bound to .10, then releases it (or its lease expires). Phone B joins and gets .10. A returns and gets .11. .12-.200 were never used.

## Reproduction
Scratch test `vv_f4_sticky` in the dhcpv4_server test module (pool .10-.200): `bind_first_client`, RELEASE from .10, DISCOVER and REQUEST from `CLIENT2_HW`, then DISCOVER from `CLIENT_HW`.

```
F4 client2 got 192.168.1.10, returning client1 offered 192.168.1.11
```

## Suggested fix
In the free scan, prefer addresses no record references, and fall back to the oldest inactive record's address. Or change the docs to say the address is kept only while nobody else needs it.
