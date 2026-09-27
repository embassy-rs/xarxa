# 159. A DHCP address change drops every parked packet and neighbor entry on the interface, IPv6 included

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/dhcpv4.rs:865](../src/iface/dhcpv4.rs#L865), [src/stack.rs:143](../src/stack.rs#L143) |
| Features | default (`dhcpv4`) |
| Verification | confirmed against the code |

## Summary
`dhcpv4_apply` calls `purge_iface_link_state` whenever the leased address changes, including the first bind and lease loss. That clears all neighbor entries (ARP and NDISC) of the interface and drops all packets parked on it. UDP datagrams whose send returned `Ok` are lost, which contradicts DESIGN §7. IPv6 state is unrelated to the IPv4 lease.

## Details
src/iface/dhcpv4.rs:865:
```rust
inner.purge_iface_link_state(self.handle);
```
src/stack.rs:143-150 does:
```rust
self.neighbor_cache.clear_iface(handle);
self.pending.purge_iface(handle);
```
Both filter only on the interface (src/neighbor.rs:401-402, 544-545), not on address family or subnet. Parked IPv4 packets whose next hop is still valid on the new subnet are dropped too.

## Failure scenario
At boot the application sends a UDP datagram to an IPv6 link-local peer. `send` returns `Ok` and the packet parks on NDISC. The DHCPv4 ACK arrives before resolution completes. The parked datagram and the Incomplete entry are silently dropped.

## Suggested fix
Purge only IPv4 neighbor entries and IPv4 parked packets, or only those no longer on-link after the change.
