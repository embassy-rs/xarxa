# 162. set_hardware_addr silently replaces the link-local address and flushes neighbor state, even for the same MAC

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:345](../src/iface/mod.rs#L345), [src/iface/mod.rs:452](../src/iface/mod.rs#L452), [src/stack.rs:143](../src/stack.rs#L143) |
| Features | `ipv6` plus `medium-ethernet` or `medium-ieee802154` (default) |
| Verification | confirmed against the code |

## Summary
With IPv6 on Ethernet or 802.15.4, `set_hardware_addr` removes the automatic link-local address, adds a new one, and calls `invalidate()`. That clears the interface's neighbor cache and drops every parked packet, of both families. It does this even when the address is unchanged. None of it is documented.

## Details
src/iface/mod.rs:349:
```rust
self.state_mut().hardware_addr = addr;
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
{
    let had = self.state_mut().remove_ip_addrs(AddrOrigin::LinkLocal);
    if let Some(ll) = link_local_addr(addr) {
        if self.state_mut().ip_addrs.push(ll).is_err() { ... }
        self.invalidate();
```
src/stack.rs:147:
```rust
self.neighbor_cache.clear_iface(handle);
self.pending.purge_iface(handle);
```
Consequences not in the doc:
- A TCP connection on the old fe80:: address fails the `has_ip_addr` source check in dispatch. Its segments are dropped with no error until a timeout fires.
- Parked UDP datagrams that `send` reported as `Ok` are dropped. That breaks the DESIGN §7 promise.
- Solicited-node groups change and MLD reports go out.
- The link-local entry moves to the end of `ip_addrs`.

In IPv4-only builds nothing is flushed.

## Failure scenario
The app re-applies the MAC from flash on every reconnect with the same value. Each call drops the whole neighbor cache and any parked datagrams. The finder confirmed this in a test: a UDP datagram parked on an unresolved IPv4 neighbor is gone after a same-MAC `set_hardware_addr`, and only the ARP reply goes out when the ARP arrives.

## Suggested fix
Return early when the address is unchanged. Document that the link-local address is re-derived and that neighbor state and parked packets are flushed.
