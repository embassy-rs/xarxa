# 195. NeighborCache::remove/retain/clear docs misdescribe the fate of parked packets

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/neighbor.rs:372](../src/neighbor.rs#L372), [src/stack.rs:2391](../src/stack.rs#L2391) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The docs say packets parked on a removed Incomplete entry "are dropped when their own timeout expires, a few seconds later". The pending queue is keyed by `(iface, addr)`, not by entry. So the packets are still flushed if the neighbor's ARP arrives, or if a later send restarts resolution.

## Details
src/neighbor.rs:369-372: "Removing an entry whose resolution is still in progress leaves the packets parked on it waiting: they are dropped when their own timeout expires, a few seconds later."

src/stack.rs:2391-2397
```rust
fn fill_neighbor(...) {
    let key = (iface.handle, addr);
    self.neighbor_cache.fill(key, hardware_addr, self.now);
    let _ = self.flush_pending(iface, &key, hardware_addr);
}
```
- IPv4: `process_arp` calls `fill_neighbor` for any ARP request or reply from an on-subnet source, entry or not (src/stack.rs:2211-2219).
- IPv6: an NS with a source link-layer option (src/stack.rs:2264) or an RA from that router (slaac.rs:441) also calls `fill_neighbor`. Only an NA for an unknown target is discarded (src/stack.rs:2342-2346).
- A new send to the address restarts resolution. The old packets then flush, or get ICMP errors, with the new ones.

## Failure scenario
A user removes an in-progress entry to stop traffic to a host. The host's ARP reply arrives 100 ms later and the parked packets are sent anyway.

## Suggested fix
Purge pending packets for the key in `remove`/`retain`/`clear`, or document the actual behavior.
