# 047. Neighbor cache eviction defeats per-neighbor solicitation rate limiting

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/neighbor.rs:422](../src/neighbor.rs#L422), [src/stack.rs:2512](../src/stack.rs#L2512), [src/stack.rs:2340](../src/stack.rs#L2340), [src/config.rs:82](../src/config.rs#L82) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The only solicitation rate limit is the `retrans_at` timer of each cache entry. When more neighbors are in use than `NEIGHBOR_CACHE_COUNT` (8 by default), entries are evicted and that state is lost. The next send to an evicted neighbor starts a fresh resolution with an immediate ARP request or NS. A round-robin over 9 on-link destinations sent 6 to 9 ARP requests per destination per second, and every packet missed the cache. Evicting an Incomplete entry also strands its parked packets.

## Details
src/stack.rs:2512, on every cache miss:
```rust
NeighborAnswer::NotFound => {}
}

// Start resolving: create the INCOMPLETE entry and send the first solicitation.
debug!("address {} not in neighbor cache, sending solicitation", next_hop);
self.neighbor_cache.start_resolution((iface.handle, next_hop), self.now);
self.solicit_neighbor(iface, next_hop);
```
src/neighbor.rs:422, `insert_state` on a full cache evicts Stale first, then the Reachable entry with the nearest `expires_at`, then the Incomplete entry with the nearest `retrans_at`:
```rust
let rank = match state {
    State::Stale { .. } => (0u8, Instant::ZERO),
    State::Reachable { expires_at, .. } => (1u8, *expires_at),
    State::Incomplete { retrans_at, .. } => (2u8, *retrans_at),
};
```
Nothing remembers that an address was solicited once its entry is gone. With a cyclic access pattern over N+1 neighbors, the evicted entry is the one about to be used next, so every send misses and solicits.

Evicting an Incomplete entry has two more effects:
- Its parked packets stay in the pending queue with no entry. No ICMP error is generated. They expire silently after `PENDING_QUEUE_LIFETIME` (5 s).
- For IPv6, the NA that arrives later is dropped as "advertisement for unknown target" (src/stack.rs:2340), so it does not flush them either.

With live neighbors this is also a performance cliff: every packet parks, broadcasts, and waits one RTT.

## Failure scenario
- A Modbus/TCP or UDP poller in a default build talks round-robin to 9 on-link devices. Every request broadcasts an ARP request, and every request waits for a fresh resolution.
- An on-link attacker pings the device from 9 or more spoofed on-link sources in turn. Each echo reply is routed, misses the cache, and triggers a broadcast ARP request, several per second for the same address. Amplification is about 1:1.

## RFC reference
RFC 1122 §2.3.2.1:
> A mechanism to prevent ARP flooding (repeatedly sending an ARP Request for the same IP address, at a high rate) MUST be included. The recommended maximum rate is 1 per second per destination.

RFC 4861 §7.3.3:
> A node MUST NOT send Neighbor Solicitations to the same neighbor more frequently than once every RetransTimer milliseconds.

For ARP the MUST is that a mechanism exists. It exists, but eviction defeats it. The 1/s rate is recommended. For NDISC the rate is itself a MUST NOT.

## Reproduction
Test in the `src/stack.rs` test module (the ARP target is parsed out of each transmitted request and counted):
```rust
#[test]
fn verify_neighbor_thrash_arp_flood() {
    let (mut stack, _rx, tx, _room) = test_stack_with_room(Medium::Ethernet);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let n = crate::neighbor::NEIGHBOR_CACHE_COUNT as u8 + 1;
    let mut t = 0u32;
    for _round in 0..20 {
        for i in 0..n {
            let dst = Ipv4Addr::new(192, 168, 1, 10 + i);
            let _ = stack.udp_socket(udp).send_slice(b"x", (dst, 1000));
        }
        t += 50;
        stack.poll(Instant::from_millis(t));
    }
    // count ARP requests per target in `tx`, assert max <= 2
}
```
Output:
```
NEIGHBOR_CACHE_COUNT=8
ARP requests in 1000 ms: {192.168.1.10: 7, 192.168.1.11: 6, 192.168.1.12: 6, 192.168.1.13: 7, 192.168.1.14: 7, 192.168.1.15: 7, 192.168.1.16: 8, 192.168.1.17: 8, 192.168.1.18: 9}
```

## Suggested fix
- Do not evict an Incomplete entry to start a new resolution. Drop or refuse the new packet instead.
- Or keep a small per-address "last solicited" record that survives eviction, and do not solicit again within `RETRANS_TIMER`.
- Consider evicting by last use (LRU) rather than by nearest expiry, and a larger default cache.
