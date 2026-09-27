# 231. Echoes from spoofed on-link sources evict real neighbor cache entries

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/neighbor.rs:422](../src/neighbor.rs#L422), [build.rs:15](../build.rs#L15) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Each echo request from a new on-link source makes the reply start neighbor resolution, which inserts an Incomplete entry. With the default 8-entry cache, 8 spoofed sources evict a real Reachable entry, and each one triggers a broadcast ARP. The cost is bounded: the evicted neighbor is re-resolved on next use, and an on-link attacker has stronger attacks anyway.

## Details
The echo reply is routed and transmitted, which parks it and calls `start_resolution` for the spoofed source. `insert_state` (src/neighbor.rs:422) ranks Stale first, then Reachable by nearest expiry, then Incomplete, and overwrites the lowest rank. `NEIGHBOR_CACHE_COUNT` is 8 (build.rs:15). `reset_expiry_if_existing` never inserts and is not part of the mechanism.

## Failure scenario
An on-link attacker pings from many spoofed source IPs in the subnet. Real entries such as the gateway's are evicted and re-resolved, adding latency. Each spoofed ping also causes one ARP broadcast.

## Reproduction
Test in a scratch copy of `src/stack.rs` `mod test`:
```rust
#[test]
#[cfg(feature = "medium-ethernet")]
fn vv_neighbor_flood() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    inject(&mut stack, &rx, arp_request_from(OTHER_HW, REMOTE_V4));
    assert!(stack.neighbor_cache().get(iface, REMOTE_V4.into()).is_some());
    tx.borrow_mut().clear();
    for i in 0..8u8 {
        let src = Ipv4Addr::new(192, 168, 1, 100 + i);
        let req = icmpv4_echo(Icmpv4Message::EchoRequest, 1, 1, b"x");
        let pkt = ipv4_packet(src, OUR_V4, IpProtocol::Icmp, &req);
        inject(&mut stack, &rx, eth_frame_from(EthernetAddress([0x02,0,0,0,1,i]), OUR_HW, EthernetProtocol::Ipv4, &pkt));
    }
    std::println!("REMOTE_V4 entry after flood: {:?}, solicitations: {}", stack.neighbor_cache().get(iface, REMOTE_V4.into()), tx.borrow().len());
    assert!(stack.neighbor_cache().get(iface, REMOTE_V4.into()).is_none());
}
```
Output:
```
REMOTE_V4 entry after flood: None, solicitations: 8
ok
```

## Suggested fix
Protect in-use Reachable entries, such as a default route's next hop, from eviction by new Incomplete entries. Or cap how many Incomplete entries replies to unresolved sources may create.
