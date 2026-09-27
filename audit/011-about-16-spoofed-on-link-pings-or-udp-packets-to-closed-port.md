# 011. About 16 spoofed on-link pings (or UDP packets to closed ports) fill the whole packet pool for 3 to 5 s

| | |
|---|---|
| Severity | high |
| Category | security |
| Location | [src/stack.rs:2714](../src/stack.rs#L2714), [src/stack.rs:2731](../src/stack.rs#L2731), [src/neighbor.rs:492](../src/neighbor.rs#L492), [src/neighbor.rs:422](../src/neighbor.rs#L422), [build.rs:16](../build.rs#L16), [xarxa-driver/build.rs:9](../xarxa-driver/build.rs#L9) |
| Features | default |
| Verification | reproduced with a test |

## Summary

Packets for an unresolved next hop are parked in the pending queue. The queue has only a global bound, `PENDING_QUEUE_COUNT`, which defaults to 16. That equals the default `PACKET_BUF_COUNT`. One echo request (or UDP packet to a closed port) from each of 16 fake on-link addresses parks 16 replies and empties the pool. Until the buffers come back the stack can neither receive nor send.

## Details

The echo reply is built in the request's own buffer ([src/stack.rs:1576](../src/stack.rs#L1576)). It goes through `route_reply`, `transmit_ip` and `dispatch_ip`. For an on-link source not in the cache, `lookup_hardware_addr` returns `Pending` and the buffer is parked.

src/stack.rs:2712
```rust
NeighborLookup::Pending { next_hop } => {
    debug!("neighbor {} pending, queing packet", next_hop);
    self.pending.push((iface.handle, next_hop), buf, self.now);
}
```

The 802.15.4 arm does the same at line 2731. `PendingQueue::push` drops the oldest packet only once the global queue is full. There is no per-neighbor bound.

src/neighbor.rs:497
```rust
if let Err(packet) = self.packets.push(packet) {
    trace!("neighbor: pending queue full, dropping oldest packet");
    self.packets.remove(0);
    unwrap!(self.packets.push(packet).map_err(|_| Full));
}
```

Defaults: `("PENDING_QUEUE_COUNT", 16)` (build.rs:16), `("PACKET_BUF_COUNT", 16)` (xarxa-driver/build.rs:9). So the pool runs out before the queue does.

Parked buffers are freed when resolution fails (`MAX_MULTICAST_SOLICIT` = 3 probes, `RETRANS_TIMER` = 1 s, so about 3 s) or when `PENDING_QUEUE_LIFETIME` (5 s) runs out. With 16 distinct sources and the 8-entry neighbor cache, `insert_state` (src/neighbor.rs:422) evicts Incomplete entries. Packets parked on an evicted entry never see a failure event and sit for the full 5 s.

The same path is taken by ICMP port unreachable for UDP to a closed port, TCP RSTs, and IPv6 echo replies behind NDISC. One source repeated 16 times has the same effect, since there is no per-neighbor limit.

While the pool is empty:
- Drivers cannot refill RX, so every received frame is dropped, including ARP/NA replies from real neighbors.
- UDP and raw sends return `NoBuffer`.
- TCP is held back and polls every `POOL_RETRY_DELAY` (1 ms).
- Solicitations cannot be allocated (`transmit_arp_request`, src/stack.rs:2529), so the stack also loses the retransmissions for its own resolutions.

The global drop-head also lets one bad neighbor push out packets parked for legitimate neighbors.

## Failure scenario

Default config, Ethernet interface 192.168.1.1/24. An attacker on the LAN sends ICMP echo requests from 192.168.1.100..115 (nonexistent hosts) every 3 to 5 s. The pool stays empty. TCP stalls, UDP sends fail with `NoBuffer`, and ARP requests from real peers go unanswered. For IPv6, an off-link attacker spoofing sources inside our on-link /64 can do the same if the router does not filter them.

## RFC reference

RFC 4861 §7.2.2: "the sender MUST, for each neighbor, retain a small queue of packets waiting for address resolution to complete. The queue MUST hold at least one packet, and MAY contain more. However, the number of queued packets per neighbor SHOULD be limited to some small value. When a queue overflows, the new arrival SHOULD replace the oldest entry."

## Reproduction

Test in `mod test` of src/stack.rs, in a scratch copy:

```rust
#[test]
fn vzz_pending_fills_pool() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    { let mut v = Vec::new(); while let Some(b) = PacketBuf::try_new() { v.push(b); } println!("pool free at start: {}", v.len()); }
    for i in 0..16u8 {
        let req = icmpv4_echo(Icmpv4Message::EchoRequest, 1, i as u16, b"hello");
        let pkt = ipv4_packet(Ipv4Addr::new(192, 168, 1, 100 + i), OUR_V4, IpProtocol::Icmp, &req);
        let hw = EthernetAddress([0x02, 0, 0, 0, 1, i]);
        inject(&mut stack, &rx, eth_frame_from(hw, OUR_HW, EthernetProtocol::Ipv4, &pkt));
    }
    println!("frames sent (ARP reqs): {}", tx.borrow().len());
    println!("try_new after 16 pings: {:?}", PacketBuf::try_new().is_some());
    println!("udp send: {:?}", stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)));
    for s in 1..=6u32 { stack.poll(Instant::from_secs(s as _)); let mut v = Vec::new(); while let Some(b) = PacketBuf::try_new() { v.push(b); } println!("t={}s free buffers {}", s, v.len()); }
}
```

`XARXA_PACKET_BUF_COUNT=16 cargo test --lib vzz_pending_fills_pool -- --nocapture --test-threads=1`

```
pool free at start: 16
frames sent (ARP reqs): 15
try_new after 16 pings: false
udp send: Err(NoBuffer)
t=1s free buffers 0
t=2s free buffers 0
t=3s free buffers 8
t=4s free buffers 8
t=5s free buffers 16
t=6s free buffers 16
```

The 16th ARP request could not be allocated. 8 buffers come back at 3 s (failed resolutions), the other 8 at 5 s (entries evicted from the cache).

## Suggested fix

- Bound parked packets per neighbor (Linux `unres_qlen`, lwIP `ARP_QUEUE_LEN`), 1 to 3 per key, replacing the oldest for that key.
- Keep the global pending bound well below the pool size.
- Consider parking at most one best-effort stack-generated reply per neighbor, or none.
- Drop parked packets on cache eviction of their entry instead of waiting for the lifetime.
