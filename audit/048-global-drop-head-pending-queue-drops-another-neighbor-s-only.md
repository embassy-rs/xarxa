# 048. Global drop-head pending queue drops another neighbor's only parked packet

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/neighbor.rs:498](../src/neighbor.rs#L498), [src/udp.rs:793](../src/udp.rs#L793), [src/config.rs:84](../src/config.rs#L84) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The pending queue is one global FIFO. When it is full, `push` drops the oldest packet, whatever neighbor it was for. One busy unresolved destination can evict every packet parked for other neighbors, including their only one. The dropped packet gets no ICMP error, and the UDP send that parked it already returned `Ok`.

## Details
src/neighbor.rs:498:
```rust
if let Err(packet) = self.packets.push(packet) {
    trace!("neighbor: pending queue full, dropping oldest packet");
    self.packets.remove(0);
    unwrap!(self.packets.push(packet).map_err(|_| Full));
}
```
There is no per-key limit or accounting. DESIGN.md calls this "like Linux's `unres_qlen`", but Linux's queue is per neighbor.

The UDP doc (src/udp.rs:793) says: "If the destination's neighbor is unresolved, the packet is queued inside the stack and sent when resolution completes. This still counts as a successful send." That is false for a packet evicted this way. The `PENDING_QUEUE_COUNT` doc (src/config.rs:84) does not mention the drop policy.

The problem gets worse if the default count is lowered to 2, as intended in `gen_config.py` (commit d2d95301, not yet in build.rs): then two packets to another neighbor evict one.

## Failure scenario
A TCP SYN or DNS query to host A is parked. Before A answers, the application sends `PENDING_QUEUE_COUNT` (16) packets to unresolved host B. A's packet is dropped silently. The SYN waits for its RTO, and the DNS query waits for its retransmit timer.

## RFC reference
RFC 4861 §7.2.2:
> While waiting for address resolution to complete, the sender MUST, for each neighbor, retain a small queue of packets waiting for address resolution to complete. The queue MUST hold at least one packet, and MAY contain more. However, the number of queued packets per neighbor SHOULD be limited to some small value. When a queue overflows, the new arrival SHOULD replace the oldest entry.

RFC 1122 §2.3.2.2:
> The link layer SHOULD save (rather than discard) at least one (the latest) packet of each set of packets destined to the same unresolved IP address, and transmit the saved packet when the address has been resolved.

The MUST applies to IPv6. For IPv4/ARP it is a SHOULD. Both go through the same `PendingQueue`.

## Reproduction
Test in the `src/stack.rs` test module (IPv4/ARP):
```rust
#[test]
fn vrfy_pending_queue_cross_neighbor_eviction() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let a = Ipv4Addr::new(192, 168, 1, 3);
    stack.udp_socket(handle).send_slice(b"to-A", (a, 1000)).unwrap();
    for _ in 0..crate::config::PENDING_QUEUE_COUNT {
        stack.udp_socket(handle).send_slice(b"to-B", (REMOTE_V4, 1000)).unwrap();
    }
    tx.borrow_mut().clear();
    let a_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x03]);
    inject(&mut stack, &rx, arp_request_from(a_hw, a));
    let frames: Vec<Vec<u8>> = tx.borrow().iter().cloned().collect();
    let mut to_a = 0;
    for f in &frames {
        let mut f = f.clone();
        let eth = EthernetFrame::new_checked(&mut f[..]).unwrap();
        if eth.ethertype() == EthernetProtocol::Ipv4 && eth.dst_addr() == a_hw {
            to_a += 1;
        }
    }
    println!("frames after ARP from A: {}, IPv4 to A: {}", frames.len(), to_a);
    assert_eq!(to_a, 0);
}
```
Output (the one frame is the ARP reply):
```
frames after ARP from A: 1, IPv4 to A: 0
test ... ok
```

## Suggested fix
Limit packets per key (for example 3 or 4). When a key is at its limit, drop that key's oldest packet. When the global queue is full, drop from the key with the most packets, never a key's last one. Document the policy on `PENDING_QUEUE_COUNT` and adjust the UDP send doc.
