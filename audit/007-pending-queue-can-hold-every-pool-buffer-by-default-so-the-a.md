# 007. Pending queue can hold every pool buffer by default, so the ARP/NA reply that would drain it cannot be received

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/neighbor.rs:492](../src/neighbor.rs#L492), [build.rs:16](../build.rs#L16), [xarxa-driver/build.rs:9](../xarxa-driver/build.rs#L9), [src/config.rs:89](../src/config.rs#L89), [src/stack.rs:2714](../src/stack.rs#L2714), [src/stack.rs:2535](../src/stack.rs#L2535), [src/stack.rs:2564](../src/stack.rs#L2564) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`PENDING_QUEUE_COUNT` is 16 at HEAD, the same as the default `PACKET_BUF_COUNT`. Nothing limits how many pool buffers parked packets hold. A burst of sends to one unresolved neighbor parks the whole pool. The stack then cannot send its solicitation retransmissions, and the driver cannot receive the ARP reply or NA, so resolution fails against a live host after about 3 s and every parked packet is dropped with `HostUnreachable`.

Commit d2d95301 ("Change default pending queue count to 2.") describes exactly this stall. It only edited `gen_config.py`. `build.rs` was not regenerated, so the default at HEAD is still 16.

## Details

build.rs:16
```rust
("PENDING_QUEUE_COUNT", 16),
```

gen_config.py:60
```python
feature("pending_queue_count", default=2, min=1, max=256, pow2=8)
```

xarxa-driver/build.rs:9
```rust
("PACKET_BUF_COUNT", 16),
```

The public doc also still says 16 (src/config.rs:89): "This is a limit with and without `alloc`. Default: 16."

`PendingQueue::push` (src/neighbor.rs:488-503) only drops the oldest entry once the `BoundedVec<_, PENDING_QUEUE_COUNT>` is full. `UdpSocket::prepare_datagram` (src/udp.rs:908-918) checks `can_transmit`, which is true since nothing reached the device, then allocates. `dispatch_ip` parks the packet (src/stack.rs:2714) and the send returns `Ok`.

Once the pool is empty:

- `transmit_arp_request` (src/stack.rs:2535) and `transmit_ndisc_solicit` (src/stack.rs:2564) fail `PacketBuf::try_new()` and return. `poll_retransmit` still counts each one as a probe.
- A driver refilling its RX ring gets no buffer and drops the incoming frame (DESIGN.md §3). The ARP reply or NA is lost, and so is every other frame on every interface.
- After `MAX_MULTICAST_SOLICIT` probes, `ProbeEvent::Failed` (src/stack.rs:1937) drops the parked packets with host-unreachable errors, although the neighbor is alive.

TCP hits the same thing. With no congestion control (the default), `dispatch` parks a whole window of segments on a Stale neighbor, one buffer each.

Even with `build.rs` regenerated, a user who sets `pending-queue-count` at or above `packet-buf-count` gets the stall back. Nothing checks the relation.

## Failure scenario

1. Default build. An embedded driver refills its RX ring from the pool.
2. Right after boot, or 60 s after the last traffic to the server, the application sends 16 UDP datagrams to 192.168.1.2, which needs ARP.
3. All 16 return `Ok` and are parked. The pool is empty.
4. The server's ARP reply arrives. The driver has no replacement buffer and drops it. The ARP retransmissions at +1 s and +2 s are never sent.
5. At +3 s every datagram is dropped and the socket reports `HostUnreachable`. Nothing is received on any interface in between.

## RFC reference

RFC 4861 §7.2.2: "The queue MUST hold at least one packet, and MAY contain more. However, the number of queued packets per neighbor SHOULD be limited to some small value."

## Reproduction

Added to the `mod test` of src/stack.rs in a scratch copy. It leaves exactly `PENDING_QUEUE_COUNT` pool buffers free, which models the default 16-buffer pool.

```rust
#[test]
fn vrfy_pending_queue_starves_pool() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let mut held = Vec::new();
    while let Some(b) = PacketBuf::try_new() { held.push(b); }
    for _ in 0..crate::config::PENDING_QUEUE_COUNT { held.pop(); }
    let mut oks = 0;
    for _ in 0..20 {
        match stack.udp_socket(handle).send_slice(b"x", (REMOTE_V4, 1000)) {
            Ok(()) => oks += 1,
            Err(e) => println!("send err {:?}", e),
        }
    }
    println!("oks = {oks}, tx after sends = {}", tx.borrow().len());
    assert!(PacketBuf::try_new().is_none());
    for secs in 1..=2 {
        stack.poll(Instant::ZERO + Duration::from_secs(secs));
        println!("t={secs}s tx frames = {}", tx.borrow().len());
    }
    assert_eq!(tx.borrow().len(), 1);
    stack.poll(Instant::ZERO + Duration::from_secs(3));
    stack.poll(Instant::ZERO + Duration::from_secs(4));
    drop(held);
    println!("recv after failure: {:?}", stack.udp_socket(handle).recv().as_ref().map(|_| ()));
}
```

`cargo test --lib vrfy_ -- --nocapture --test-threads=1`:

```
PENDING_QUEUE_COUNT = 16
send err NoBuffer (x4)
oks = 16, tx after sends = 1
t=1s tx frames = 1
t=2s tx frames = 1
recv after failure: Err(IcmpError { error: HostUnreachable, remote: SocketAddr { addr: V4(192.168.1.2), port: 1000 } })
test ... ok
```

The test device unwraps `try_new()` in `receive`, so the dropped reply itself could not be injected. The empty pool assertion shows a real driver would have no buffer for it.

## Suggested fix

- Regenerate `build.rs` so the default is 2, and fix the doc in src/config.rs.
- Add a build-time check that `PENDING_QUEUE_COUNT < PACKET_BUF_COUNT`, with some margin.
- Cap parked packets per neighbor, per RFC 4861 §7.2.2.
- Consider returning an error from UDP/raw sends to a resolving neighbor once the cap is reached, instead of `Ok` followed by a drop.
