# 291. Default config lets UDP RX queues pin the entire packet pool

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/udp.rs:230](../src/udp.rs#L230), [src/config.rs:125](../src/config.rs#L125), [xarxa-driver/src/config.rs:32](../xarxa-driver/src/config.rs#L32) |
| Features | default |
| Verification | reproduced with a test |

## Summary
With the defaults, 4 UDP sockets with 4-deep RX queues can hold all 16 pool buffers. Nothing caps the total held by socket queues, and with `alloc` the socket count is unbounded. A remote host can fill the queues of any wildcard-remote socket the application doesn't read, and the whole stack stops receiving and sending. DESIGN.md §3 and §11 acknowledge the pool pinning, but with the default sizing the per-socket bound it relies on caps nothing.

## Details
src/udp.rs:230:
```rust
pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
    if self.rx_queue.push_back(buf).is_err() {
```
The only bound is the per-socket `UDP_RX_QUEUE_COUNT` (4). `PACKET_BUF_COUNT` is 16. Raw socket queues add to the same budget. A real driver's RX ring also holds pool buffers, so fewer unread sockets suffice.

## Failure scenario
The device has a few bound UDP sockets, one of them send-only (for example a telemetry sender on an ephemeral port) and never read. A remote host sends 4 datagrams to each. The pool is empty: the driver can't refill RX, TCP is held back with `NoBuffer`, ARP and NDISC replies are dropped. It clears only when the application reads or closes the sockets, so it is permanent for a socket that is never read.

## Reproduction
Added to `src/stack.rs` `mod test`, run with `XARXA_PACKET_BUF_COUNT=16 cargo test --lib v_udp_pool_pin -- --nocapture`:
```rust
#[test]
fn v_udp_pool_pin() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    println!("pool count {}", xarxa_driver::config::PACKET_BUF_COUNT);
    for port in 1..=4u16 {
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(port, ListenSocketAddr::UNSPECIFIED).unwrap();
    }
    for port in 1..=4u16 {
        for _ in 0..crate::config::UDP_RX_QUEUE_COUNT {
            let datagram = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), port, b"x");
            inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram));
        }
    }
    println!("try_new after flood: {:?}", xarxa_driver::PacketBuf::try_new().is_some());
    assert!(xarxa_driver::PacketBuf::try_new().is_some(), "pool exhausted by UDP rx queues");
}
```
Output:
```
pool count 16
try_new after flood: false
panicked at src/stack.rs:7796:9: pool exhausted by UDP rx queues
```

## Suggested fix
Make the defaults coherent (total queue capacity well below the pool), or add a stack-wide limit on buffers held in socket RX queues with a reserve for the driver and TX. At least document the interaction on `UDP_RX_QUEUE_COUNT` and `bind`, and suggest connecting send-only sockets.
