# 278. Every poll routes and builds a TcpRepr for every open TCP socket, idle or not

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/tcp/mod.rs:1887](../src/tcp/mod.rs#L1887), [src/tcp/mod.rs:1804](../src/tcp/mod.rs#L1804), [src/tcp/mod.rs:1932](../src/tcp/mod.rs#L1932), [src/stack.rs:1168](../src/stack.rs#L1168), [src/stack.rs:277](../src/stack.rs#L277), [src/stack.rs:346](../src/stack.rs#L346) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`Stack::poll` dispatches every TCP socket. Inside `dispatch` the only early exit is `tuple == None`. Every socket with a tuple runs `has_ip_addr`, `route()` and a full `TcpRepr` build (SACK ranges, timestamp, scaled window) before anything checks whether a segment is due. Poll cost grows linearly with open connections. Dispatching every socket per poll is the documented design (DESIGN §7). The cost is the unconditional work inside it.

## Details
src/stack.rs:1168:
```rust
for (_, socket) in self.sockets.tcp.iter_mut() {
```
src/tcp/mod.rs:1804: `let Some(tuple) = self.tuple else {` is the only early exit.

src/tcp/mod.rs:1887:
```rust
let route = if cx.has_ip_addr(tuple.local.addr) {
```
`has_ip_addr` scans every interface's addresses (src/stack.rs:277). `route` filters interfaces by on-link prefix and walks the routes table for off-link peers (src/stack.rs:346). Then src/tcp/mod.rs:1912-1946 builds the `TcpRepr`, with `generate_sack_ranges(ack)` at :1932 and `timestamp_repr` at :1937.

Finder measurements (release, default features, x86-64 `perf stat`):
- Idle poll: 507 instructions with no TCP sockets, 7,595 with 16 idle ESTABLISHED sockets (443 per socket). `has_ip_addr` plus `route` is about 160 of those.
- One UDP datagram, poll plus `recv_slice`: 1,740 instructions with 0 TCP sockets, 8,828 with 16 (64-byte payload). 2,933 vs 10,023 with 1472 bytes.

The verifier did not reproduce the UDP counts but measured the per-socket cost directly and it agrees. On a Cortex-M4 at 180 MHz, 443 instructions is roughly 2.5 us per socket per poll.

## Failure scenario
A firmware with 16 idle TCP connections (MQTT, HTTP keep-alive) receives a UDP stream. embassy-net polls about once per frame. Each poll dispatches all 16 sockets and each one routes and builds a repr although nothing is due. Per-datagram cost rises 3x to 5x. The DESIGN §9 UDP RX numbers were measured with no idle TCP connections.

## Reproduction
Verifier, `src/tcp/mod.rs` test module, release build:
```rust
#[test]
fn zz_idle_dispatch_cost() {
    let mut s = socket_established();
    let n = 2_000_000u32;
    let t0 = std::time::Instant::now();
    let mut sent = 0u32;
    for i in 0..n {
        let t = Instant::from_millis(1 + (i / 1000));
        let mut clock = Clock::new(t);
        let _: Result<(), ()> = s.sockets.get_mut(0).dispatch(&mut s.stack.tx_context(), &mut clock, |_, _, _, _, _, _r| { sent += 1; Ok(()) });
        core::hint::black_box(clock.next());
    }
    println!("idle dispatch: {:.1} ns/call, sent {}", t0.elapsed().as_nanos() as f64 / n as f64, sent);
    s.tuple = None;
    // same loop again
}
```
`cargo test --release --lib zz_idle -- --nocapture`:
```
idle dispatch: 17.4 ns/call, sent 0
tuple=None dispatch: 2.3 ns/call
```

## Suggested fix
Run the timer checks and a cheap "anything due" test first (data or FIN within the windows, ACK due, SYN or RST pending, a timer fired). Return before `has_ip_addr`, `route` and repr construction when nothing is due. Build SACK ranges and the timestamp only when a segment is actually emitted. The `Clock` checks already come before the route, so deadline counting is unaffected.
