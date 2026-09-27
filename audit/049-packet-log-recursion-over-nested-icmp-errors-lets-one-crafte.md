# 049. packet-log recursion over nested ICMP errors lets one crafted packet use tens of KB of stack

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/packet_log.rs:702](../src/packet_log.rs#L702), [src/packet_log.rs:776](../src/packet_log.rs#L776), [src/packet_log.rs:145](../src/packet_log.rs#L145), [src/packet_log.rs:452](../src/packet_log.rs#L452), [src/stack.rs:1098](../src/stack.rs#L1098) |
| Features | `packet-log` (with `log` or `defmt` for the large frames) |
| Verification | reproduced with a test |

## Summary
With `packet-log`, every received frame is decoded before any validation. `log_icmpv4` and `log_icmpv6` recurse into `log_ipv4`/`log_ipv6` for the packet quoted in an ICMP error, with no depth limit. One 1484-byte IPv4 packet holding nested Destination Unreachable errors recursed 53 levels and used about 37 KB of stack in a release build (133 KB in debug). On a microcontroller this overflows the network task's stack, often with no guard to catch it.

## Details
src/packet_log.rs:702:
```rust
if ty.is_error() {
    log_ipv4(packet.data_mut());
}
```
`log_ipv4` ends in `log_transport`, which calls `log_icmpv4` again (src/packet_log.rs:452). The ICMPv6 path does the same at src/packet_log.rs:776. Each level costs 28 bytes of packet for IPv4 and 48 for IPv6.

The 6LoWPAN walker has the same shape: `log_sixlowpan` calls itself on a FRAG1 payload (src/packet_log.rs:145), and the NHC extension header walk recurses too.

src/stack.rs:1098 logs each frame before `process`:
```rust
crate::packet_log::log_packet(&mut buf, packet_log_layer(medium));
```
So the packet only has to reach the driver. It needs no valid destination and no checksum.

Stack use per level depends on the logger. Without a logger in release it is about 16 B/level, since the `trace!` arguments are optimized away. With `log` at trace level it is 570 to 690 B/level in release and about 2.5 KB/level in debug. Thumb frames are smaller, but 10 to 15 KB is still far above typical embassy task stacks.

A separate fuzz run of `packet_log` (3M structured mutations through `log_layer`, 2M random inputs per sub-decoder) found no panic and no infinite loop. Stack depth is the only robustness problem found there.

## Failure scenario
A firmware built with `packet-log` and `defmt` (a normal debug setup) receives, from any host that can reach it, an IPv4 packet whose ICMP error payload quotes another IPv4+ICMP error, nested about 50 times, with `total_len` set so each level parses. `log_packet` recurses 50+ levels and overflows the net runner task's stack: a HardFault, or silent corruption of adjacent memory on parts without a stack guard.

## Reproduction
In a scratch copy of `src/packet_log.rs`, a `cfg(test)` thread-local recorder of the minimum stack address and the depth was added at the top of `log_ipv4`, plus this test in its `mod test`:
```rust
#[test]
fn verify_nested_icmp_depth() {
    let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Trace).try_init();
    fn ipv4(payload: &[u8]) -> std::vec::Vec<u8> {
        let mut v = vec![0u8; 20 + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut v[..]);
            ip.set_version(4); ip.set_header_len(20); ip.set_total_len((20 + payload.len()) as u16);
            ip.set_next_header(IpProtocol::Icmp); ip.set_hop_limit(64);
            ip.set_src_addr(Ipv4Addr::new(10, 0, 0, 1)); ip.set_dst_addr(Ipv4Addr::new(10, 0, 0, 2));
            ip.fill_checksum();
        }
        v[20..].copy_from_slice(payload);
        v
    }
    let mut pkt = ipv4(&[8, 0, 0, 0, 0, 1, 0, 1]);
    while pkt.len() + 28 <= 1500 {
        let mut icmp = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&pkt);
        pkt = ipv4(&icmp);
    }
    let x = 0u8;
    let top = core::hint::black_box(&x) as *const u8 as usize;
    log_ipv4(&mut pkt);
    let min = VERIFY_MIN.with(|m| m.get());
    let depth = VERIFY_DEPTH.with(|d| d.get());
    println!("packet_len={} depth={} stack_used={}", pkt.len(), depth, top - min);
}
```
`cargo test [--release] --lib --features packet-log,log verify_nested_icmp_depth -- --nocapture`:
```
debug:   packet_len=1484 depth=53 stack_used=133440
release: packet_len=1484 depth=53 stack_used=36759
```
This is measured at the deepest `log_ipv4` entry, so the formatting frames below it are not counted.

## Suggested fix
Pass a depth counter and stop after one quoted packet: log the quoted IP header and transport header of an ICMP error, but do not recurse into an ICMP error quoted inside it. Limit the 6LoWPAN FRAG1 and NHC recursion the same way.
