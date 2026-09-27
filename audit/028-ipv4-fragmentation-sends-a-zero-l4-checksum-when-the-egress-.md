# 028. IPv4 fragmentation sends a zero UDP/ICMP checksum when the egress device claims tx checksum offload

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/fragmentation.rs:274](../src/fragmentation.rs#L274), [src/udp.rs:950](../src/udp.rs#L950), [src/stack.rs:1615](../src/stack.rs#L1615), [src/stack.rs:2670](../src/stack.rs#L2670) |
| Features | default (`ipv4-fragmentation`) |
| Verification | reproduced with a test |

## Summary

UDP and the ICMPv4 echo reply write their checksum as 0 when the egress interface claims `udp.tx` / `icmpv4.tx`. The decision ignores the MTU. A packet bigger than the IP MTU is then fragmented, and the zero checksum goes out in the first fragment. No device can fill it in, since it covers several frames, and the STM32 MAC bypasses fragmented frames anyway. Fragmented UDP loses its checksum, and echo replies to large pings are invalid.

## Details

src/udp.rs:950-956:

```rust
if !self.tx.checksum_caps(route.iface).udp.tx {
    udp.fill_checksum(&src.addr, &dst.addr);
} else {
    // ...
    udp.set_checksum(0);
}
```

src/stack.rs:1615-1619 (echo reply, built in the request buffer):

```rust
if !checksum_caps.icmpv4.tx {
    reply_icmp.fill_checksum();
} else {
    reply_icmp.set_checksum(0);
}
```

src/stack.rs:2670-2674, `StackInner::transmit_ip`:

```rust
if total_ip_len > iface.ip_mtu() {
    match ethertype {
        #[cfg(feature = "ipv4-fragmentation")]
        EthernetProtocol::Ipv4 => self.fragment_ipv4(iface, dst_addr, next_hop, buf),
```

src/fragmentation.rs:274-283, `dispatch_ipv4_frag` copies the header and payload verbatim and patches only IPv4 header fields:

```rust
tx_buffer[..ip_header_len].copy_from_slice(&buffer[..ip_header_len]);
tx_buffer[ip_header_len..]
    .copy_from_slice(&buffer[frag.ipv4.frag_offset as usize + ip_header_len..][..payload_len]);
...
packet.set_total_len(ip_len as u16);
packet.set_ident(frag.ipv4.ident);
packet.set_more_frags(more_frags);
packet.set_dont_frag(false);
packet.set_frag_offset(frag.ipv4.frag_offset);
```

Nothing upstream keeps these packets under the MTU. UDP `send_slice` checks only buffer capacity. The echo reply is built from a reassembled request of any size up to the buffer.

RM0090 §33 (STM32F4 MAC, checksum insertion): "Fragmented IP frames (IPv4 or IPv6) ... are bypassed and not processed by the checksum." The embassy-stm32 xarxa driver (`embassy-stm32/src/eth/mod.rs:125-133`) claims `ChecksumOffload::BOTH` for udp and icmpv4 on eth_v1b/v1c/v2. So the reference hardware hits this with its default setup.

The public doc of the tx flag ([xarxa-driver/src/lib.rs:94](../xarxa-driver/src/lib.rs#L94)) promises "The device fills in the checksum of transmitted packets", which cannot hold for a fragmented datagram.

TCP is not affected: segments are sized by the routed MTU. Raw sockets are not affected: they send the user's bytes.

The receive side has the same flaw (read, not tested). After reassembly ([src/stack.rs:1318](../src/stack.rs#L1318)), UDP and ICMP verification is skipped when `udp.rx` / `icmpv4.rx` is set (e.g. [src/stack.rs:1345](../src/stack.rs#L1345)). The hardware never checked the fragments, so a reassembled datagram gets no L4 checksum check at all.

## Failure scenario

- The device claims `icmpv4.tx`. A peer runs `ping -s 2000` against it. The reply is built with ICMP checksum 0, fragmented, and sent unchanged by the MAC. The peer drops it. Every ping above the MTU fails.
- The device claims `udp.tx`. Every UDP datagram above the MTU goes out with checksum 0 ("no checksum").

## RFC reference

RFC 1122 §4.1.3.4:

> A host MUST implement the facility to generate and validate UDP checksums. An application MAY optionally be able to control whether a UDP checksum will be generated, but it MUST default to checksumming on.

RFC 792 defines the Echo Reply checksum over the whole ICMP message. There is no "no checksum" value.

## Reproduction

Added to `src/stack.rs` `mod test` in a scratch copy (cfg `all(udp, ipv4-fragmentation, ipv4-reassembly)`):

```rust
fn zz_frag_udp_offload_zero_checksum() {
    let mtu = 576;
    let mut caps = ChecksumCapabilities::default();
    caps.udp = ChecksumOffload::BOTH;
    let (mut stack, _rx, tx, _room) = test_stack_inner(Medium::Ip, mtu, caps);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp).send_slice(&[0x77; 1000], SocketAddr::new(REMOTE_V4.into(), 1000)).unwrap();
    let frames = tx.borrow().clone();
    println!("frames {}", frames.len());
    let datagram = check_fragments(&frames, Medium::Ip, mtu, 1008);
    println!("udp checksum {:#06x}", checksum_at(&datagram, UDP_CHECKSUM));
    assert!(frames.len() > 1);
    assert_ne!(checksum_at(&datagram, UDP_CHECKSUM), 0, "fragmented UDP went out with a zero checksum");
}
```

`cargo test --lib zz_frag -- --nocapture`:

```
frames 2
udp checksum 0x0000
panicked at src/stack.rs:6155:9: assertion `left != right` failed: fragmented UDP went out with a zero checksum
test stack::test::zz_frag_udp_offload_zero_checksum ... FAILED
```

The finder also reproduced the echo-reply case (MTU 576, `icmpv4 = BOTH`, 1008-byte fragmented request): the reassembled reply had ICMP checksum 0x0000. The verifier did not re-run that one.

## Suggested fix

In `fragment_ipv4`, before parking the packet, compute the L4 checksum in software when the caps say tx offload for its protocol (what Linux does with `skb_checksum_help` before `ip_do_fragment`). On receive, verify reassembled packets in software regardless of the rx caps.
