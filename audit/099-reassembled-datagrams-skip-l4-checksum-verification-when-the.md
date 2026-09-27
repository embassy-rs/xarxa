# 099. Reassembled datagrams skip L4 checksum verification when the arrival device claims rx offload, although the hardware cannot verify fragments

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/udp.rs:994](../src/udp.rs#L994), [src/stack.rs:1317](../src/stack.rs#L1317), [src/stack.rs:1497](../src/stack.rs#L1497), [src/stack.rs:1563](../src/stack.rs#L1563), [src/stack.rs:1815](../src/stack.rs#L1815), [src/stack.rs:1345](../src/stack.rs#L1345), [src/stack.rs:1369](../src/stack.rs#L1369) |
| Features | default (`ipv4-reassembly`), with a driver claiming L4 rx offload |
| Verification | reproduced with a test |

## Summary

After IPv4 reassembly the packet continues through `process_ipv4` with the arrival interface, and every L4 check skips software verification when that interface claims `udp.rx`, `tcp.rx`, `icmpv4.rx` or `icmpv6.rx`. A per-frame checksum engine cannot verify the L4 checksum of a fragment, since the checksum covers the whole datagram. So nobody verifies it, and a corrupted reassembled datagram reaches the socket. A corrupted fragmented ping gets a reply with a freshly computed, valid checksum over the corrupted data.

## Details

src/stack.rs:1317, reassembly, after which processing continues with the same `iface`:

```rust
let mut buf = if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
    let Some(buf) = self.reassemble_ipv4(buf) else {
        return;
    };
    buf
```

src/udp.rs:994:

```rust
if !self.ifaces.get(iface.index()).checksum_caps().udp.rx && !udp_packet.verify_checksum(&src_addr, &dst_addr) {
```

The same pattern is at src/stack.rs:1497 (TCP), 1563 (ICMPv4), 1815 (ICMPv6), and 1345 and 1369 (DHCP client and server, via `checksum_caps` read before reassembly).

The driver contract (xarxa-driver/src/lib.rs:89-92) says "The device verifies the checksum of received packets. The stack then does not verify it in software." Real hardware does not do this for fragments. RM0090 §33: "the receive checksum offload bypasses the payload of fragmented IP datagrams, IP datagrams with security features, IPv6 routing headers, and payloads other than TCP, UDP or ICMP." The embassy-stm32 xarxa driver passes bypassed frames up (`if (rdes4 & RXDESC_4_IPCB) != 0 { return true; // Let caller handle software checksum }`) while claiming `BOTH` for udp, tcp, icmpv4 and icmpv6. `PacketMeta` has no "checksum verified" bit, so the driver cannot tell the stack which frames it checked.

The 6LoWPAN reassembly path (`process_sixlowpan_fragment`, src/sixlowpan.rs:644, then `process_ipv6`) has the same shape, but 802.15.4 drivers practically never claim L4 rx offload.

## Failure scenario

A board using the stm32 driver receives a fragmented UDP datagram, e.g. a large DNS or CoAP reply from a peer whose PMTUD failed. A bit flips in transit, or a fragment of another datagram with the same ident is spliced in. The reassembled datagram fails its UDP checksum and is delivered to the application anyway. Fragmented TCP segments are accepted the same way.

## RFC reference

RFC 1122 §4.1.3.4:

> If a UDP datagram is received with a checksum that is non-zero and invalid, UDP MUST silently discard the datagram.

RFC 9293 §3.1:

> The TCP checksum is never optional. The sender MUST generate it (MUST-2) and the receiver MUST check it (MUST-3).

## Reproduction

Test in `mod test` of src/stack.rs, in a scratch copy of the crate:

```rust
#[test]
fn verify_reassembled_udp_bad_checksum_offload() {
    for offload in [false, true] {
        let mut caps = ChecksumCapabilities::default();
        if offload { caps.udp = ChecksumOffload::BOTH; }
        let (mut stack, rx, _tx) = test_stack_with_checksum(Medium::Ip, caps);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, ListenSocketAddr::UNSPECIFIED).unwrap();
        let payload = vec![0x55u8; 1000];
        let mut datagram = udp_datagram(REMOTE_V4.into(), 5000, OUR_V4.into(), 5000, &payload);
        datagram[500] ^= 0x01; // UDP checksum now wrong
        let first = 512usize;
        let f1 = ipv4_fragment(REMOTE_V4, OUR_V4, IpProtocol::Udp, 0x4242, true, 0, &datagram[..first]);
        let f2 = ipv4_fragment(REMOTE_V4, OUR_V4, IpProtocol::Udp, 0x4242, false, first as u16, &datagram[first..]);
        inject(&mut stack, &rx, f1);
        inject(&mut stack, &rx, f2);
        let got = stack.udp_socket(handle).can_recv();
        println!("offload={offload} delivered={got}");
        if offload { assert!(!got, "corrupted reassembled datagram delivered with udp rx offload"); }
    }
}
```

`cargo test --lib verify_reassembled -- --nocapture`:

```
offload=false delivered=false
offload=true delivered=true
thread 'stack::test::verify_reassembled_udp_bad_checksum_offload' panicked at src/stack.rs:6416:17:
corrupted reassembled datagram delivered with udp rx offload
test result: FAILED. 0 passed; 1 failed
```

## Suggested fix

Treat rx offload as void for reassembled packets. For example, have `reassemble_ipv4` and `process_sixlowpan_fragment` signal that the buffer was reassembled, and verify L4 checksums in software for it. Longer term, add a per-packet "L4 checksum verified" bit in `PacketMeta`, so drivers can report frames the hardware bypassed.
