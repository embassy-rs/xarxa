# 070. Destination Options, Routing (Segments Left 0), No Next Header and atomic fragments are answered with "unrecognized next header"

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:1767](../src/stack.rs#L1767), [src/stack.rs:1724](../src/stack.rs#L1724), [src/stack.rs:1791](../src/stack.rs#L1791), [src/udp.rs:323](../src/udp.rs#L323), [src/icmp_error.rs:88](../src/icmp_error.rs#L88) |
| Features | default (`ipv6`) |
| Verification | reproduced with a test |

## Summary

After the optional hop-by-hop header, `process_ipv6` only accepts ICMPv6, UDP and TCP. Everything else goes to the `_` arm, which sends Parameter Problem code 1 pointing at the next header field. That includes No Next Header (59), which is not unrecognized, and the Destination Options and Routing headers RFC 8200 says a full implementation includes. UDP, TCP or ICMPv6 behind a Destination Options header, or behind a Routing header with Segments Left 0, is dropped and the sender is told the header is unknown.

## Details

src/stack.rs:1724 handles only hop-by-hop, else `(next_header, IPV6_HEADER_LEN, 6)`. Then src/stack.rs:1767-1795:
```rust
match next_header {
    IpProtocol::Icmpv6 => self.process_icmpv6(...),
    IpProtocol::Udp => self.process_udp(...),
    IpProtocol::Tcp => self.process_tcp(...),
    _ => {
        ...
        self.transmit_icmpv6_error(
            iface,
            &mut buf,
            Icmpv6Message::ParamProblem,
            Icmpv6ParamProblem::UnrecognizedNxtHdr.into(),
            nh_offset as u32,
            false,
        );
    }
}
```

Wrong answers per case:
- 59: a recognized value meaning "nothing follows". No error should be sent.
- Destination Options (60): should be walked with the same option semantics as hop-by-hop.
- Routing (43), Segments Left 0: must be ignored and processing continues (for example an RPL RH3 at the final hop).
- Routing, Segments Left != 0: code 0 pointing at the Routing Type, not code 1.
- Atomic fragment (offset 0, M=0): should be processed as a whole packet. Non-atomic fragments fall under the documented missing IPv6 reassembly (README "Not yet implemented").

The 6LoWPAN decompressor can produce Routing and Destination Options headers from NHC, and those hit the same arm.

`parse_datagram` in src/udp.rs:323 and `parse_quoted_packet` in src/icmp_error.rs:88 also only skip hop-by-hop. Not a bug today, since nothing else reaches them, but a fix has to update them.

## Failure scenario

- A peer sends an IPv6 packet with next header 59 to our address. The stack replies with Parameter Problem code 1, pointer 6.
- A peer sends UDP behind an 8-byte Destination Options header holding only PadN. The socket never sees the datagram, and the peer gets Parameter Problem code 1, pointer 6.

## RFC reference

RFC 8200 §4:
> A full implementation of IPv6 includes implementation of the following extension headers: Hop-by-Hop Options, Fragment, Destination Options, Routing, ...

> IPv6 nodes must accept and attempt to process extension headers in any order and occurring any number of times in the same packet

RFC 8200 §4.4:
> If Segments Left is zero, the node must ignore the Routing header and proceed to process the next header in the packet ... If Segments Left is non-zero, the node must discard the packet and send an ICMP Parameter Problem, Code 0, message to the packet's Source Address, pointing to the unrecognized Routing Type.

RFC 8200 §4.5:
> If the fragment is a whole datagram (that is, both the Fragment Offset field and the M flag are zero), then it does not need any further reassembly and should be processed as a fully reassembled packet

RFC 8200 §4.7:
> The value 59 in the Next Header field of an IPv6 header or any extension header indicates that there is nothing following that header.

The RFC uses lowercase must/should here.

## Reproduction

Test in the `src/stack.rs` test module of a scratch copy, `cargo test --lib vfy_ -- --nocapture --test-threads=1`:

```rust
#[test]
fn vfy_f1_nonxt_and_destopts() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    inject(&mut stack, &rx, ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol(59), &[]));
    { let tx = tx.borrow(); println!("F1 nh59: {} frames", tx.len());
      for f in tx.iter() { let (t, c, ptr, _) = parse_icmpv6_reply(f, OUR_V6, REMOTE_V6); println!("F1 nh59 reply type={:?} code={} ptr={}", t, c, ptr); } }
    tx.borrow_mut().clear();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let dgram = udp_datagram(REMOTE_V6.into(), 1000, OUR_V6.into(), 5555, b"hello");
    let mut payload = vec![17u8, 0, 1, 4, 0, 0, 0, 0]; // DestOpts: NH=UDP, len 0, PadN(4)
    payload.extend_from_slice(&dgram);
    inject(&mut stack, &rx, ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol(60), &payload));
    let got = stack.udp_socket(udp).recv().is_ok();
    println!("F1 destopts: delivered={}", got);
    let tx = tx.borrow();
    for f in tx.iter() { let (t, c, ptr, _) = parse_icmpv6_reply(f, OUR_V6, REMOTE_V6); println!("F1 destopts reply type={:?} code={} ptr={}", t, c, ptr); }
    assert!(!got);
}
```

Output:
```
F1 nh59: 1 frames
F1 nh59 reply type=ParamProblem code=1 ptr=6
F1 destopts: delivered=false
F1 destopts reply type=ParamProblem code=1 ptr=6
ok
```

## Suggested fix

Loop over extension headers in `process_ipv6`:
- Destination Options: walk with `process_hop_by_hop`.
- Routing with SL=0: skip. SL!=0: Parameter Problem code 0 pointing at the Routing Type.
- 59: drop silently.
- Fragment: strip atomic fragments, drop others silently.

Keep `l4_offset` and `nh_offset` updated for quoting and pointers, and teach `parse_datagram` and `parse_quoted_packet` the same walk.
