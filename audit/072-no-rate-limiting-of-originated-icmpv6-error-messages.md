# 072. No rate limiting of originated ICMPv6 error messages

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:2090](../src/stack.rs#L2090), [src/udp.rs:1037](../src/udp.rs#L1037), [src/stack.rs:1734](../src/stack.rs#L1734), [src/stack.rs:1787](../src/stack.rs#L1787), [src/stack.rs:2950](../src/stack.rs#L2950) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`transmit_icmpv6_error` sends one error per offending packet. There is no token bucket or counter anywhere on the path. RFC 4443 §2.4(f) makes a rate limit a MUST for every IPv6 node. Any sender can make the stack answer every bad packet with an error of up to 1280 bytes, which costs pool buffers and device room and can be aimed at a spoofed source.

## Details

src/stack.rs:2090, `transmit_icmpv6_error`, applies the §2.4(e) checks and then goes straight to `route_reply`, `build_icmpv6_error` and `transmit_reply`. The only rate limit in the tree is for TCP challenge ACKs.

Callers:
- UDP port unreachable, src/udp.rs:1037.
- Unrecognized hop-by-hop option, src/stack.rs:1734.
- Unrecognized next header, src/stack.rs:1787. This includes every IPv6 fragment, since IPv6 reassembly is not implemented.

`build_icmpv6_error` allocates a fresh `PacketBuf` and quotes up to 1232 bytes, so the error is as large as the packet that caused it. If the error's destination is unresolved, it is parked in the shared drop-head pending queue, where it can push out socket packets.

The multicast case makes it worse. For an unrecognized option whose type has high bits 10, `process_hop_by_hop` returns `allow_multicast_dst: true` (src/stack.rs:2950):

```rust
return Ok(HopByHopAction::DiscardSendError {
    pointer,
    allow_multicast_dst: true,
});
```

So one packet to ff02::1 with a spoofed source makes every xarxa node on the link send the victim a Parameter Problem. RFC 4443 allows that exception only because (f) bounds it.

Pool exhaustion from errors parked on unresolved neighbors is covered in [011](011-about-16-spoofed-on-link-pings-or-udp-packets-to-closed-port.md). A rate limit would also bound that.

ICMPv4 errors (`transmit_icmpv4_error`, src/stack.rs:2050) are not limited either. RFC 1122 does not require a limit for hosts, so that part is hardening, not a violation.

## Failure scenario

- A remote host floods a closed UDP port over IPv6 with a spoofed source. The device answers each datagram with a Port Unreachable of up to 1280 bytes to the victim, using a pool buffer and a TX slot per packet.
- An attacker on the link sends packets with hop-by-hop option type 0x80 to ff02::1, source set to the victim. Every xarxa node answers every packet.

## RFC reference

RFC 4443 §2.4(f):

> Finally, in order to limit the bandwidth and forwarding costs incurred by originating ICMPv6 error messages, an IPv6 node MUST limit the rate of ICMPv6 error messages it originates.

> For example, in a small/mid-size device, the possible defaults could be B=10, N=10/s.

> NOTE: THE RESTRICTIONS UNDER (e) AND (f) ABOVE TAKE PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR ORIGINATING ICMP ERROR MESSAGES.

## Reproduction

Test added to `mod test` in src/stack.rs, in a scratch copy of HEAD:

```rust
#[test]
fn vfy_f3_no_rate_limit() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    for i in 0..200u16 {
        let dgram = udp_datagram(REMOTE_V6.into(), 1000 + i, OUR_V6.into(), 9, b"x");
        rx.borrow_mut().push_back(ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Udp, &dgram));
        stack.poll(Instant::ZERO);
    }
    println!("F3: {} icmpv6 errors for 200 datagrams at one instant", tx.borrow().len());
    assert_eq!(tx.borrow().len(), 200);
}
```

Output:

```
F3: 200 icmpv6 errors for 200 datagrams at one instant
ok
```

## Suggested fix

Add a token bucket to `StackInner` (B=10, N=10/s as the RFC suggests), refilled lazily from `now` when it is used, so it needs no timer. Check it in `transmit_icmpv6_error` before allocating the reply. Optionally apply the same bucket, or a second one, to `transmit_icmpv4_error`.
