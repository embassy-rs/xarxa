# 030. No PMTU reaction to ICMP Fragmentation Needed / ICMPv6 Packet Too Big, while DF is always set (TCP black holes)

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/icmp_error.rs:33](../src/icmp_error.rs#L33), [src/icmp_error.rs:56](../src/icmp_error.rs#L56), [src/tcp/mod.rs:956](../src/tcp/mod.rs#L956), [src/stack.rs:2805](../src/stack.rs#L2805) |
| Features | default |
| Verification | reproduced with a test |

## Summary

ICMPv4 Fragmentation Needed and ICMPv6 Packet Too Big are only mapped to `IcmpError::PacketTooBig`. TCP records it as a soft error, UDP reports it. The MTU field is never read and nothing lowers the segment size. Every IPv4 packet the stack builds has DF set, and IPv6 packets go up to the link MTU. On a path with a smaller MTU and no MSS clamping, full-size TCP segments are dropped on every retransmission and the connection stalls until it times out.

## Details

src/icmp_error.rs:33 and :56:

```rust
Icmpv4DstUnreachable::FragRequired => IcmpError::PacketTooBig,
```

```rust
Icmpv6Message::PktTooBig => Some(IcmpError::PacketTooBig),
```

The Next-Hop MTU / MTU field is read nowhere outside packet logging.

src/tcp/mod.rs:956-964, `process_icmp_error`:

```rust
match self.state {
    State::SynSent | State::SynReceived => {
        debug!("{} during handshake, aborting connection", error);
        self.set_state(State::Closed);
        self.tuple = None;
    }
    _ => {
        trace!("icmp error {}, recorded as soft error", error);
    }
}
```

src/stack.rs:2805, in `push_ipv4_header`, on every stack-built packet:

```rust
packet.set_dont_frag(true);
```

DESIGN §7 notes "no PMTU/MSS reaction to packet-too-big yet". README "Not yet implemented" does not list PMTUD, and nothing documents that DF is always set. Setting DF is the first half of RFC 1191. Without the second half it turns a missing optimization into a black hole.

Minor: during SYN-SENT/SYN-RECEIVED a Packet Too Big aborts the handshake like any other ICMP error. SYNs are small, so this rarely matters.

## Failure scenario

The device (MTU 1500) talks to a server across a tunnel or PPPoE hop with MTU 1480 and no MSS clamping. The handshake completes. The first full-size segment is dropped and the router returns Frag Needed (IPv4) or PTB (IPv6). xarxa records a soft error and retransmits the same 1500-byte segment until the connection times out. Large UDP datagrams are never delivered either.

## RFC reference

RFC 1191 §3:

> When a host receives a Datagram Too Big message, it MUST reduce its estimate of the PMTU for the relevant path, based on the value of the Next-Hop MTU field in the message (see section 4).

> We do require that after receiving a Datagram Too Big message, a host MUST attempt to avoid eliciting more such messages in the near future. The host may either reduce the size of the datagrams it is sending along the path, or cease setting the Don't Fragment bit in the headers of those datagrams.

RFC 8201 §1:

> Nodes not implementing Path MTU Discovery must use the IPv6 minimum link MTU defined in [RFC8200] as the maximum packet size.

RFC 8200 §5:

> a minimal IPv6 implementation (e.g., in a boot ROM) may simply restrict itself to sending packets no larger than 1280 octets, and omit implementation of Path MTU Discovery.

## Reproduction

Test `verif_tcp_ignores_frag_needed` added to `src/stack.rs` `mod test` in a scratch copy. It completes a handshake with a SYN|ACK carrying MSS 1460, sends 3000 bytes, injects an ICMPv4 Destination Unreachable code 4 (next-hop MTU 1280) from 192.168.1.254 quoting the first 28 bytes of the first data segment, then polls at 1 s, 3 s, 7 s and 15 s and prints every transmitted segment. The ICMP part:

```rust
let mut icmp = vec![0u8; 8 + 28];
{ let mut p = Icmpv4Packet::new_unchecked(&mut icmp[..]); p.set_msg_type(Icmpv4Message::DstUnreachable); p.set_msg_code(Icmpv4DstUnreachable::FragRequired.into()); p.clear_unused(); p.data_mut().copy_from_slice(&first[..28]); }
icmp[6..8].copy_from_slice(&1280u16.to_be_bytes());
{ let mut p = Icmpv4Packet::new_unchecked(&mut icmp[..]); p.fill_checksum(); }
inject(&mut stack, &rx, ipv4_packet(Ipv4Addr::new(192,168,1,254), OUR_V4, IpProtocol::Icmp, &icmp));
for t in [1000u32, 3000, 7000, 15000] { stack.poll(Instant::from_millis(t as _)); /* print ip.total_len(), ip.dont_frag() of each tx frame */ }
```

`cargo test --lib verif_tcp_ignores_frag_needed -- --nocapture`:

```
SYN df true
first data segment: ip len 1500 df true
icmp err: Some(PacketTooBig)
t=1000 retransmit: ip len 1500 df true
t=3000 retransmit: ip len 1500 df true
t=7000 retransmit: ip len 1500 df true
t=15000 retransmit: ip len 1500 df true
```

## Suggested fix

On `PacketTooBig` for a synchronized TCP connection, lower the connection's MSS from the reported MTU (clamped to at least 68 for IPv4, 1280 for IPv6) and retransmit. Short of that: clear DF on IPv4 and cap IPv6 at 1280 until PMTUD exists. Add PMTUD to README "Not yet implemented".
