# 012. IPv4 DF is set on every packet but Fragmentation Needed is ignored, so paths with a smaller MTU black-hole traffic

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/stack.rs:2805](../src/stack.rs#L2805), [src/icmp_error.rs:33](../src/icmp_error.rs#L33), [src/icmp_error.rs:56](../src/icmp_error.rs#L56), [src/tcp/mod.rs:949](../src/tcp/mod.rs#L949), [src/tcp/mod.rs:1897](../src/tcp/mod.rs#L1897), [src/tcp/mod.rs:1911](../src/tcp/mod.rs#L1911) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary

`push_ipv4_header` sets DF on every IPv4 packet the stack builds. A received Fragmentation Needed (or ICMPv6 Packet Too Big) is only recorded as an error. Nothing shrinks the packet size and nothing clears DF. On a path whose MTU is below the first-hop MTU, full-size TCP segments are dropped on every retransmission until the connection times out, and large UDP datagrams are lost for good.

## Details

src/stack.rs:2802
```rust
packet.set_ident(0);
packet.clear_flags();
packet.set_more_frags(false);
packet.set_dont_frag(true);
```

Every stack-built IPv4 packet goes through this: UDP and TCP via `TxContext::transmit_ip`, ICMP echo replies and errors, IGMP, and DHCP server replies. The only place DF is cleared is the local fragmenter (src/fragmentation.rs:282), which only runs when a packet exceeds the first-hop interface MTU.

On receipt, FragRequired and PktTooBig map to `IcmpError::PacketTooBig` (src/icmp_error.rs:33, 56). TCP stores it and does nothing else in synchronized states:

src/tcp/mod.rs:955
```rust
self.icmp_error = Some(error);
match self.state {
    State::SynSent | State::SynReceived => { /* abort */ }
    _ => {
        trace!("icmp error {}, recorded as soft error", error);
    }
}
```

The segment size comes only from the egress interface: `self.ip_mtu = route.ip_mtu;` (src/tcp/mod.rs:1897) and `let local_mss = self.ip_mtu - ip_header_len - TCP_HEADER_LEN;` (src/tcp/mod.rs:1911). UDP puts the error in the socket's slot. There is no PMTU cache anywhere.

DESIGN §7 documents "no PMTU/MSS reaction to packet-too-big yet". What it does not say is that DF is always set, which is what turns missing PMTUD into a black hole for IPv4 instead of a fallback to router fragmentation. README "Not yet implemented" does not list PMTUD.

For IPv6 there is no DF to clear. The stack sends up to the interface MTU (1500 on Ethernet) and ignores PTB, so any narrower path (6in4 at 1480, WireGuard, PPPoE) stalls the same way.

DF on every packet is inherited from smoltcp.

## Failure scenario

Device on Ethernet (MTU 1500) talks to a server that advertises MSS 1460, through a 1400-byte tunnel or PPPoE link with no MSS clamping. The handshake and small requests work. The first full-size segment is dropped with Frag Needed. xarxa retransmits the same DF segment with backoff until the connection timeout, so bulk transfers hang. UDP datagrams above 1400 bytes are never delivered, where DF=0 would have let the router fragment them.

MSS clamping on many PPPoE and tunnel routers hides the TCP case. It does not help UDP.

## RFC reference

RFC 1191 §3: "When a host receives a Datagram Too Big message, it MUST reduce its estimate of the PMTU for the relevant path, based on the value of the Next-Hop MTU field in the message" and "after receiving a Datagram Too Big message, a host MUST attempt to avoid eliciting more such messages in the near future. The host may either reduce the size of the datagrams it is sending along the path, or cease setting the Don't Fragment bit in the headers of those datagrams."

RFC 1191 §3 also: "We do not want the IP layer to simply set the DF bit in every packet, since it is possible that a packetization layer, perhaps a UDP application outside the kernel, is unable to change its datagram size."

RFC 8200 §5: "a minimal IPv6 implementation (e.g., in a boot ROM) may simply restrict itself to sending packets no larger than 1280 octets, and omit implementation of Path MTU Discovery."

RFC 8201 §4 (lowercase requirement language, as the RFC itself notes): "The node must reduce the size of the packets it is sending along the path."

## Suggested fix

- Until PMTUD exists, clear DF on stack-built IPv4 packets (at least UDP and TCP), as lwIP does.
- For IPv6, clamp the TCP MSS to 1280 - 60 for off-link destinations, or implement PMTUD.
- Better: on an in-window `PacketTooBig`, lower the socket's MSS to the reported next-hop MTU (floor 68 / 1280) and retransmit.
