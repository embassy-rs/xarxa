# 039. No IPv6 path MTU handling: RA MTU option and Packet Too Big are ignored, and full-size packets go off-link

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:389](../src/iface/slaac.rs#L389), [src/icmp_error.rs:56](../src/icmp_error.rs#L56), [src/tcp/mod.rs:1887](../src/tcp/mod.rs#L1887), [src/iface/mod.rs:727](../src/iface/mod.rs#L727) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary

xarxa sends IPv6 packets up to the interface IP MTU (1500 on Ethernet) to off-link destinations. The RA MTU option is never applied, and an incoming Packet Too Big only becomes a soft `IcmpError` on the socket. RFC 8200 §5 expects either PMTUD or a 1280-byte cap, and xarxa does neither. There is no IPv6 fragmentation either, so oversized packets on a reduced-MTU path are lost for good.

## Details

`slaac_process_advertisement` (src/iface/slaac.rs:389) only acts on `SourceLinkLayerAddr` (line 410) and `PrefixInformation` (line 423). Outside src/wire, the only use of `NdiscOptionType::Mtu` is a trace in src/packet_log.rs:849.

src/icmp_error.rs:56 maps PTB to an error slot entry, and nothing reacts to it:

```rust
Icmpv6Message::PktTooBig => Some(IcmpError::PacketTooBig),
```

`Iface::ip_mtu` (src/iface/mod.rs:727) comes only from the driver caps and `PACKET_BUF_SIZE`. TCP sizes segments from `route.ip_mtu` in `dispatch` (src/tcp/mod.rs:1887 onward). UDP and raw sends are checked against the same value.

What is documented: DESIGN.md §7 "ICMP errors on sockets" says there is no PMTU/MSS reaction to packet-too-big for TCP. Not documented: the ignored RA MTU option, the missing 1280 cap, and the UDP/raw PTB non-reaction. None of it is in README "Not yet implemented" or DESIGN §10/§11.

Scope: only the RA MTU part is a normative SHOULD violation. The PMTUD-or-1280 text in RFC 8200 is a strong recommendation, not a MUST. Honouring the RA MTU only helps when the router advertises the reduced link MTU. A smaller MTU further along the path still needs PMTUD or the 1280 cap.

## Failure scenario

The upstream router sits behind PPPoE and advertises MTU 1492 in its RAs. A UDP application sends 1450-byte datagrams to an internet host. Each IPv6 packet is 1498 bytes. The router drops every one and sends PTB, which is ignored. The datagrams are blackholed indefinitely. TCP bulk transfers stall the same way after the handshake, unless the router clamps the MSS.

## RFC reference

RFC 4861 §6.3.4:

> If the MTU option is present, hosts SHOULD copy the option's value into LinkMTU so long as the value is greater than or equal to the minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value specified in the link-type-specific document (e.g., [IPv6-ETHER]).

RFC 8200 §5:

> It is strongly recommended that IPv6 nodes implement Path MTU Discovery [RFC8201], in order to discover and take advantage of path MTUs greater than 1280 octets. However, a minimal IPv6 implementation (e.g., in a boot ROM) may simply restrict itself to sending packets no larger than 1280 octets, and omit implementation of Path MTU Discovery.

## Suggested fix

- Honour the RA MTU option: store a per-interface IPv6 link MTU, clamped to 1280..=`ip_mtu()`, and use it for IPv6 in `route()`. See also finding 040.
- Then either cap IPv6 packets to off-link destinations at 1280, or implement a minimal PMTU reaction (at least lower the TCP connection's MSS on PTB).
- Document whatever stays out of scope in README "Not yet implemented".
