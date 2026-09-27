# 040. RA fields Cur Hop Limit, Reachable Time, Retrans Timer and the MTU option are ignored

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:397](../src/iface/slaac.rs#L397), [src/iface/mod.rs:727](../src/iface/mod.rs#L727), [src/neighbor.rs:30](../src/neighbor.rs#L30) |
| Features | default (`slaac`) |
| Verification | confirmed against the RFC text |

## Summary

`slaac_process_advertisement` reads only the router flags, the router lifetime, the SLLA option and the prefix options. Cur Hop Limit, Reachable Time, Retrans Timer and the MTU option are ignored. All four are SHOULD in RFC 4861 §6.3.4. Only the MTU option has real impact: a router advertising a smaller link MTU is ignored, and with no PMTUD and no IPv6 fragmentation the oversized packets are lost for good.

## Details

src/iface/slaac.rs:397:

```rust
let flags = icmp_packet.router_flags();
let router_lifetime = icmp_packet.router_lifetime();
```

The option loops only act on `SourceLinkLayerAddr` (line 410) and `PrefixInformation` (line 423). `ip_mtu()` (src/iface/mod.rs:727) comes from the driver caps and `PACKET_BUF_SIZE` only, and nothing can lower it. The neighbor cache uses the fixed `RETRANS_TIMER` of 1 s (src/neighbor.rs:30) and a fixed 60 s reachable lifetime. Sockets default to hop limit 64.

The missing PMTU reaction is documented (DESIGN §7). Ignoring the RA MTU option, the cheap mitigation, is not documented anywhere. The MTU part overlaps with finding 039.

## Failure scenario

A router with a PPPoE or tunnel uplink advertises MTU 1492 (or 1280) on a 1500-byte Ethernet LAN. The xarxa host keeps using ip_mtu 1500 and advertises a matching MSS. A remote TCP peer on a 1500 path sends and accepts full-size segments. Our 1500-byte data segments are dropped by the router, the PTB is ignored, and the connection stalls on retransmissions after the handshake. Large UDP datagrams are dropped silently. Honouring the MTU option would have lowered ip_mtu and our MSS.

## RFC reference

RFC 4861 §6.3.4:

> If the received Cur Hop Limit value is non-zero, the host SHOULD set its CurHopLimit variable to the received value.

> If the received Reachable Time value is non-zero, the host SHOULD set its BaseReachableTime variable to the received value.

> The RetransTimer variable SHOULD be copied from the Retrans Timer field, if the received value is non-zero.

> If the MTU option is present, hosts SHOULD copy the option's value into LinkMTU so long as the value is greater than or equal to the minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value specified in the link-type-specific document (e.g., [IPv6-ETHER]).

## Suggested fix

- Read the MTU option in the first option pass. If 1280 <= mtu <= the device IP MTU, store it in `IfaceState` as an IPv6 link MTU and take the min with it in `ip_mtu()` for IPv6.
- Optionally use a non-zero Cur Hop Limit as the default IPv6 hop limit for sockets that did not set one.
- Reachable Time and Retrans Timer are low impact. If left out, list them in README "Not yet implemented".
