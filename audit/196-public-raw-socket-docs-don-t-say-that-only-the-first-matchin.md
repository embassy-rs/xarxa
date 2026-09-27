# 196. Public raw socket docs don't say that only the first matching socket (in slab order) receives a packet

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/raw.rs:56](../src/raw.rs#L56), [src/raw.rs:636](../src/raw.rs#L636), [src/raw.rs:686](../src/raw.rs#L686), [src/stack.rs:1340](../src/stack.rs#L1340) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Ingress delivers each packet to the first matching raw socket in slab order, and only to it. A wildcard socket added earlier starves more specific ones added later. The public docs say none of this, and they don't describe the receive scope either (packets for us only, DHCP consumed by the stack).

## Details
`process_raw_ethernet` (src/raw.rs:636-661) and `process_raw_ip` (src/raw.rs:686-715) return after the first match. Only the `pub(crate)` comments say so. The public docs (module doc, `RawMode::Ethernet`, `RawMode::Ip` at src/raw.rs:56-65) say "Send and receive whole IP packets, on all interfaces" and "only packets with this IP protocol are received".

Undocumented:
- One socket per packet, by slab index, not specificity (unlike UDP's scored demux).
- A full RX queue on the first match drops the packet even if a later socket matches.
- IP mode only sees packets that pass the for-us check (src/stack.rs:1386-1406, before the raw offer at 1412-1421). Ethernet mode only sees frames that pass the MAC filter.
- With `dhcpv4`/`dhcpv4-server` active, DHCP packets are consumed and returned at src/stack.rs:1340-1383, before the raw offer. This also contradicts DESIGN.md §7 ("*before* the stack's own protocol handlers run").

## Failure scenario
An app adds a sniffer `Ip { version: None, protocol: None }`, then a socket bound to protocol 89. Every protocol-89 packet moves zero-copy into the sniffer and the second socket receives nothing. Two ping apps with raw ICMP sockets cannot both see echo replies.

## Suggested fix
Document first-match delivery and the receive scope on `RawMode` and the module. Or deliver to the most specific match, or copy to every match like Linux.
