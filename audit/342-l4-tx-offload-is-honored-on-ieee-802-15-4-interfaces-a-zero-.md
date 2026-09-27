# 342. L4 checksum offload flags are honored on IEEE 802.15.4 interfaces

| | |
|---|---|
| Severity | info |
| Category | hardening |
| Location | [src/udp.rs:950](../src/udp.rs#L950), [src/sixlowpan.rs:482](../src/sixlowpan.rs#L482), [src/iface/mod.rs:667](../src/iface/mod.rs#L667), [xarxa-driver/src/lib.rs:107](../xarxa-driver/src/lib.rs#L107) |
| Features | default (`medium-ieee802154`) |
| Verification | confirmed against the code |

## Summary
UDP, TCP and ICMPv6 builders write a zero checksum when the egress interface claims tx offload, whatever the medium. On 802.15.4 the compressor carries that zero inline in the UDP NHC. No radio can fill in a checksum inside a compressed, possibly fragmented payload. This only happens if a driver claims offload it does not do, which is a driver bug that breaks Ethernet too. The stack could still guard against it, since the claim is never valid on this medium.

## Details
src/udp.rs:950:
```rust
if !self.tx.checksum_caps(route.iface).udp.tx {
    udp.fill_checksum(&src.addr, &dst.addr);
} else {
    udp.set_checksum(0);
}
```
src/sixlowpan.rs:482:
```rust
checksum: Some(udp.checksum()),
```
`checksum_caps` (src/iface/mod.rs:667) returns the cached caps unchanged. The `ChecksumCapabilities` docs (xarxa-driver/src/lib.rs:107) say nothing about media. TCP (src/tcp/repr.rs:270) and the ICMPv6 builders behave the same. On rx, the flags skip verification of decompressed packets.

The finder reproduced it in a scratch copy: an 802.15.4 test device with `caps.udp = ChecksumOffload::BOTH` sent a UDP datagram whose decompressed checksum was 0x0000.

## Failure scenario
An 802.15.4 driver copies an Ethernet driver's caps with L4 offload set. Every UDP datagram leaves with checksum 0 and IPv6 peers discard it. Corrupted reassembled datagrams are accepted on rx.

## RFC reference
RFC 8200 §8.1: "IPv6 receivers must discard UDP packets containing a zero checksum". RFC 6282 §4.3.2: "The UDP checksum operation is mandatory with IPv6 [RFC2460] for all packets."

## Suggested fix
Clear the L4 checksum caps for `Medium::Ieee802154` in `add_iface`, or document that they must be all false for 802.15.4 devices.
