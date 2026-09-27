# 050. Raw-socket packets carry user checksums, but the driver contract lets the device's tx offload rewrite them: raw ICMPv4 pings break on the stm32 MAC

| | |
|---|---|
| Severity | medium |
| Category | api |
| Location | [src/raw.rs:484](../src/raw.rs#L484), [src/raw.rs:583](../src/raw.rs#L583), [src/raw.rs:611](../src/raw.rs#L611), [xarxa-driver/src/lib.rs:93](../xarxa-driver/src/lib.rs#L93), [xarxa-driver/src/lib.rs:114](../xarxa-driver/src/lib.rs#L114), [DESIGN.md:609](../DESIGN.md#L609) |
| Features | default |
| Verification | confirmed against the code (and the STM32 reference manual) |

## Summary
Raw sockets pass user bytes to the driver unchanged, and the docs tell the user to fill in the checksum. The driver contract says every checksum the stack leaves to the device is written as zero, and gives no per-packet signal. So a driver that claims `icmpv4.tx` enables insertion on every frame, raw ones included. On MACs like the STM32 ETH, a non-zero ICMPv4 checksum field gives a wrong inserted checksum, so a raw-socket ping built as documented goes out corrupt.

## Details
src/raw.rs:484, the send doc:
```rust
/// - In IP mode, a whole IP packet, with checksum calculated. The destination
```
Raw frames reach the driver untouched: Ethernet mode through `self.tx.transmit_ethernet(unwrap!(eth_iface), buf)` (src/raw.rs:583), IP mode through `self.tx.transmit_raw_ip(&route, buf, dst_addr)` (src/raw.rs:611). Neither consults the offload capabilities. The xarxa code path matches DESIGN §4: "Raw sockets are also unaffected: they emit what the user wrote, header bytes included" (DESIGN.md:609).

The driver side, xarxa-driver/src/lib.rs:93:
```rust
/// The device fills in the checksum of transmitted packets.
///
/// The stack then writes the field as zero instead of computing it.
pub tx: bool,
```
and xarxa-driver/src/lib.rs:114:
```rust
/// A checksum the stack does not compute is written as zero, so that a device
/// that fills it in finds a known value there.
```
Nothing tells a driver author that some frames carry arbitrary checksum bytes. The embassy-stm32 xarxa driver sets `CIC_FULL` on every TX descriptor (embassy-stm32/src/eth/v1/descriptors.rs, about line 392) and reports `caps.checksum.icmpv4 = ChecksumOffload::BOTH` (embassy-stm32/src/eth/mod.rs:131).

RM0090 §33 (checksum insertion):
> Note that: for ICMP-over-IPv4 packets, the checksum field in the ICMP packet must always be 0x0000 in both modes, because pseudo-headers are not defined for such packets. If it does not equal 0x0000, an incorrect checksum may be inserted into the packet.

Scope:
- Raw ICMPv4 (echo and any other type), in IP and Ethernet mode, goes out with a wrong checksum on MACs with this behavior.
- Raw TCP/UDP and the IPv4 header checksum are recomputed in full mode ("the checksum field is ignored ... and overwritten"). A correct user checksum comes out correct. Only a deliberately wrong one is silently fixed.

Linux avoids this with a per-skb `ip_summed`: only stack-built packets are marked `CHECKSUM_PARTIAL`. `PacketMeta` has no equivalent.

Not testable with the test device, which does no insertion.

## Failure scenario
An application on an STM32F4/F7/H7 board with embassy-stm32's xarxa driver pings a host through a raw IP socket bound to ICMP, which is the documented way to ping (DESIGN §7). It fills in the ICMP checksum as raw.rs says. The MAC inserts a checksum computed over the non-zero field. The host drops the request, and ping never gets a reply. Zeroing the checksum works around it, against the docs.

## Suggested fix
Give the driver a per-packet signal, for example a `PacketMeta` bit set only on packets whose checksums the stack left zero, and document that drivers must only insert on those. At a minimum, document on `ChecksumCapabilities`/`ChecksumOffload::tx` that raw-socket frames carry arbitrary checksum bytes, and fix DESIGN §4 and the raw send docs to say the device's tx offload may rewrite a raw packet's checksums.
