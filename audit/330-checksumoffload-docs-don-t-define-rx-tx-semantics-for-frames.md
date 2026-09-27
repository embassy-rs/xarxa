# 330. ChecksumOffload docs don't say what rx/tx mean for frames the hardware skips, or that failed frames must be dropped

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [xarxa-driver/src/lib.rs:90](../xarxa-driver/src/lib.rs#L90), [xarxa-driver/src/lib.rs:114](../xarxa-driver/src/lib.rs#L114), [xarxa-driver/src/lib.rs:136](../xarxa-driver/src/lib.rs#L136) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The `rx` and `tx` flags read as per-device facts. Real MACs verify and insert per frame, and skip some frames (IPv4 fragments, IP options). The docs don't say that a driver claiming `rx` must drop frames that fail, or what to do with frames the hardware didn't check. The embassy-stm32 driver in the sister repo took the natural misreading.

## Details
xarxa-driver/src/lib.rs:90:
```rust
/// The device verifies the checksum of received packets.
///
/// The stack then does not verify it in software.
pub rx: bool,
/// The device fills in the checksum of transmitted packets.
///
/// The stack then writes the field as zero instead of computing it.
pub tx: bool,
```
Gaps:
- Nothing says a failed frame must be dropped. The stack sees no status bit.
- Nothing says frames the device did not check need a drop or `rx = false`. /home/dirbaio/embassy/embassy/embassy-stm32/src/eth/v1/descriptors.rs:106 passes them up: `return true; // Let caller handle software checksum`. The stack skips the check when `rx` is set (src/udp.rs:994).
- lib.rs:114 "written as zero, so that a device that fills it in finds a known value there" does not hold for raw-socket frames (user bytes) or for the L4 checksum of IPv4 fragments.
- `all_offloaded()` (lib.rs:136) suggests loopback but does not warn against other uses.

The resulting behaviour bugs are covered by the fragmentation-tx and reassembly-rx findings.

## Failure scenario
A driver author claims `rx` on a MAC that flags errors but still delivers the frame, or that bypasses fragments. Corrupt datagrams reach sockets with no check anywhere.

## Suggested fix
Document that `rx = true` means every delivered frame of that protocol was verified and bad ones are dropped. Frames the device could not verify must be dropped, or the driver must set `rx = false`, until a per-packet flag exists. Document that `tx` insertion cannot fix fragments and that raw frames carry user checksums.
