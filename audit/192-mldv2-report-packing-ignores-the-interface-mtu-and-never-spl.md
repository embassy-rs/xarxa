# 192. MLDv2 report packing ignores the interface MTU and never splits: extra groups are silently dropped

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/multicast.rs:622](../src/multicast.rs#L622), [src/multicast.rs:376](../src/multicast.rs#L376), [src/stack.rs:2670](../src/stack.rs#L2670), [src/sixlowpan.rs:38](../src/sixlowpan.rs#L38) |
| Features | default (large tables need `alloc`, small MTU case needs 802.15.4 without `sixlowpan-fragmentation`) |
| Verification | confirmed against the code |

## Summary
`mldv2_report_start` sizes a report by `PacketBuf` tailroom, not by the interface IP MTU, and the general-query response sends a single report. Records past one buffer are dropped with a warning. If the report is larger than `ip_mtu()`, `transmit_ip` drops the whole report, since IPv6 fragmentation is not implemented.

## Details
src/multicast.rs:622
```rust
let max_records = (pkt.tailroom() - 8) / MLD_ADDRESS_RECORD_LEN;
```
That is 72 records with 1514-byte buffers. The general-query response (src/multicast.rs:376-384) calls `mldv2_report_packet` once.

src/stack.rs:2670 drops any IPv6 packet over `iface.ip_mtu()` ("IPv6 fragmentation support is unimplemented. Dropping.").

Two cases lose the whole report:
- Default features: an 802.15.4 interface has `ip_mtu` 1280. A report with 62 or more records (40+8+8+20N > 1280) is dropped.
- Without `sixlowpan-fragmentation`, `ip_mtu` is the one-frame value (src/sixlowpan.rs:38-48), roughly 100 bytes. A few records are enough.

Without `alloc`, the default group table (8) keeps the Ethernet case below 72.

## Failure scenario
- With `alloc` and more than 72 IPv6 groups, groups past the cap are never reported to general queries and the router prunes them.
- On 6LoWPAN without fragmentation, a couple of app groups plus the solicited-node group make every general-query response vanish.

## RFC reference
RFC 3810 §6.3: "Multiple Current State Records are packed into individual Report messages, to the extent possible."

## Suggested fix
Size batches by `min(tailroom, ip_mtu - 40 - 8 - 8)` and send as many reports as needed.
