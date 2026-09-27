# 172. TX timestamp queue overflow drains the driver's timestamps and throws them away

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/mod.rs:755](../src/iface/mod.rs#L755), [src/stack.rs:122](../src/stack.rs#L122) |
| Features | packetmeta-timestamp |
| Verification | confirmed against the code |

## Summary
`drain_tx_timestamps` pulls every timestamp out of the driver even when the stack queue (`TX_TIMESTAMP_QUEUE_COUNT`, default 4) is full. Each extra one is dropped. Timestamps the driver could have kept until the application caught up are lost.

## Details
src/iface/mod.rs:755:
```rust
pub(crate) fn drain_tx_timestamps(&mut self, timestamps: &mut TxTimestampQueue) {
    while let Some(timestamp) = self.driver.poll_tx_timestamp() {
        timestamps.push(timestamp);
    }
}
```
`push` drops on a full queue (src/stack.rs:122, "tx timestamp queue full, dropping timestamp") and the loop continues. This follows the documented "Full queues drop incoming timestamps", so it is a design weakness, not a doc contradiction. It makes any deeper driver FIFO useless.

## Failure scenario
A PTP application sends 6 timestamped packets in a burst and reads one timestamp per loop iteration. The next poll drains all 6, keeps 4 and drops 2 that the driver still held.

## Suggested fix
Stop draining a driver once the stack queue is full and leave the rest in the driver.
