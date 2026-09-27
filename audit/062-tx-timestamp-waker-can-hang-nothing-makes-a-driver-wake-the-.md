# 062. TX timestamp waiters can hang: nothing wakes the poll task or schedules a deadline when a transmit timestamp becomes ready

| | |
|---|---|
| Severity | medium |
| Category | missed-wake |
| Location | [src/stack.rs:1081](../src/stack.rs#L1081), [src/stack.rs:120](../src/stack.rs#L120), [src/stack.rs:730](../src/stack.rs#L730), [xarxa-driver/src/lib.rs:218](../xarxa-driver/src/lib.rs#L218), [xarxa-driver/src/lib.rs:294](../xarxa-driver/src/lib.rs#L294) |
| Features | `packetmeta-timestamp`, `async` (both default) |
| Verification | confirmed against the code |

## Summary

Transmit timestamps move from a driver into the stack queue only at the start of `Stack::poll`. That is also the only place the `register_tx_timestamp_waker` waker is woken. The `Driver::register_waker` contract does not ask the driver to wake the poll task when a timestamp becomes ready, and `poll` counts no deadline for timestamps still to come. An async task waiting for a timestamp sleeps until an unrelated RX, timer or socket operation triggers a poll, up to `MAX_POLL_DELAY` (1 day).

## Details

src/stack.rs:1078, at the top of `poll`, before ingress and egress:

```rust
// Collect the transmit timestamps the drivers have ready for us.
#[cfg(feature = "packetmeta-timestamp")]
for (_, iface) in self.ifaces.iter_mut() {
    iface.drain_tx_timestamps(&mut self.inner.tx_timestamps);
}
```

src/stack.rs:120, `TxTimestampQueue::push`, the only wake of the tx-timestamp waker:

```rust
pub(crate) fn push(&mut self, timestamp: TxTimestamp) {
    if self.queue.push_back(timestamp).is_err() {
        trace!("tx timestamp queue full, dropping timestamp");
        return;
    }
    #[cfg(feature = "async")]
    self.waker.wake();
}
```

xarxa-driver/src/lib.rs:218 lists three wake conditions: a frame was received, room to transmit after `can_transmit` returned `false`, and a link state change. Transmit timestamps are not among them. Yet xarxa-driver/src/lib.rs:293 says:

> Timestamps become available an arbitrary time after `transmit` returned, so this should be polled repeatedly, not just once after sending.

Nothing in the stack polls repeatedly. The `poll` async doc (src/stack.rs:1063) repeats the three driver wake conditions. The `register_tx_timestamp_waker` doc (src/stack.rs:725) only says it is woken "when a TX timestamp is queued".

A second case: packets transmitted during `poll` itself, for example app packets with `request_timestamp` flushed from the pending queue after neighbor resolution. Their timestamps miss that poll's drain even if the driver has them at once, because the drain runs first. Nothing wakes the task or counts a deadline for them either.

The existing timestamp test passes only because `TestDevice::transmit` makes the timestamp available synchronously.

## Failure scenario

1. An async PTP app on stm32 eth sends a Sync with `request_timestamp = true`.
2. It registers the tx-timestamp waker, gets `None` from `poll_tx_timestamp`, and sleeps.
3. The runner polls right after the send, before the MAC has sent the frame. Nothing is drained.
4. DMA completes and the timestamp is ready in the driver. The TX ring was not full, so a driver that follows the contract wakes nobody.
5. The runner sleeps until the next received frame or stack timer. On a quiet link that can be up to a day. The Follow_Up is late or never sent.

## Suggested fix

Add "a transmit timestamp became available" to the `Driver::register_waker` wake conditions, and say so in the `Stack::poll` async doc and the `register_tx_timestamp_waker` doc. Also drain timestamps at the end of `poll`, so ones produced by packets sent during the poll are collected. Optionally count a short deadline while a requested timestamp has not arrived.
