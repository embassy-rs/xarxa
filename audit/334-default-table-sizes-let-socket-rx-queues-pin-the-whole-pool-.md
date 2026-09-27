# 334. Default socket RX queue bounds add up past the pool size

| | |
|---|---|
| Severity | info |
| Category | resource-leak |
| Location | [src/config.rs:125](../src/config.rs#L125), [src/config.rs:132](../src/config.rs#L132) |
| Features | default |
| Verification | confirmed against the code |

## Summary
With defaults, 4 UDP sockets x 4 queued plus 2 raw sockets x 4 queued is 24 buffers. The pool has 16. Slow readers, or a flood on an open port, can hold the whole pool. DESIGN §3 documents that slow readers pin pool memory and §11 lists reserves as open, so this is a tradeoff. The new point is that the default knobs allow queued RX alone to empty the pool.

## Details
`UDP_RX_QUEUE_COUNT` and `RAW_RX_QUEUE_COUNT` default to 4 (src/config.rs:125, 132). `UDP_SOCKET_COUNT` is 4, `RAW_SOCKET_COUNT` 2, `PACKET_BUF_COUNT` 16. With `alloc` the socket counts are unbounded anyway.

Once the pool is empty:
- Drivers can't allocate RX buffers, so nothing new arrives until the app reads.
- ARP replies, NAs, TCP ACKs and RSTs need a fresh buffer and are not sent. Echo replies still work, built in place.
- A TCP socket with output held back by the pool retries every `POOL_RETRY_DELAY` (1 ms). The poll loop does not run at 1 kHz otherwise.

## Failure scenario
Four bound UDP sockets read rarely on a busy multicast LAN fill their queues with 16 buffers. The device stops answering ARP, and peers lose it once their caches expire.

## Suggested fix
Pick defaults where the sum of RX queue bounds stays below the pool size, or document the constraint in `xarxa::config`. Longer term, a TX and control reserve (DESIGN §11).
