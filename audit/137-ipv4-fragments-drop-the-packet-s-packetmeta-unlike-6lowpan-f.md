# 137. IPv4 fragments drop the packet's PacketMeta, unlike 6LoWPAN fragments and contrary to the Driver::transmit doc

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/fragmentation.rs:264](../src/fragmentation.rs#L264), [src/sixlowpan.rs:891](../src/sixlowpan.rs#L891), [xarxa-driver/src/lib.rs:269](../xarxa-driver/src/lib.rs#L269) |
| Features | `packetmeta-id` or `packetmeta-timestamp`, with `ipv4-fragmentation` |
| Verification | confirmed against the code |

## Summary
`dispatch_ipv4_frag` builds each fragment in a fresh `PacketBuf` and never copies the original packet's meta. A UDP or raw IP datagram sent with an `id` or `request_timestamp` that needs IPv4 fragmentation reaches the driver with default meta. No `TxTimestamp` for its id is ever reported. The 6LoWPAN fragmenter puts the meta on the first fragment.

## Details
src/fragmentation.rs:264-269
```rust
let Some(mut tx_buffer) = PacketBuf::try_new() else {
    trace!("fragmenter: no packet buffer, fragments wait");
    return false;
};
tx_buffer.reserve(LINK_HEADER_LEN);
tx_buffer.set_len(ip_len);
```
There is no `set_meta` anywhere in `dispatch_ipv4_frag`.

src/sixlowpan.rs:891-894
```rust
// The packet's metadata rides on its first fragment.
if first {
    tx_buffer.set_meta(buffer.meta());
}
```

xarxa-driver/src/lib.rs:269-270 says "The buffer's [`PacketMeta`] is whatever the sending socket attached to the packet". src/raw.rs:509 says "The metadata is handed to the driver along with the frame." Both UDP (`UdpMetadata`) and raw `send_with_meta` are affected.

## Failure scenario
With `packetmeta-timestamp`, an IP-medium interface with MTU 576. A UDP send of a 1000-byte datagram with meta `{ id: 7, request_timestamp: true }` returns `Ok`. The driver sees two fragments with id 0 and `request_timestamp` false. `Stack::poll_tx_timestamp` never reports id 7.

## Suggested fix
Copy `buffer.meta()` onto the first fragment, as 6LoWPAN does. Document on `PacketMeta` that a fragmented packet's meta rides on its first fragment.
