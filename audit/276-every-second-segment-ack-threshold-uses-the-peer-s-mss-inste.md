# 276. Every-second-segment ACK threshold uses the peer's MSS instead of our own (RMSS)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1675](../src/tcp/mod.rs#L1675) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`immediate_ack_to_transmit` forces an ACK once more than `remote_mss` bytes are unacknowledged. RMSS in SHLD-19 is the MSS of the receiving endpoint, which is us. When the peer's MSS is larger than the segments it can send us, we ACK only every 3rd or later segment, or at the delayed-ACK timer.

## Details
src/tcp/mod.rs:1675:
```rust
remote_last_ack + self.remote_mss < self.remote_seq_no + self.rx_buffer.len()
```
The function's own doc comment quotes RMSS as the MSS of the endpoint receiving the segments.

## Failure scenario
- A small `PACKET_BUF_SIZE` build advertises MSS 536, the Linux peer advertises 1460. We ACK after the 3rd segment.
- 6LoWPAN: local MSS around 48, peer MSS 1220. About 25 segments per ACK, so in practice the 10 ms timer.
- If the peer sent no MSS option (536 default) and our MSS is larger, we ACK every segment.

Slower ACK clocking slows the peer's slow start and fast retransmit.

## RFC reference
RFC 9293 §3.8.6.3: "An ACK SHOULD be generated for at least every second full-sized segment or 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the segments to be acknowledged, or the default value if not specified) (SHLD-19)."

## Suggested fix
Use the MSS we advertised (derived from the interface IP MTU) as the threshold.
