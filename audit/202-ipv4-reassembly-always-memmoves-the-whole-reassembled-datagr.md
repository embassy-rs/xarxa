# 202. IPv4 reassembly always memmoves the whole reassembled datagram

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/reassembly.rs:313](../src/reassembly.rs#L313), [src/reassembly.rs:82](../src/reassembly.rs#L82), [src/reassembly.rs:126](../src/reassembly.rs#L126), [src/stack.rs:1607](../src/stack.rs#L1607), [src/stack.rs:1846](../src/stack.rs#L1846) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The reassembly buffer comes from the pool with zero headroom and fragments are copied in from byte 0. On completion `ensure_headroom(header_len)` therefore always moves the whole payload. That doubles the one extra copy DESIGN §6 budgets for this path. An echo reply to a reassembled ping moves it again.

## Details
`PacketAssembler::buffer` (src/reassembly.rs:82-84) calls `PacketBuf::try_new()`, which gives zero headroom, and never reserves. `add` writes `buffer[offset..][..len]` (line 126).

src/reassembly.rs:313-317
```rust
if !payload.ensure_headroom(header_len) {
    ...
}
payload.push_front(header_len);
```
`ensure_headroom` takes the `copy_within` path every time. The buffer re-enters `process_ipv4` with headroom 0, and after `pull_front` has only the IP header length as headroom. The echo reply then moves it again:

src/stack.rs:1607
```rust
if !buf.ensure_headroom(LINK_HEADER_LEN + IPV4_HEADER_LEN) {
```
With `medium-ethernet` that needs 34 bytes against 20. Without it, `LINK_HEADER_LEN` is 0 and this second move does not happen.

6LoWPAN is narrower. src/sixlowpan.rs:723 adds the decompressed first fragment including its IPv6 header at offset 0, so completion needs no move. Only the ICMPv6 echo reply (src/stack.rs:1846) moves it, once.

## Failure scenario
A peer behind a smaller-MTU path sends 1400-byte UDP datagrams in two fragments. Each costs a copy from the fragments plus a full memmove at completion. A `ping -s 1400` across such a path costs a third move for the reply.

## Suggested fix
Reserve headroom when the assembler takes its buffer (`LINK_HEADER_LEN + 60` for IPv4, `LINK_HEADER_LEN` for 6LoWPAN, whose first fragment carries the IPv6 header). Check capacity against headroom + `total_size` in `set_total_size` and `add`, which also rejects oversized datagrams at the first fragment.
