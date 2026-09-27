# 051. Single reassembly slot with no eviction: one stray fragment blocks all IPv4/6LoWPAN reassembly for 60 s

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/reassembly.rs:179](../src/reassembly.rs#L179), [src/reassembly.rs:91](../src/reassembly.rs#L91), [src/reassembly.rs:112](../src/reassembly.rs#L112), [src/reassembly.rs:277](../src/reassembly.rs#L277), [src/stack.rs:1316](../src/stack.rs#L1316), [src/stack.rs:1400](../src/stack.rs#L1400), [build.rs:26](../build.rs#L26) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`PacketAssemblerSet::get` only returns a slot with the same key or a free one. It never evicts. `REASSEMBLY_BUFFER_COUNT` defaults to 1. So any fragment that starts a datagram that never completes holds the only slot, and a pool buffer, for `reassembly_timeout` (60 s). Every other fragmented datagram, IPv4 or 6LoWPAN, from any peer is dropped in that time. Datagrams that are known to be uncompletable are not released early, and fragments not addressed to us also take the slot.

## Details

src/reassembly.rs:179:

```rust
pub(crate) fn get(&mut self, key: &K, expires_at: Instant) -> Result<&mut PacketAssembler<K>, AssemblerFullError> {
    let mut empty_slot = None;
    for slot in &mut self.assemblers {
        if slot.key.as_ref() == Some(key) {
            return Ok(slot);
        }
        if slot.is_free() {
            empty_slot = Some(slot)
        }
    }

    let slot = empty_slot.ok_or(AssemblerFullError)?;
```

`reassemble_ipv4` (src/reassembly.rs:277) drops the fragment on `AssemblerFullError`. The slot's key and expiry are set by `get` before any validation. None of the later error paths reset it:

- Total size larger than `PACKET_BUF_SIZE`: `set_total_size` fails (src/reassembly.rs:99), `check!` returns. The slot, and the buffer taken by an earlier fragment, stay. A 3000-byte UDP datagram (a large EDNS DNS answer) does this.
- Middle fragments past the buffer fail the capacity check in `add` (src/reassembly.rs:115). Same result.
- `add` fails when the pool is empty (`buffer()` returns `AssemblerError`). Same result.
- A second last fragment with a different total fails at src/reassembly.rs:92-96. The slot stays.
- A fragment extending past the declared total makes `peek_front() > total_size`, so `is_complete` (src/reassembly.rs:150) is never true.

Reassembly runs in `process_ipv4` right after the header checksum (src/stack.rs:1316), before the "not for us" check at src/stack.rs:1400:

```rust
#[cfg(feature = "ipv4-reassembly")]
let mut buf = if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
    let Some(buf) = self.reassemble_ipv4(buf) else {
        return;
    };
```

So a fragment for another IP takes the slot, as long as the link layer delivers it: any packet on an IP-medium interface, or on Ethernet a frame to our MAC or to broadcast/multicast (src/stack.rs:1248-1253). The reassembled packet is then thrown away.

`remove_expired` runs only at the end of `poll` (src/stack.rs:1222). Fragments that arrive in the poll where the old slot expires are still refused.

The slot is shared with 6LoWPAN (src/config.rs:152, "IPv4 and 6LoWPAN together"). `process_sixlowpan_fragment` (src/sixlowpan.rs:685) claims it before `set_total_size` and decompression in the same way.

The 60 s timeout itself is within RFC 1122 §3.3.2's recommended range. The problem is the single slot with no eviction and no early release.

## Failure scenario

- An off-path host sends one IPv4 fragment with MF=1 and a random ident every 59 s, to our address or to any address on an IP-medium link. No ident guessing is needed.
- Or one fragment of a legitimate datagram is lost on a lossy link.
- Or a peer sends a datagram larger than a packet buffer.

For the next 60 s every fragmented datagram to this host is silently dropped. Large DNS answers, tunnels and fragmented UDP from peers whose PMTUD failed stall for a minute each time.

## Reproduction

Tests in the `stack.rs` test module (`test_stack(Medium::Ip)`, raw socket on protocol 99), run in a scratch copy of the crate:

```rust
#[test]
fn vrfy_reassembly_slot_hog_not_for_us() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    let handle = stack.add_raw_socket().unwrap();
    stack.raw_socket(handle).bind(RawMode::Ip { version: Some(IpVersion::V4), protocol: Some(IpProtocol(99)) }).unwrap();
    let proto = IpProtocol(99);
    let stray = ipv4_fragment(Ipv4Addr::new(1,2,3,4), Ipv4Addr::new(10,9,9,9), proto, 0x7777, true, 0, &[0; 8]);
    rx.borrow_mut().push_back(stray);
    println!("deadline after stray = {:?}", stack.poll(Instant::from_secs(0)));
    let frag1 = ipv4_fragment(REMOTE_V4, OUR_V4, proto, 0x1234, true, 0, &[0xAA; 24]);
    let frag2 = ipv4_fragment(REMOTE_V4, OUR_V4, proto, 0x1234, false, 24, &[0xBB; 6]);
    rx.borrow_mut().push_back(frag1.clone()); rx.borrow_mut().push_back(frag2.clone());
    stack.poll(Instant::from_secs(2));
    assert!(!stack.raw_socket(handle).can_recv());
    rx.borrow_mut().push_back(frag1); rx.borrow_mut().push_back(frag2);
    stack.poll(Instant::from_secs(61)); stack.poll(Instant::from_secs(61));
    println!("after 61s can_recv = {}", stack.raw_socket(handle).can_recv());
}
```

A second test, `vrfy_reassembly_slot_hog_oversize`, uses the same setup. It injects ident 0x5555 at offset 0 (1000 B, MF=1) and the last fragment at offset 2000 (1000 B), then the valid 0x1234 pair at t=1 s, and asserts `!can_recv()`.

Output:

```
vrfy_reassembly_slot_hog_not_for_us: deadline after stray = Instant { millis: 60000 }; after 61s can_recv = false; ok
vrfy_reassembly_slot_hog_oversize: deadline = Instant { millis: 60000 }; ok
```

## Suggested fix

- Reset the assembler when the datagram is known not to be completable: `set_total_size` error, `add` error, data past `total_size`, a `total_size` mismatch.
- When the set is full and a new key arrives, evict the oldest slot (or the one with the nearest expiry).
- Check the destination address before reassembling (keeping the DHCP exception). Every fragment carries it.
- Consider a shorter default timeout for small-memory builds.
