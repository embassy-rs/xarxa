# 009. A failed or late 6LoWPAN fragment pins the only reassembly slot for 60 s

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/sixlowpan.rs:682](../src/sixlowpan.rs#L682), [src/sixlowpan.rs:703](../src/sixlowpan.rs#L703), [src/sixlowpan.rs:711](../src/sixlowpan.rs#L711), [src/sixlowpan.rs:723](../src/sixlowpan.rs#L723), [src/sixlowpan.rs:729](../src/sixlowpan.rs#L729), [src/reassembly.rs:179](../src/reassembly.rs#L179), [build.rs:26](../build.rs#L26) |
| Features | `sixlowpan-reassembly` (default), `REASSEMBLY_BUFFER_COUNT = 1` (default) |
| Verification | reproduced with a test |

## Summary

`process_sixlowpan_fragment` claims an assembler slot before anything that can fail. None of the later error returns reset it, so the slot holds that key until `reassembly_timeout` (60 s). A late duplicate of a fragment of an already completed datagram also claims a new slot that can never complete. The default set has one slot, shared with IPv4 reassembly, so every other fragmented datagram is dropped for 60 s.

## Details

src/sixlowpan.rs:682-692
```rust
let frag_slot = match self
    .fragments
    .assembler
    .get(&key, self.inner.now + self.fragments.reassembly_timeout)
{
    Ok(frag) => frag,
    Err(_) => {
        debug!("No available packet assembler for fragmented packet");
        return None;
    }
};
```

src/reassembly.rs:190-193
```rust
let slot = empty_slot.ok_or(AssemblerFullError)?;
slot.key = Some(*key);
slot.expires_at = expires_at;
Ok(slot)
```

The error paths after the claim only return:

- src/sixlowpan.rs:703: `set_total_size(datagram_size)` fails, for example `datagram_size` larger than the packet buffer.
- src/sixlowpan.rs:711-722: `sixlowpan_to_ipv6` fails. Examples: an unknown address context, an unsupported encoding such as M=1 DAC=1, an elided UDP checksum in FRAG1 (rejected at src/sixlowpan.rs:369-372), a header chain that doesn't fit FRAG1.
- src/sixlowpan.rs:723 and :729: `frag_slot.add` fails (out of range, too many holes, no buffer).

`assemble()` only resets the slot on success. `remove_expired` frees it at `expires_at`.

For a non-first fragment, `add()` also takes a pool `PacketBuf`, which stays pinned for the 60 s. In the FRAG1 decompression failure case only the slot is held, since the buffer is allocated lazily in `add()`.

The duplicate case happens in normal operation. xarxa does no 802.15.4 sequence-number duplicate detection. When the MAC ACK for a last fragment is lost, the sender retransmits that frame. The datagram has already completed and freed its slot, so the duplicate opens a new one with the same key. The existing `test_reassembly_duplicates` (src/sixlowpan.rs:1885) records "Late duplicates start a new, never completed, reassembly" but not that the slot then stays busy.

Holding a slot for a real incomplete datagram is intended (`test_reassembly_slots_full`). The problem is that benign events hold it with entries that can never complete.

Over 6LoWPAN every full-size TCP segment is fragmented. One lost MAC ACK stalls all fragmented ingress for 60 s, and TCP backoff stretches that further. IPv4 reassembly on other interfaces is blocked too, because the slot set is stack-global. The trigger is 6LoWPAN-specific.

## Failure scenario

1. A peer sends a 300-byte UDP datagram in 4 fragments.
2. The MAC ACK for fragment 4 is lost and the peer retransmits it.
3. xarxa delivers the datagram, then files the duplicate in a new slot.
4. For the next 60 s every fragmented datagram from any node, TCP retransmissions included, is dropped with "No available packet assembler".

The same happens after one FRAG1 that xarxa cannot decompress, for example one using address context 0 when none is configured.

## RFC reference

RFC 4944 §5.3: "The reassembly timeout MUST be set to a maximum of 60 seconds (this is also the timeout in the IPv6 reassembly procedure [RFC2460])."

60 s is the upper bound, not a required value.

## Reproduction

Added to the `mod test` of src/sixlowpan.rs in a scratch copy:

```rust
#[test]
#[cfg(feature = "sixlowpan-reassembly")]
fn v5_dup_last_fragment_pins_slot() {
    let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
    let frames = big_datagram(1);
    for f in &frames { inject(&mut stack, &rx, f.clone()); }
    check_received(&mut stack, udp);
    inject(&mut stack, &rx, frames[3].clone()); // MAC-level retransmission
    let d = stack.poll(Instant::from_secs(1));
    println!("deadline after dup: {:?}", d);
    for f in &big_datagram(2) { inject(&mut stack, &rx, f.clone()); }
    let r1 = stack.udp_socket(udp).recv().err();
    println!("second datagram at t=1s: {:?}", r1);
    stack.poll(Instant::from_secs(59));
    for f in &big_datagram(3) { inject(&mut stack, &rx, f.clone()); }
    println!("third datagram at t=59s: {:?}", stack.udp_socket(udp).recv().err());
    stack.poll(Instant::from_secs(61));
    for f in &big_datagram(4) { inject(&mut stack, &rx, f.clone()); }
    println!("fourth datagram at t=61s ok: {:?}", stack.udp_socket(udp).recv().is_ok());
    assert_eq!(r1, None, "second datagram was dropped");
}

#[test]
#[cfg(feature = "sixlowpan-reassembly")]
fn v5_bad_frag1_pins_slot() {
    let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
    let bad = big_datagram(7);
    let mac_len = mac_repr(PEER_LL, OUR_LL, Some(PAN)).buffer_len();
    let mut f0 = bad[0].clone();
    f0[mac_len + 4 + 1] |= 0x40; // SAC=1, context 0 which we lack
    inject(&mut stack, &rx, f0);
    stack.poll(Instant::from_secs(1));
    for f in &big_datagram(1) { inject(&mut stack, &rx, f.clone()); }
    assert_eq!(stack.udp_socket(udp).recv().err(), None, "good datagram dropped after bad FRAG1");
}
```

`cargo test --lib v5_ -- --nocapture`:

```
deadline after dup: Instant { millis: 60000 }
second datagram at t=1s: Some(Exhausted)
third datagram at t=59s: Some(Exhausted)
fourth datagram at t=61s ok: true
panicked: assertion failed: second datagram was dropped
panicked: assertion failed: good datagram dropped after bad FRAG1 (left: Some(Exhausted))
```

## Suggested fix

- Validate what can be validated before claiming a slot, and `reset()` the slot on every error path after the claim.
- Remember recently completed keys for a short time and drop late duplicates of them.
- Consider a shorter default reassembly timeout for 6LoWPAN.
