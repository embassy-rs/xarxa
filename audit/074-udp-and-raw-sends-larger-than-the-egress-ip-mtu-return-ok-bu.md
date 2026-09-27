# 074. UDP and raw sends larger than the egress IP MTU return Ok but are silently dropped

| | |
|---|---|
| Severity | medium |
| Category | doc-mismatch |
| Location | [src/stack.rs:2670](../src/stack.rs#L2670), [src/udp.rs:919](../src/udp.rs#L919), [src/raw.rs:561](../src/raw.rs#L561), [src/udp.rs:808](../src/udp.rs#L808), [src/raw.rs:496](../src/raw.rs#L496) |
| Features | default (IPv4 is affected only without `ipv4-fragmentation`) |
| Verification | reproduced with a test |

## Summary

UDP and raw-IP sends only check the payload against the packet buffer capacity, not against the route's IP MTU. `StackInner::transmit_ip` then drops any IPv6 packet over the interface MTU, and any IPv4 packet over it when `ipv4-fragmentation` is off, with only a debug log. By then the send has returned `Ok(())`. That contradicts the `send_with` docs and DESIGN.md §7.

## Details

src/udp.rs:919, in `prepare_datagram`. `route.ip_mtu` is available but not used:

```rust
if max_size > buf.capacity() - headroom {
    return Err(SendError::BufferFull);
}
```

src/raw.rs:561 has the same capacity-only check.

src/stack.rs:2670, in `StackInner::transmit_ip`:

```rust
if total_ip_len > iface.ip_mtu() {
    match ethertype {
        #[cfg(feature = "ipv4-fragmentation")]
        EthernetProtocol::Ipv4 => self.fragment_ipv4(iface, dst_addr, next_hop, buf),
        #[cfg(not(feature = "ipv4-fragmentation"))]
        EthernetProtocol::Ipv4 => {
            debug!("Enable the `ipv4-fragmentation` feature for fragmentation support. Dropping");
        }
        _ => {
            debug!("IPv6 fragmentation support is unimplemented. Dropping.");
        }
    }
    return;
}
```

The docs say otherwise:
- src/udp.rs:808: "`BufferFull`: if the payload cannot fit in a packet buffer."
- src/raw.rs:496: "`BufferFull`: if the packet cannot fit in a packet buffer."
- DESIGN.md §7: "`Ok` means the packet is in the device or parked on a neighbor resolution; it is never dropped on the way there."

README lists IPv6 fragmentation as not implemented. The silent `Ok` is not documented.

The case is common:
- 802.15.4: IP MTU 1280 with `sixlowpan-fragmentation`, about 100 bytes without it.
- Any driver whose MTU is below the buffer size (PPP or cellular on `Medium::Ip`, a `packet-buf-size` raised for VLAN tags).

Stack-generated packets over the MTU are dropped the same way, for example an ICMPv6 echo reply routed out of an interface with a smaller MTU than the one the request came in on. Those are best-effort.

## Failure scenario

An application on an interface with IP MTU 1280 sends a 1400-byte UDP datagram to an IPv6 peer. `send_slice` returns `Ok(())`. Nothing is transmitted and no error is ever reported.

## Reproduction

Test added to `mod test` in src/stack.rs, in a scratch copy of HEAD:

```rust
#[test]
fn vzz_udp_v6_over_mtu_silent() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ip, 1280);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(udp).send_slice(&[0; 1400], (REMOTE_V6, 53));
    println!("send result {:?}, frames {}", r, tx.borrow().len());
    assert!(!(r.is_ok() && tx.borrow().is_empty()), "Ok but nothing sent");
}
```

Command: `cargo test --lib vzz_udp_v6_over_mtu_silent -- --nocapture --test-threads=1`

Output:

```
send result Ok(()), frames 0
panicked at src/stack.rs:3118:9: Ok but nothing sent
```

## Suggested fix

In `prepare_datagram` and the raw IP send, reject a packet whose IP length would exceed `route.ip_mtu`, unless it is IPv4 and `ipv4-fragmentation` is on. Use a new error variant, or `BufferFull` with updated docs.
