# 098. UDP and raw sends bigger than the egress interface's IP MTU (IPv6, or IPv4 without fragmentation) return Ok and are dropped silently

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/udp.rs:919](../src/udp.rs#L919), [src/raw.rs:561](../src/raw.rs#L561), [src/raw.rs:612](../src/raw.rs#L612), [src/stack.rs:2670](../src/stack.rs#L2670), [src/udp.rs:808](../src/udp.rs#L808), [src/raw.rs:102](../src/raw.rs#L102) |
| Features | default (IPv4 is affected only without `ipv4-fragmentation`) |
| Verification | reproduced with a test |

This is the same defect as [074](074-udp-and-raw-sends-larger-than-the-egress-ip-mtu-return-ok-bu.md), found again independently by four reports in the gap round.

## Summary

UDP and raw IP sends check the payload only against the `PacketBuf` capacity. `StackInner::transmit_ip` then drops any packet larger than `iface.ip_mtu()` that it cannot fragment, IPv6 always and IPv4 without `ipv4-fragmentation`, with only a debug log. The send has already returned `Ok`. This contradicts the documented error contract and DESIGN.md §7, and the application cannot detect the limit or react to it.

## Details

src/udp.rs:919, the only size check in `prepare_datagram`. The route, with its `ip_mtu`, was computed at src/udp.rs:873-876:

```rust
if max_size > buf.capacity() - headroom {
    return Err(SendError::BufferFull);
}
```

src/raw.rs:561 has the same capacity-only check, and src/raw.rs:612-613 always reports success:

```rust
self.tx.transmit_raw_ip(&route, buf, dst_addr);
Ok(())
```

src/stack.rs:2670, `StackInner::transmit_ip`:

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
- src/raw.rs:102: "The packet does not fit in a packet buffer."
- DESIGN.md §7: "`Ok` means the packet is in the device or parked on a neighbor resolution; it is never dropped on the way there."

Setups where `ip_mtu` is below the buffer limit:
- A driver reporting an MTU below 1514/1500 (1280 is common for tunnels and USB-NCM).
- 802.15.4 with `sixlowpan-fragmentation`: `ip_mtu` is 1280, but UDP payloads up to about 1452 bytes pass the buffer check.
- 802.15.4 without it: `ip_mtu` is about 100 bytes.

Raw Ethernet frames are not checked against the device MTU either. `TxContext::transmit_ethernet` hands them straight to the driver. This was not tested, and the result depends on the driver.

Missing IPv6 fragmentation is a documented gap. Reporting success for a packet that is certain to be dropped is the bug here.

## Failure scenario

A 6LoWPAN node (`ip_mtu` 1280) sends a 1300-byte CoAP datagram over IPv6. `send_slice` returns `Ok`, nothing is transmitted, and no error ever reaches the application, which has no way to learn it should send smaller datagrams.

## Reproduction

Test in `mod test` of src/stack.rs, in a scratch copy of the crate:

```rust
#[test]
fn v_udp_over_mtu() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ip, 1280);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(udp).send_slice(&[0; 1000], (REMOTE_V6, 9)); // Ok, tx=1
    tx.borrow_mut().clear();
    let r = stack.udp_socket(udp).send_slice(&[0; 1300], (REMOTE_V6, 9));
    let n6 = tx.borrow().len();
    tx.borrow_mut().clear();
    let r4 = stack.udp_socket(udp).send_slice(&[0; 1300], (REMOTE_V4, 9));
    tx.borrow_mut().clear();
    let raw = stack.add_raw_socket().unwrap();
    stack.raw_socket(raw).bind(crate::raw::RawMode::Ip { version: None, protocol: None }).unwrap();
    let pkt = ipv6_packet(OUR_V6, REMOTE_V6, IpProtocol::Udp,
        &udp_datagram(OUR_V6.into(), 1, REMOTE_V6.into(), 2, &[0; 1300]));
    let rr = stack.raw_socket(raw).send_slice(&pkt);
    assert!(!(r.is_ok() && n6 == 0), "Ok but nothing sent");
}
```

`cargo test --lib v_udp_over_mtu -- --nocapture`:

```
1000: Ok(()) tx=1
1300 v6: Ok(()) tx=0
1300 v4: Ok(()) tx=2
raw v6 1348: Ok(()) tx=0
panicked: Ok but nothing sent
```

## Suggested fix

In `prepare_datagram` and in the raw IP send path, compare the final IP packet size against `route.ip_mtu` and return an error (`BufferFull`, or a new `PacketTooLarge`) when it cannot go out: IPv6 always, IPv4 without `ipv4-fragmentation`. Check raw Ethernet frames against the device MTU. Update the `BufferFull` docs to match.
