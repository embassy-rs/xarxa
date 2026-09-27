# 010. IPv4 packet fragmented on an IEEE 802.15.4 interface leaves IPv4 state in the fragmenter, and sixlowpan_egress then sends empty FRAGN frames forever

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/stack.rs:2670](../src/stack.rs#L2670), [src/stack.rs:2720](../src/stack.rs#L2720), [src/fragmentation.rs:138](../src/fragmentation.rs#L138), [src/fragmentation.rs:211](../src/fragmentation.rs#L211), [src/fragmentation.rs:264](../src/fragmentation.rs#L264), [src/sixlowpan.rs:858](../src/sixlowpan.rs#L858), [src/iface/mod.rs:783](../src/iface/mod.rs#L783) |
| Features | default (`ipv4`, `ipv4-fragmentation`, `medium-ieee802154`, `sixlowpan-fragmentation`) |
| Verification | reproduced with a test |

## Summary

`transmit_ip` fragments any oversized IPv4 packet before `dispatch_ip` drops IPv4 on 802.15.4. If `fragment_ipv4` runs out of pool buffers partway, the interface's fragmenter keeps IPv4 state. The next poll's `fragment_egress` picks `sixlowpan_egress` by medium, which reads that state with `fragn_size = 0`. It sends 10-byte FRAGN frames with no payload and never advances. With a driver that never reports busy, `poll` never returns. Otherwise every poll fills the radio with garbage and the interface reports busy to every socket forever.

## Details

The MTU branch runs before any medium check.

src/stack.rs:2670-2674
```rust
if total_ip_len > iface.ip_mtu() {
    match ethertype {
        // If we have an IPv4 packet, then we need to check if we need to fragment it.
        #[cfg(feature = "ipv4-fragmentation")]
        EthernetProtocol::Ipv4 => self.fragment_ipv4(iface, dst_addr, next_hop, buf),
```

The IPv4 drop happens later, per fragment, in `dispatch_ip`.

src/stack.rs:2720-2724
```rust
#[cfg(feature = "ipv4")]
if let IpAddr::V4(_) = dst_addr {
    debug!("dropping IPv4 packet routed to an IEEE 802.15.4 interface");
    return;
}
```

`fragment_ipv4` stores the packet with `frag.sent_bytes = ip_header_len` (src/fragmentation.rs:211) and leaves `frag.sixlowpan` at its reset value. It calls `ipv4_egress`, which builds each fragment in a new buffer, and `dispatch_ip` drops it. If `PacketBuf::try_new()` fails (src/fragmentation.rs:264), the rest stays in the fragmenter.

The next poll dispatches by medium.

src/fragmentation.rs:139-144
```rust
match iface.medium() {
    #[cfg(feature = "medium-ieee802154")]
    crate::iface::Medium::Ieee802154 => {
        #[cfg(feature = "sixlowpan-fragmentation")]
        self.sixlowpan_egress(iface)?;
    }
```

src/sixlowpan.rs:858-876
```rust
let first = frag.sent_bytes == 0;
let remaining = frag.packet_len - frag.sent_bytes;
let (frag_repr, frag_size) = if first {
    ...
} else {
    (
        SixlowpanFragRepr::Fragment { ... },
        remaining.min(frag.sixlowpan.fragn_size),
    )
};
```

`sent_bytes` is non-zero, so this is the FRAGN branch, and `fragn_size` is 0. The frame carries an empty FRAGN header (size 0, tag 0, offset 0) with absent addresses. `frag.sent_bytes += frag_size` (src/sixlowpan.rs:896) adds 0, so `finished()` never becomes true. The `while !iface.fragmenter.finished()` loop in `sixlowpan_egress` stops only when `can_transmit()` returns false. The driver then wakes the poll task and it starts again. With the trait default `can_transmit` (always true), `poll` loops forever.

Meanwhile `can_transmit_new_packet` sees a non-empty fragmenter (src/iface/mod.rs:783) and returns `Blocked::NoBuffer`, so UDP and raw sends on that interface, IPv6 included, get `DeviceBusy`.

In a build with `ipv4-fragmentation` and `medium-ieee802154` but without `sixlowpan-fragmentation`, `fragment_egress` does nothing for this medium. The fragmenter is never drained and the interface reports busy forever. This follows from the code and was not re-tested.

Device busy cannot trigger this, since the dropped fragments never use device room. Only pool exhaustion during `fragment_ipv4` does.

Ways an IPv4 packet reaches an 802.15.4 interface:

- `add_ip_addr` and `set_ip_addrs` accept IPv4 CIDRs on any medium, and routes can name any interface.
- `TxContext::route` (src/stack.rs:351-361) sends every broadcast and multicast destination out of the first interface. If the 802.15.4 interface was added first, IPv4 broadcast and multicast go there.

## Failure scenario

1. Default build. The 802.15.4 interface is added first, Ethernet second.
2. The application sends an IPv4 multicast UDP datagram larger than the 802.15.4 IP MTU while the pool is nearly empty. The send returns `Ok`.
3. `fragment_ipv4` runs out of buffers after the first fragments.
4. From then on, every poll fills the radio with empty FRAGN frames, or never returns if the driver never reports busy. Every UDP/raw send on the interface gets `DeviceBusy`.

## Reproduction

Added to the `mod test` of src/stack.rs in a scratch copy. `test_stack_with_room(Medium::Ieee802154)` gives the interface `OUR_V4/24`, and its IP MTU is 1280.

```rust
fn vhold_all_but(n: usize) -> Vec<PacketBuf> {
    let mut held = Vec::new();
    while let Some(b) = PacketBuf::try_new() { held.push(b); }
    for _ in 0..n { held.pop(); }
    held
}

#[test]
fn vzz_ipv4_frag_on_802154() {
    let (mut stack, _rx, tx, room) = test_stack_with_room(Medium::Ieee802154);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let held = vhold_all_but(1);
    let r = stack.udp_socket(udp).send_slice(&[0xab; 1400], (REMOTE_V4, 1000));
    drop(held);
    tx.borrow_mut().clear();
    room.set(Some(20)); // None => poll never returns
    stack.poll(Instant::from_millis(10));
    let n1 = tx.borrow().len();
    tx.borrow_mut().clear();
    room.set(Some(20));
    stack.poll(Instant::from_millis(20));
    room.set(Some(20));
    let r6 = stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V6, 1000));
    assert_eq!(n1, 0);
}
```

`cargo test --lib vzz_ipv4_frag_on_802154 -- --nocapture --test-threads=1` (printlns omitted above):

```
802154 ip_mtu = 1280
send result Ok(())
frames after send: 0
frames after poll1: 20 deadline Instant { millis: 86400010 }
  [41, 00, 09, 00, 00, e0, 00, 00, 00, 00]
  [41, 00, 0a, 00, 00, e0, 00, 00, 00, 00]
  [41, 00, 0b, 00, 00, e0, 00, 00, 00, 00]
frames after poll2: 20
ipv6 send result Err(DeviceBusy)
panicked: assertion `left == right` failed: left: 20 right: 0
```

With `room` left at `None` (unlimited) before the first poll, `timeout 60 cargo test ...` killed the process (exit 143): `poll` never returned.

## Suggested fix

- Drop IPv4 packets routed to an 802.15.4 interface in `transmit_ip`, before the MTU branch. Or check the medium in `fragment_ipv4`.
- Tag the fragmenter with the kind of packet it holds, so `fragment_egress` can never read one kind of state as the other.
