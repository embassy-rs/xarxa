# 219. Stale interface bindings survive remove_iface and silently apply to a new interface that reuses the index

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:751](../src/stack.rs#L751), [src/raw.rs:308](../src/raw.rs#L308), [src/raw.rs:502](../src/raw.rs#L502), [src/raw.rs:540](../src/raw.rs#L540) |
| Features | iface-bind, raw-ethernet (default) |
| Verification | reproduced with a test |

## Summary
`remove_iface` purges neighbors, parked packets, routes and `tx_blocked_on`, but not the `IfaceBinding` of UDP, TCP and raw sockets, listeners or outstanding `AcceptToken`s. The next `add_iface` reuses the slot, so those sockets silently start using the new interface. An Ethernet-mode raw socket then hands Ethernet frames to a non-Ethernet driver, bypassing the medium check `bind` does.

## Details
src/stack.rs:751-775 clears only `neighbor_cache`, `pending`, `routes` and `tx_blocked_on`. The `InvalidMedium` check is only in `RawSocket::bind` (src/raw.rs:304-308). Send uses the binding directly (src/raw.rs:540-552) and goes `transmit_ethernet` -> `transmit_raw` -> `driver.transmit`, with no medium check.

src/raw.rs:502 documents "Panics if the socket is bound to an interface that has been removed". That holds only between removal and reuse. After reuse, send neither panics nor errors.

The binding is a handle the user supplied, and handle reuse is documented as the user's responsibility (DESIGN.md §2). That lowers severity. The doc contradiction and the medium bypass remain.

## Failure scenario
The app removes a Wi-Fi interface (Ethernet medium) and adds a cellular modem (IP medium), which gets the same handle. An LLDP/ARP helper raw socket bound to Wi-Fi keeps sending Ethernet frames, now into the modem driver. UDP sockets pinned to Wi-Fi now go out over cellular.

## Reproduction
Test in the `stack.rs` test module:
```rust
#[test]
#[cfg(all(feature = "iface-bind", feature = "raw-ethernet"))]
fn vv_remove_iface_rebind() {
    let mut stack = Stack::new(1, Instant::ZERO);
    let d0 = TestDevice::new(Medium::Ethernet);
    let h0 = d0.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));
    let raw = stack.add_raw_socket().unwrap();
    stack.raw_socket(raw).bind_to_iface(Some(h0)).unwrap();
    stack.raw_socket(raw).bind(RawMode::Ethernet { ethertype: None }).unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind_to_iface(Some(h0)).unwrap();
    stack.remove_iface(h0);
    let d1 = TestDevice::new(Medium::Ip);
    let tx1 = d1.tx.clone();
    let h1 = d1.install(&mut stack, HardwareAddress::Ip);
    println!("h0={:?} h1={:?}", h0, h1);
    let r = stack.raw_socket(raw).send_slice(&[0xff; 60]);
    println!("raw send {:?} tx1={}", r, tx1.borrow().len());
    println!("udp bound_iface {:?}", stack.udp_socket(udp).bound_iface());
}
```
Output:
```
h0=IfaceHandle(0) h1=IfaceHandle(0)
raw send Ok(()) tx1=1
udp bound_iface Some(IfaceHandle(0))
```

## Suggested fix
In `remove_iface`, reset or close every socket and listener bound to the handle. Check the medium in the raw Ethernet send path too, and fix the `send_with` panic doc. The dropped iface waker is covered by finding 218.
