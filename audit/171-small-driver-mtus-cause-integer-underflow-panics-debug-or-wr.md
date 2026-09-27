# 171. Small driver MTUs cause integer underflow panics (debug) or wrapped sizes (release) in ip_mtu, TCP MSS and DHCP

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/iface/mod.rs:731](../src/iface/mod.rs#L731), [src/tcp/mod.rs:1911](../src/tcp/mod.rs#L1911), [src/iface/dhcpv4.rs:491](../src/iface/dhcpv4.rs#L491), [src/iface/dhcpv4.rs:495](../src/iface/dhcpv4.rs#L495) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`add_iface` does not validate `Capabilities::max_transmission_unit`, and no minimum is documented. Several size computations subtract header lengths without saturation. Small MTUs panic in debug builds and wrap to garbage sizes in release.

## Details
src/iface/mod.rs:731, underflows below 14:
```rust
Medium::Ethernet => caps.max_transmission_unit - ETHERNET_HEADER_LEN,
```
src/tcp/mod.rs:1911, underflows for IP MTUs below 40 to 80 depending on version and options:
```rust
let local_mss = self.ip_mtu - ip_header_len - TCP_HEADER_LEN;
```
src/iface/dhcpv4.rs:491, underflows below 68 (and line 495 similarly):
```rust
let max_size = (ip_mtu - MAX_IPV4_HEADER_LEN - UDP_HEADER_LEN) as u16;
```
For 802.15.4 without `sixlowpan-fragmentation`, `sixlowpan::ip_mtu` uses `saturating_sub`, so it returns a small value (possibly 0). The panic then moves to the TCP MSS computation. In release, `local_mss` wraps and a garbage MSS option is advertised. On Ethernet with MTU 10, `ip_mtu` wraps and is capped to 1500, so the stack sends frames the device can't take.

The trigger is a driver-supplied value, not network input.

## Failure scenario
A driver reads the MTU from a register that is 0 before the MAC is initialized. `add_iface` succeeds, and the first send panics (debug). Or an 802.15.4 driver reports MTU 70 without fragmentation: `ip_mtu` is 53 and `53 - 40 - 20` panics in TCP dispatch.

## Reproduction
`stack` module test harness, scratch copy:
```rust
#[test]
fn vv_small_mtu_panics() {
    let r = std::panic::catch_unwind(|| {
        let (mut stack, _rx, _tx, _room) = test_stack_with_mtu(Medium::Ethernet, 10);
        stack.iface(IfaceHandle::new(0)).ip_mtu()
    });
    assert!(r.is_ok(), "panicked");
}
```
Output: `thread 'stack::test::vv_small_mtu_panics' panicked at src/iface/mod.rs:731:33: attempt to subtract with overflow`

## Suggested fix
Reject MTUs below a documented minimum at `add_iface` (medium header plus 68 for IPv4, or plus what TCP needs). Use saturating arithmetic in the MSS and DHCP size computations.
