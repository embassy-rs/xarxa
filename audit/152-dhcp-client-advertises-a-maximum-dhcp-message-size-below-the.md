# 152. DHCP client advertises a Maximum DHCP Message Size below the legal minimum of 576

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:491](../src/iface/dhcpv4.rs#L491), [src/iface/dhcpv4.rs:540](../src/iface/dhcpv4.rs#L540) |
| Features | default (`dhcpv4`) |
| Verification | reproduced with a test |

## Summary
Option 57 is computed as `ip_mtu - 60 - 8` with no lower bound. Any interface with an IP MTU below 644 (Ethernet frame MTU below 658) advertises a value under 576. With `packet-buf-size-590`, the documented minimum for DHCP, it is always 508. A driver MTU below 82 makes the subtraction underflow.

## Details
src/iface/dhcpv4.rs:490-491:
```rust
const MAX_IPV4_HEADER_LEN: usize = 60;
let max_size = (ip_mtu - MAX_IPV4_HEADER_LEN - UDP_HEADER_LEN) as u16;
```
The build assert at line 36 accepts `PACKET_BUF_SIZE >= LINK_HEADER_LEN + 576`, so ip_mtu can be 576.

Related: `parameter_request_list: Some(&[])` emits option 55 with length 0, which RFC 2132 §9.8 forbids.

## Failure scenario
A driver reports a 600-byte MTU. ip_mtu is 586 and every DISCOVER/REQUEST carries option 57 = 518. A strict server may ignore the option or the message.

## RFC reference
RFC 2132 §9.10: "The code for this option is 57, and its length is 2. The minimum legal value is 576 octets."

RFC 2132 §9.8: "The code for this option is 55. Its minimum length is 1."

## Reproduction
Test in the `src/iface/dhcpv4.rs` test module:
```rust
#[test]
fn vv_small_mtu_max_size() {
    let driver = TestDevice::new(Medium::Ethernet).with_mtu(600);
    let tx = driver.tx.clone();
    let mut stack = Stack::new(1, at(0));
    let h = driver.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));
    stack.poll(at(0)); tx.borrow_mut().clear();
    stack.iface(h).set_dhcpv4(Some(DhcpConfig::default())).unwrap();
    stack.poll(at(0));
    let mut sent = parse_sent(&tx.borrow()[0]);
    let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
    let v = packet.option(field::OPT_MAX_DHCP_MESSAGE_SIZE).unwrap();
    let v = u16::from_be_bytes([v[0], v[1]]);
    assert!(v >= 576, "max size {} < 576", v);
}
```
Output: `panicked: max size 518 < 576`.

## Suggested fix
Clamp to at least 576, or omit option 57 when the computed value is below 576. Use saturating arithmetic. Skip option 55 when the list is empty.
