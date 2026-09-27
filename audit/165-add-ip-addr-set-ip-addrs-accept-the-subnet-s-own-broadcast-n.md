# 165. add_ip_addr/set_ip_addrs accept the subnet's own broadcast/network address and loopback addresses

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/iface/mod.rs:389](../src/iface/mod.rs#L389), [src/iface/mod.rs:435](../src/iface/mod.rs#L435), [src/iface/mod.rs:82](../src/iface/mod.rs#L82) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Validation is only `IpAddr::is_unicast`, which rejects 255.255.255.255, multicast and unspecified. A directed broadcast of the address's own prefix (10.0.0.255/24), an all-zero host part, 127.0.0.1/8 and ::1 are accepted. `AddrError::NotUnicast` is documented as covering broadcast.

## Details
src/iface/mod.rs:389:
```rust
if !cidr.address().is_unicast() {
    return Err(AddrError::NotUnicast);
}
```
src/wire/ipv4.rs:64:
```rust
!(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
```
With 10.0.0.255/24 assigned, `get_source_address_ipv4` picks it as source for 10.0.0.x, while ingress `is_unicast_v4` (mod.rs:902) treats it as broadcast. With ::1 assigned, `update_solicited_node_groups` joins ff02::1:ff00:1 but `has_solicited_node` excludes it, so each `config_changed` likely re-sends MLD reports (not demonstrated).

## Failure scenario
A user mistypes 192.168.1.255/24. `add_ip_addr` succeeds and packets to the subnet carry a broadcast source that peers must discard.

## RFC reference
RFC 1122 §3.2.1.3 (d): "Directed broadcast to the specified network. It MUST NOT be used as a source address."
RFC 4291 §2.5.3: "It must not be assigned to any physical interface."

## Reproduction
Test in `src/stack.rs` `mod test` (scratch copy), `cargo test --lib vv_ -- --nocapture`:
```rust
let (mut stack, _rx, _tx) = test_stack(Medium::Ethernet);
let h = IfaceHandle::new(0);
let r = stack.iface(h).add_ip_addr(IpCidr::new(Ipv4Addr::new(10, 0, 0, 255).into(), 24));
std::println!("directed bcast: {:?}", r);
let r = stack.iface(h).add_ip_addr(IpCidr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8));
std::println!("loopback: {:?}", r);
```
Output:
```
directed bcast: Ok(None)
loopback: Ok(None)
```

## Suggested fix
Reject IPv4 addresses equal to their prefix broadcast or with an all-zero host part (prefix below 31), and 127.0.0.0/8 and ::1. Or narrow the `NotUnicast` doc.
