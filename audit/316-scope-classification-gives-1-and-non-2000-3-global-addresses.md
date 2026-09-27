# 316. Scope classification gives ::1 and non-2000::/3 addresses Unknown scope, so ::1 can be picked as source

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/ipv6.rs:175](../src/wire/ipv6.rs#L175), [src/wire/ipv6.rs:136](../src/wire/ipv6.rs#L136), [src/iface/mod.rs:1089](../src/iface/mod.rs#L1089) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`x_multicast_scope` returns `MulticastScope::Unknown` (0xFF, above Global) for ::1 and for unicast addresses outside fe80::/64, fc00::/7 and 2000::/3, such as NAT64 64:ff9b::/96. Multicast scope nibbles other than 1/2/4/5/8/E (for example 3, realm-local) also map to Unknown. Rule 2 of source selection compares scopes as u8, so with ::1 assigned next to a global address, ::1 wins for such destinations. Only matters when ::1 is assigned on an interface, which the code allows.

## Details
src/wire/ipv6.rs:175:
```rust
fn x_multicast_scope(&self) -> MulticastScope {
    if self.is_multicast() {
        return MulticastScope::from(self.octets()[1] & 0b1111);
    }

    if self.is_link_local() {
        MulticastScope::LinkLocal
    } else if self.is_unique_local() || self.is_global_unicast() {
        // ULA are considered global scope
        // https://www.rfc-editor.org/rfc/rfc6724#section-3.1
        MulticastScope::Global
    } else {
        MulticastScope::Unknown
    }
}
```
`is_global_unicast` (line 136) is `(octets[0] >> 5) == 0b001`. Rule 2 in `get_source_address_ipv6`, src/iface/mod.rs:1089-1092:
```rust
// Rule 2: prefer appropriate scope.
let candidate_scope = candidate_cidr.address().x_multicast_scope() as u8;
let addr_scope = cidr.address().x_multicast_scope() as u8;
let dst_scope = dst_addr.x_multicast_scope() as u8;
```
For a destination of scope 0xFF, a ::1 candidate (0xFF) beats a Global one.

## Failure scenario
The application assigns ::1/128 next to a SLAAC global address and connects to a NAT64 address 64:ff9b::a.b.c.d. The SYN goes out with source ::1 and the connection never completes.

## RFC reference
RFC 6724 §3.4: "The loopback address MUST be treated as having link-local scope" and "NSAP addresses and other addresses with as-yet-undefined format prefixes MUST be treated as having global scope".

RFC 6724 §3.3: embedded-IPv4 addresses "MUST be treated as having global scope."

RFC 4291 §2.4: "implementations must treat all addresses that do not start with any of the above-listed prefixes as Global Unicast addresses."

## Reproduction
Added to `mod test` in src/stack.rs:
```rust
#[test] fn vtest_srcsel_loopback() {
    let (mut stack,_rx,_tx)=test_stack(Medium::Ip);
    let handle=IfaceHandle::new(0);
    let ll=Ipv6Addr::new(0xfe80,0,0,0,0,0,0,1);
    let gua=Ipv6Addr::new(0x2001,0xdb8,3,0,0,0,0,1);
    for order in 0..2 {
        let addrs = if order==0 {[IpCidr::new(ll.into(),64),IpCidr::new(gua.into(),64),IpCidr::new(Ipv6Addr::LOCALHOST.into(),128)]}
            else {[IpCidr::new(Ipv6Addr::LOCALHOST.into(),128),IpCidr::new(ll.into(),64),IpCidr::new(gua.into(),64)]};
        stack.iface(handle).set_ip_addrs(addrs).unwrap();
        let iface=stack.ifaces.get(0);
        let pick=|dst:Ipv6Addr| iface.get_source_address_ipv6(&dst, Instant::ZERO);
        println!("order {order}: nat64 -> {}, ff03::1 -> {}, 2001:db9::2 -> {}",
            pick(Ipv6Addr::new(0x64,0xff9b,0,0,0,0,0xc000,0x201)),
            pick(Ipv6Addr::new(0xff03,0,0,0,0,0,0,1)),
            pick(Ipv6Addr::new(0x2001,0xdb9,3,0,0,0,0,2)));
    }
}
```
Output:
```
order 0: nat64 -> ::1, ff03::1 -> ::1, 2001:db9::2 -> 2001:db8:3::1
order 1: nat64 -> ::1, ff03::1 -> ::1, 2001:db9::2 -> 2001:db8:3::1
```

## Suggested fix
For unicast, return LinkLocal for fe80::/10 and ::1, Global for everything else. Map the undefined multicast scope nibbles to sensible values. Consider excluding ::1 from candidates for non-loopback destinations.
