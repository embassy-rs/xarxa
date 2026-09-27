# 360. Public `checksum::pseudo_header` panics via `unreachable!()` on mixed address families, undocumented

| | |
|---|---|
| Severity | info |
| Category | api |
| Location | [src/wire/ip.rs:605](../src/wire/ip.rs#L605), [src/wire/ip.rs:612](../src/wire/ip.rs#L612) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`xarxa::wire::checksum::pseudo_header` is public (`pub use self::ip::checksum` at src/wire/mod.rs:125) and has no doc comment. If one address is IPv4 and the other IPv6, it panics with "entered unreachable code". The `UdpPacket`/`TcpPacket` checksum methods document this panic. The helper does not.

## Details
src/wire/ip.rs:605:
```rust
pub fn pseudo_header(src_addr: &Address, dst_addr: &Address, next_header: Protocol, length: u32) -> u16 {
    match (src_addr, dst_addr) {
        ...
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}
```
Internal callers always pass same-family pairs.

## Reproduction
Test added to the `src/wire/ip.rs` test module in a scratch copy:
```rust
#[test]
#[should_panic]
fn zz_pseudo_mixed() {
    use crate::wire::{Ipv4Addr, Ipv6Addr, IpProtocol};
    checksum::pseudo_header(&Address::V4(Ipv4Addr::new(1,2,3,4)), &Address::V6(Ipv6Addr::LOCALHOST), IpProtocol::Udp, 8);
}
```
Output: `panicked at src/wire/ip.rs:612:18: internal error: entered unreachable code` (test passes).

## Suggested fix
Add a doc comment with a Panics section, or expose only `pseudo_header_v4`/`pseudo_header_v6`.
