# 303. DhcpPacket::sname() reads the wrong offset and returns Err(Malformed) for every normal packet

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/wire/dhcpv4.rs:185](../src/wire/dhcpv4.rs#L185), [src/wire/dhcpv4.rs:451](../src/wire/dhcpv4.rs#L451) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The field table puts CHADDR at 28..34 and SNAME at 34..108. On the wire chaddr is 16 bytes (28..44) and sname is 64 bytes (44..108). For an Ethernet chaddr, bytes 34..44 are zero padding, so the public `sname()` finds a NUL at index 0 and returns `Err(Malformed)`. If chaddr has more than 6 non-zero bytes, it returns the padding followed by the name instead.

## Details
src/wire/dhcpv4.rs:184-185:
```rust
pub const CHADDR: Field = 28..34;
pub const SNAME: Field = 34..108;
```
src/wire/dhcpv4.rs:451 reads `&self.buffer[field::SNAME]` and returns `Err(Malformed)` when the first NUL is at 0. The doc says `Malformed` means "the field is empty or not valid UTF-8". Nothing in the crate calls `sname()`. It is public through `xarxa::wire::DhcpPacket`. Emission is fine: `set_sname_and_boot_file_to_zero` zeroes 34..108, which also clears the chaddr padding. `boot_file()` (108..236) is correct.

## Failure scenario
An app parses a DHCPOFFER with `DhcpPacket` and calls `sname()` for the boot server name. It always gets `Err(Malformed)`.

## RFC reference
RFC 2131 §2, Table 1: "chaddr 16 Client hardware address." and "sname 64 Optional server host name, null terminated string."

## Reproduction
Added to `mod test` in src/wire/dhcpv4.rs, scratch copy:
```rust
#[test]
fn verify_sname_offset() {
    let mut buf = vec![0u8; 300];
    buf[0] = 2; buf[1] = 1; buf[2] = 6;
    buf[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    buf[44..48].copy_from_slice(b"srv1");
    buf[236..240].copy_from_slice(&[99, 130, 83, 99]);
    buf[240] = 255;
    let p = Packet::new_unchecked(&mut buf[..]);
    assert_eq!(p.sname(), Ok("srv1"));
}
```
`cargo test --lib verify_ -- --nocapture`:
```
assertion `left == right` failed
  left: Err(Malformed)
 right: Ok("srv1")
```

## Suggested fix
Set SNAME to 44..108. Keep a 6-byte accessor for chaddr if wanted, but use a separate 16-byte constant for the layout. Add a test for `sname()`.
