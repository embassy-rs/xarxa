# 163. Non-unicast hardware addresses are accepted by add_iface and set_hardware_addr

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/iface/mod.rs:346](../src/iface/mod.rs#L346), [src/stack.rs:653](../src/stack.rs#L653) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Only the address kind is checked. A group-bit, broadcast or all-zero MAC is accepted, becomes the source of every frame and the NDISC/ARP link-layer address, and a link-local IID is derived from it. Triggering it needs a driver bug or a misuse. It cannot come from the network.

## Details
src/stack.rs:653:
```rust
let hardware_addr = HardwareAddress::from_driver(driver.hardware_address())
    .filter(|addr| addr.medium() == medium)
    .ok_or(AddIfaceError::HardwareAddrMismatch)?;
```
src/iface/mod.rs:346:
```rust
if addr.medium() != self.state().medium() {
    return Err(MediumMismatch);
}
```

## Failure scenario
A driver without a provisioned MAC reports ff:ff:ff:ff:ff:ff. `add_iface` succeeds, every frame goes out with a broadcast source, and nothing on the LAN can resolve the host.

## RFC reference
RFC 4944 §6: "For either address format, all zero addresses MUST NOT be used."

## Suggested fix
Reject group-bit and all-zero addresses in `add_iface` (`HardwareAddrMismatch`) and `set_hardware_addr`.
