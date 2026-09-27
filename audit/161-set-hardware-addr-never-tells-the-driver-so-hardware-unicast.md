# 161. set_hardware_addr never tells the driver, and the doc does not say so

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:331](../src/iface/mod.rs#L331), [src/iface/mod.rs:345](../src/iface/mod.rs#L345), [xarxa-driver/src/lib.rs:198](../xarxa-driver/src/lib.rs#L198) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`Iface::set_hardware_addr` only updates the stack's copy of the address. The `Driver` trait has no unicast address setter, so the device keeps its own address and filter. The doc does not warn about this. On a device with a hardware destination-address filter, unicast reception stops while ARP/NDISC advertise the new MAC.

## Details
src/iface/mod.rs:345:
```rust
pub fn set_hardware_addr(&mut self, addr: HardwareAddress) -> Result<(), MediumMismatch> {
    if addr.medium() != self.state().medium() {
        return Err(MediumMismatch);
    }
    self.state_mut().hardware_addr = addr;
```
No driver call follows. The doc ("The stack starts using it for the frames it sends and for ingress filtering immediately") is literally true of the stack's software filter, so it is incomplete rather than false. DESIGN.md §4 presents this method as the override for "an address stored outside the driver (app flash, EEPROM)", which is exactly when the NIC is still programmed with another MAC.

Whether it breaks depends on the driver: MACs with a DA filter (stm32 eth MACA0, enc28j60 MAADR) and 802.15.4 radios with address filtering and auto-ack are affected.

## Failure scenario
A board reads its MAC from EEPROM and calls `set_hardware_addr` after `add_iface`, without reprogramming the stm32 MAC. Peers send ARP replies and unicast to the new MAC, and the hardware drops them. Only broadcast and multicast get through.

## Suggested fix
Document that the device must be set to the same address through the driver's API, or run promiscuous. Or add an optional `Driver::set_hardware_address` hook called from `set_hardware_addr`.
