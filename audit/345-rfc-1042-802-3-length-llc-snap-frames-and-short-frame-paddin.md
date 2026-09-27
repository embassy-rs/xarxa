# 345. RFC 1042 LLC/SNAP frames are dropped, and the driver contract does not say who pads short frames

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/stack.rs:1274](../src/stack.rs#L1274), [src/stack.rs:2739](../src/stack.rs#L2739), [xarxa-driver/src/lib.rs:279](../xarxa-driver/src/lib.rs#L279) |
| Features | `medium-ethernet` |
| Verification | confirmed against the code |

## Summary
`process_ethernet` only accepts the ARP, IPv4 and IPv6 EtherTypes. Frames with an 802.3 length field and LLC/SNAP encapsulation are dropped. RFC 1122 says a host SHOULD receive them, but only legacy equipment sends them. Separately, egress never pads to the 60-byte minimum (ARP frames are 42 bytes), and `Driver::transmit` does not say the driver or hardware must pad. Also reported as rfc1122-checklist-21.

## Details
src/stack.rs:1274:
```rust
match ethertype {
    EthernetProtocol::Arp => ...,
    EthernetProtocol::Ipv4 => ...,
    EthernetProtocol::Ipv6 => ...,
    // Drop all other traffic.
    _ => {}
}
```
`transmit_ethernet` (src/stack.rs:2739) pushes 14 bytes and hands the frame over at its natural length. The `Driver::transmit` doc (xarxa-driver/src/lib.rs:265-279) says nothing about minimum length. Most MACs pad automatically.

## Failure scenario
- A driver for a MAC with auto-pad disabled sends 42-byte ARP replies as runts. Switches drop them and ARP never completes.
- A legacy station sending IP over SNAP is not heard.

## RFC reference
RFC 1122 §2.3.3: "SHOULD be able to receive RFC-1042 packets, intermixed with RFC-894 packets".
RFC 894: "If necessary, the data field should be padded (with octets of zero) to meet the Ethernet minimum frame size."

## Suggested fix
Document on `Driver::transmit` that frames may be shorter than the Ethernet minimum and the driver or hardware must pad. Optionally accept `AA-AA-03-00-00-00` + EtherType on receive.
