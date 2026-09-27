# 331. Capabilities::max_transmission_unit doesn't say it includes the Ethernet header, and values below 14 underflow

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [xarxa-driver/src/lib.rs:170](../xarxa-driver/src/lib.rs#L170), [src/iface/mod.rs:731](../src/iface/mod.rs#L731), [xarxa-driver/src/lib.rs:196](../xarxa-driver/src/lib.rs#L196), [src/iface/mod.rs:317](../src/iface/mod.rs#L317) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The field doc talks about "the value returned by this function" and doesn't say what it counts for Ethernet or IP. The stack treats the Ethernet value as the whole frame with the 14-byte header, and subtracts without a check. A driver reporting the Linux-style 1500 gets IP MTU 1486. A value below 14 panics in debug builds.

## Details
xarxa-driver/src/lib.rs:170:
```rust
/// Maximum transmission unit.
///
/// The network device is unable to send or receive frames larger than the value returned
/// by this function.
pub max_transmission_unit: usize,
```
Only `Medium::Ieee802154` (lib.rs:54) spells out its convention. src/iface/mod.rs:731:
```rust
Medium::Ethernet => caps.max_transmission_unit - ETHERNET_HEADER_LEN,
```
`add_iface` does not validate the value. In release a value below 14 wraps, then `.min(PACKET_BUF_SIZE - LINK_HEADER_LEN)` silently gives the full buffer size. TunTapDriver and RawSocketDriver add 14 by hand, which shows the convention is non-obvious.

Also:
- `Driver::capabilities` (lib.rs:196) doesn't say it is read once at `add_iface`, unlike `hardware_address`.
- The public `Iface::ip_mtu` doc (iface/mod.rs:317) says "device MTU minus the link-layer header". For 802.15.4 with fragmentation it returns 1280.

## Failure scenario
- A driver reports 1500. IP MTU is 1486, TCP MSS 1446, IPv4 datagrams of 1487-1500 bytes are fragmented, and 1472-byte UDP sends are refused.
- A driver built from `Default` with MTU 0 panics in debug on the first `ip_mtu()` call.

## Suggested fix
Document per medium: Ethernet counts the frame without FCS, header included. IP counts the IP packet. Say capabilities are read once. Validate or saturate in `add_iface`. Fix the `Iface::ip_mtu` doc.
