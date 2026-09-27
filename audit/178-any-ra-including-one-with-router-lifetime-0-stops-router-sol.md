# 178. Any RA, including one with router lifetime 0, stops router solicitation

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:296](../src/iface/slaac.rs#L296) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`process_advertisement` moves `Discovering` to `Maintaining` on every valid RA, whatever its router lifetime. A lifetime-0 RA arriving first (for example from a Thread border router that only advertises prefixes) ends solicitation. If the real router's answer is lost, the host has no default route until the next unsolicited RA.

## Details
src/iface/slaac.rs:295-298:
```rust
// Advertisement might be unsolicited
if self.phase == Phase::Discovering {
    self.phase = Phase::Maintaining;
}
```
There is no `router_lifetime` check. The RFC MUST only requires stopping after a non-zero lifetime RA. It does not forbid stopping earlier, so this is a behavioral deviation, not a MUST violation.

## Failure scenario
A network has a main router and a Thread border router that sends RAs with lifetime 0 and a ULA PIO. The node sends RS #1. The border router's RA arrives first. The main router's reply is lost on Wi-Fi. RS #2 and #3 are never sent, and the node has no default route or GUA until the main router's next periodic RA, typically 200-600 s later.

## RFC reference
RFC 4861 §6.3.7: "Once the host sends a Router Solicitation, and receives a valid Router Advertisement with a non-zero Router Lifetime, the host MUST desist from sending additional solicitations on that interface"

## Reproduction
In the `slaac` module tests of a scratch copy:
```rust
#[test]
fn vfy_f8_zero_lifetime_stops_rs() {
    let mut slaac = Slaac::new(SlaacConfig::default(), Instant::ZERO);
    slaac.rs_sent(Instant::ZERO);
    advertise(&mut slaac, Duration::ZERO, Some(PREFIX), Instant::from_millis(10));
    assert!(slaac.soliciting());
}
```
Output: `soliciting()` is false, test fails.

## Suggested fix
Only move to `Maintaining` when `router_lifetime > 0`.
