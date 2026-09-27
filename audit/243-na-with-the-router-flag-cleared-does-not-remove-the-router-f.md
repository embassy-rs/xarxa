# 243. NA with the Router flag cleared does not remove the router from the default route list

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2304](../src/stack.rs#L2304) |
| Features | slaac |
| Verification | confirmed against the RFC text |

## Summary
`process_ndisc_advert` never reads `NdiscNeighborFlags::ROUTER` and never touches the routes table. A router that SLAAC installed as default gateway and that starts advertising R=0 stays the gateway until the RA router lifetime runs out (at most 9000 s). RFC 4861 makes removal a MUST. The deviation is noted only in a private doc comment, not in README or DESIGN.md.

## Details
src/stack.rs:2304, private doc of `process_ndisc_advert`:
```rust
/// ... record the new address as reachable (§7.2.5 II), and the IsRouter flag
/// is not tracked.
```
The body only uses `SOLICITED` and `OVERRIDE`.

## Failure scenario
A SLAAC default route via fe80::1 exists. fe80::1 is reconfigured as a host and answers our NS with an NA, R=0. xarxa keeps sending off-link traffic to fe80::1, which drops it, until the route from the last RA expires.

## RFC reference
RFC 4861 §7.2.5: "The IsRouter flag in the cache entry MUST be set based on the Router flag in the received advertisement. In those cases where the IsRouter flag changes from TRUE to FALSE as a result of this update, the node MUST remove that router from the Default Router List and update the Destination Cache entries for all destinations using that neighbor as a router".

## Suggested fix
When an NA with R=0 arrives for a target that is the gateway of a SLAAC-origin default route on that interface, remove that route. No IsRouter bit in the cache is needed. Otherwise list it under "Not yet implemented" in README.
