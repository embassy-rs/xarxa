# 179. No random initial delay before the first router solicitation

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:183](../src/iface/slaac.rs#L183), [src/iface/slaac.rs:353](../src/iface/slaac.rs#L353) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`Slaac::new` sets `retry_rs_at: now` (line 183) and `restart` sets `self.retry_rs_at = now` (line 353). The first RS goes out at the next poll. That covers boot, `set_slaac`, `restart_slaac` and every link-up edge. RFC 4861 says the first RS SHOULD be delayed by a random 0..1 s. The stack has a PRNG it could use.

## Failure scenario
After a power failure, hundreds of devices on one segment all send an RS in the same millisecond. A flapping link makes a device send an RS on every up edge with no randomization.

## RFC reference
RFC 4861 §6.3.7: "Before a host sends an initial solicitation, it SHOULD delay the transmission for a random amount of time between 0 and MAX_RTR_SOLICITATION_DELAY. This serves to alleviate congestion when many hosts start up on a link at the same time". MAX_RTR_SOLICITATION_DELAY is 1 second (§10).

## Suggested fix
Set `retry_rs_at = now + rand(0..1000 ms)` from the stack PRNG in `new` and `restart`. The deadline is already counted by `rs_required`.
