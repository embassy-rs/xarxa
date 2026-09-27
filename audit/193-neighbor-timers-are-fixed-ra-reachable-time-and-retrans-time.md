# 193. Neighbor timers are fixed: RA Reachable Time and Retrans Timer are ignored, and the ARP timeout cannot be configured

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/neighbor.rs:160](../src/neighbor.rs#L160), [src/neighbor.rs:30](../src/neighbor.rs#L30) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`ENTRY_LIFETIME` (60 s) and `RETRANS_TIMER` (1 s) are hard-coded constants. The Reachable Time and Retrans Timer fields of router advertisements are never read, ReachableTime is not randomized, and the ARP timeout is not configurable. All are SHOULD-level.

## Details
src/neighbor.rs:160
```rust
pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);
```
src/neighbor.rs:30
```rust
pub(crate) const RETRANS_TIMER: Duration = Duration::from_millis(1_000);
```
Outside `src/wire`, the only uses of `set_reachable_time`/`set_retrans_time` are in test code (src/stack.rs:3218-3219). Learned entries always get 60 s. `NeighborCache::insert` lets a user pick the expiry only for manual entries.

## Failure scenario
A slow 6LoWPAN mesh router advertises a Retrans Timer of 3 s. xarxa still sends NS every 1 s and gives up after 3 s, so resolution of multi-hop-latency neighbors fails. A battery device that wants to re-ARP less often cannot change the 60 s lifetime.

## RFC reference
RFC 4861 §6.3.4: "If the received Reachable Time value is non-zero, the host SHOULD set its BaseReachableTime variable to the received value. If the new value differs from the previous value, the host SHOULD re-compute a new random ReachableTime value. ReachableTime is computed as a uniformly distributed random value between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times the BaseReachableTime." and "The RetransTimer variable SHOULD be copied from the Retrans Timer field, if the received value is non-zero."

RFC 1122 §2.3.2.1: "If this mechanism involves a timeout, it SHOULD be possible to configure the timeout value."

## Suggested fix
Keep per-interface BaseReachableTime/RetransTimer, update them from RAs, apply jitter, and expose them as interface settings.
