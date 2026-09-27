# 290. Instant::now() uses the wall clock, so clock steps stall or fire every timer in hosted builds

| | |
|---|---|
| Severity | low |
| Category | timer |
| Location | [src/time.rs:67](../src/time.rs#L67), [src/time.rs:255](../src/time.rs#L255), examples/*.rs |
| Features | `std` (default) |
| Verification | confirmed against the code |

## Summary
`Instant::now()` converts `SystemTime::now()`, which NTP or an admin can step. Every hosted example uses it as the stack clock. A step back delays every pending timer, and a step of more than 2^31 ms breaks the instant comparison invariant. A monotonic `From<std::time::Instant>` already exists next to it.

## Details
src/time.rs:67:
```rust
pub fn now() -> Instant {
    Self::from(::std::time::SystemTime::now())
}
```
src/time.rs:255:
```rust
fn from(other: ::std::time::SystemTime) -> Instant {
    let n = other
        .duration_since(::std::time::UNIX_EPOCH)
        .expect("start time must not be before the unix epoch");
```
The doc of `now()` says it uses `SystemTime`, but not what that implies, and not that it panics before the epoch. Examples such as examples/dhcp.rs and examples/tuntap.rs pass `Instant::now()` to the stack.

## Failure scenario
- NTP steps the clock back 10 minutes. TCP retransmits, DHCP renewals and neighbor probes are all delayed by 10 minutes.
- A Raspberry Pi with no RTC starts at 1970 and NTP steps it forward by decades. The new time mod 2^32 lands at a random offset. About half the time held deadlines compare as up to 24.8 days in the future, and the stack stalls.

## Suggested fix
Implement `Instant::now()` with `std::time::Instant::now()` through the existing `From` impl.
