# 283. set_keep_alive changes don't take effect on an idle connection

| | |
|---|---|
| Severity | low |
| Category | timer |
| Location | [src/tcp/mod.rs:2420](../src/tcp/mod.rs#L2420), [src/tcp/mod.rs:407](../src/tcp/mod.rs#L407), [src/tcp/mod.rs:2080](../src/tcp/mod.rs#L2080) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`Timer::set_keep_alive` only acts when the timer is Idle with no keep-alive armed. On an idle connection:
- Disabling keep-alive leaves the armed deadline, so one more probe goes out.
- Shortening the interval keeps the old, longer deadline.
- Enabling it sends a probe at the next poll, not after the interval.

The last one is deliberate (internal comment, inherited from smoltcp) but contradicts the public doc. The first two are unintended.

## Details
src/tcp/mod.rs:407-413:
```rust
fn set_keep_alive(&mut self, now: Instant) {
    if let Timer::Idle { keep_alive_at } = self
        && keep_alive_at.is_none()
    {
        *keep_alive_at = Some(now)
    }
}
```
`TcpSocket::set_keep_alive` (mod.rs:2420-2433) only calls it when the new interval is `Some`. With `None` the timer is untouched.

src/tcp/mod.rs:2080-2092 fires on the stored deadline whatever `self.keep_alive` is, and only then reschedules from it:
```rust
Timer::Idle {
    keep_alive_at: Some(keep_alive_at),
} if clock.expired(keep_alive_at) => {
    ...
    self.timer = Timer::Idle {
        keep_alive_at: self.keep_alive.map(|interval| clock.after(interval)),
    };
}
```
Only a received segment (`rewind_keep_alive`) or `set_for_idle` applies a new interval. An idle connection receives nothing.

The public doc (mod.rs:2408-2410) says a probe is sent "every time it receives no communication during that interval".

After disabling, `timeout_armed` (which reads `self.keep_alive`) is false while the timer can still send a probe. Nothing worse than the stray probe follows.

## Failure scenario
- Keep-alive at 2 h, then shortened to 10 s to detect a dead peer fast. No probe for up to 2 h.
- Keep-alive disabled on an idle cellular link to save power. One more probe still goes out up to an interval later and wakes the radio.
- Keep-alive set to 2 h right after receiving data at t=1000 (set at t=1001). A probe goes out at t=1002.

## Suggested fix
In `set_keep_alive`, when the timer is Idle, set `keep_alive_at` to `interval.map(|i| now + i)` unconditionally. Update the doc if the immediate probe on enable is kept.
