# 198. Raw send docs: panic conditions are wrong or incomplete

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/raw.rs:502](../src/raw.rs#L502), [src/raw.rs:568](../src/raw.rs#L568), [src/raw.rs:298](../src/raw.rs#L298), [src/udp.rs:820](../src/udp.rs#L820) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`RawSocket::send_with` says it panics if the bound interface was removed. That only happens in Ethernet mode. IP mode returns `Unaddressable`. The real panic when the closure returns more than `max_size` is not documented. `bind` and UDP `send_with` have the same kind of gap.

## Details
- src/raw.rs:568 `assert!(size <= max_size);` is not in `# Panics`. UDP has the same assert at src/udp.rs:820.
- IP mode: `route()` filters interfaces with `binding.matches` (src/stack.rs:349), so a removed interface gives `None` and the send returns `Unaddressable`.
- Ethernet mode: `self.tx.can_transmit(iface)` (src/raw.rs:544) looks up the stale handle and panics.
- If a new interface reuses the index, neither mode panics and the socket uses the new interface.
- `bind` (src/raw.rs:298) says it panics on a stale handle, but the lookup only runs for `RawMode::Ethernet`.

## Failure scenario
A `send_with` closure returns `data.len()` for a slice larger than `max_size` and panics in production. Or an IP-mode user expects a panic on a removed interface and gets `Unaddressable`, which reads as "no route".

## Suggested fix
Document the `max_size` panic (raw and UDP), and that the stale-interface panic is Ethernet mode only while IP mode returns `Unaddressable`. Same for `bind`.
