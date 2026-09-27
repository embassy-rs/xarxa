# 255. Test suite fails to compile or pass in feature sets CI never tests

| | |
|---|---|
| Severity | low |
| Category | feature-gating |
| Location | [src/tcp/mod.rs:11](../src/tcp/mod.rs#L11), [src/tcp/mod.rs:10938](../src/tcp/mod.rs#L10938), [src/stack.rs:4694](../src/stack.rs#L4694) |
| Features | default minus `icmp-errors`, default minus `icmp-ping-reply`, `tcp-timestamps` without `tcp-listener` |
| Verification | reproduced with a test |

## Summary
Several user-selectable feature sets make `cargo test --lib` fail to compile or fail tests. The CI matrix always adds `icmp-errors` and `icmp-ping-reply` and never `tcp-listener`, so it misses them. Most stack-level tests need the full media, protocol and socket set, so reduced builds get almost no stack-level testing. Test-only, no effect on shipped code.

## Details
Reproduced:
- Default minus `icmp-errors`: 17 compile errors in the lib tests. Tests in `stack::test` (from src/stack.rs:4694) use `IcmpError`, `take_icmp_error` and `udp::RecvError::IcmpError` without a cfg.
- Default minus `icmp-ping-reply`: 18 test failures. They include the echo tests themselves and tests that use echo replies as a probe: `sixlowpan::test::{icmp_echo_request, ieee802154_wrong_pan_id, test_address_context_on_iface, test_echo_request_sixlowpan_128_bytes, test_neighbor_solicit, test_ndisc_solicit_answered}`, `stack::test::{test_checksum_offload_rx_*, test_checksum_offload_tx_*, test_icmpv4_echo_reply*, test_icmpv6_echo_reply, test_iface_ip_addrs, test_ipv4/ipv6_bad_version_dropped, test_reply_to_link_local_stays_on_arrival_iface}`.
- `tcp-timestamps` without `tcp-listener`: `test_tsval_in_accepted_socket` (src/tcp/mod.rs:10938) is gated only on `tcp-timestamps` but uses `accepted_socket` and `syn_repr`, which need `tcp-listener`.

Reported, not re-checked by the verifier:
- src/tcp/mod.rs:11 imports `TCP_LISTENER_BACKLOG` under `all(test, feature = "tcp-listener")`, but it is only used in the test module gated on `medium-ip`, `ipv4`, `ipv6`. That gives an unused-import warning, fatal under ci.py's `-D warnings`.
- Non-default knobs (`iface-count-1`, `neighbor-cache-count-1`) and small buffers (`packet-buf-size-590`) break test compilation or fail tests with 1514-byte fixtures.

## Reproduction
Scratch copy, D = the default feature list:
```
cargo test --lib --no-default-features --features "<D minus icmp-errors>" --no-run
  error: could not compile `xarxa` (lib test) due to 17 previous errors
cargo test --lib --no-default-features --features "<D minus icmp-ping-reply>"
  18 failed
cargo test --lib --no-default-features --features std,log,alloc,medium-ethernet,medium-ip,ipv4,ipv6,tcp,tcp-timestamps --no-run
  error[E0425]: cannot find function `syn_repr` / `accepted_socket`
```

## Suggested fix
cfg-gate the affected tests on `icmp-errors`, `icmp-ping-reply` and `tcp-listener`. Move the `TCP_LISTENER_BACKLOG` import into the test module that uses it. Add these combos, and `tcp-listener`, to the ci.py matrix.
