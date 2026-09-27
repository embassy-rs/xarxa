# 297. Unaddressable docs omit "no route", and bind docs omit that a connected bind pins the local address

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/udp.rs:804](../src/udp.rs#L804), [src/udp.rs:876](../src/udp.rs#L876), [src/udp.rs:86](../src/udp.rs#L86), [src/udp.rs:474](../src/udp.rs#L474) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Three gaps in UDP public docs:
- `send_with`'s `Unaddressable` list omits "no route to the destination" and "destination IP version excluded by the bind".
- `BindError::Unaddressable`'s variant doc omits "local address is not bindable". `bind()`'s own Errors section does list it.
- `bind()` says a `None` local address receives unicast, multicast and broadcast. It does not say a fully specified remote replaces the wildcard with one unicast source, after which broadcast and multicast are no longer received.

## Details
src/udp.rs:873-876 returns `Unaddressable` when `self.tx.route(...)` is `None`. src/udp.rs:863-868 returns it on a bind version mismatch. The doc at src/udp.rs:804-807 lists only unspecified destination, family mismatch, no source, and source not assigned.

src/udp.rs:86-88, the variant doc: "The local and remote addresses belong to different address families, or no local address is available for the given remote." src/udp.rs:542-545 also returns it for a non-bindable local address.

src/udp.rs:474: "`None`: ... It receives packets destined to unicast, multicast and broadcast addresses." src/udp.rs:551-560 replaces `None` with a concrete source when the remote has address and port. The local filter is exact, so broadcast and multicast stop matching. Only DESIGN.md says this.

## Failure scenario
A user binds with a fully specified remote and expects broadcast replies, as the doc suggests. They are silently not delivered. A user seeing `Unaddressable` from send has no hint that the route table is the cause.

## Suggested fix
Add the two missing cases to the send `Unaddressable` list, add "local address is not ours, a broadcast address, or a multicast group" to `BindError::Unaddressable`, and document the local address pinning in `bind()`.
