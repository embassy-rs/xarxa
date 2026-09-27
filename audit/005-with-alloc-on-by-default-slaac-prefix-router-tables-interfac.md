# 005. With `alloc` (default), SLAAC prefix and router tables, interface addresses and routes grow without limit from Router Advertisements

| | |
|---|---|
| Severity | high |
| Category | security |
| Location | [src/iface/slaac.rs:157](../src/iface/slaac.rs#L157), [src/iface/slaac.rs:159](../src/iface/slaac.rs#L159), [src/iface/slaac.rs:209](../src/iface/slaac.rs#L209), [src/iface/slaac.rs:231](../src/iface/slaac.rs#L231), [src/iface/slaac.rs:488](../src/iface/slaac.rs#L488), [src/iface/slaac.rs:524](../src/iface/slaac.rs#L524), [src/iface/mod.rs:258](../src/iface/mod.rs#L258), [src/route.rs:139](../src/route.rs#L139), [src/storage/vec.rs:26](../src/storage/vec.rs#L26), [src/config.rs:59](../src/config.rs#L59) |
| Features | default (`alloc`, `ipv6`, SLAAC) |
| Verification | reproduced with a test |

## Summary

Several tables fed from the network use `storage::Vec`, which ignores its bound with `alloc` and accepts every push. These are the SLAAC prefix and router tables, `IfaceState::ip_addrs` and `Routes::storage`. An on-link attacker who floods Router Advertisements with distinct prefixes or source addresses grows all of them without limit. The heap runs out, which aborts on an embedded static heap, and per-packet and per-sync work grows with the table sizes.

## Details

src/storage/vec.rs:26-31
```rust
pub fn push(&mut self, item: T) -> Result<(), T> {
    #[cfg(feature = "alloc")]
    {
        self.inner.push(item);
        Ok(())
    }
```

src/storage/mod.rs says tables whose bound is a policy use `BoundedVec`, bounded in both modes. The neighbor cache and the pending queue do. These do not:

- src/iface/slaac.rs:157 `prefix: Vec<(Ipv6Cidr, PrefixInfo), SLAAC_PREFIX_COUNT>`
- src/iface/slaac.rs:159 `routes: Vec<Route, SLAAC_ROUTER_COUNT>`
- src/iface/mod.rs:258 `ip_addrs: Vec<IfaceAddr, IFACE_ADDR_COUNT>`. `sync_slaac_state` pushes one address per valid prefix (src/iface/slaac.rs:488).
- src/route.rs:139 `storage: Vec<Route, ROUTE_COUNT>`. `sync_slaac_state` installs one route per SLAAC router (src/iface/slaac.rs:524).

The "table full" branches (src/iface/slaac.rs:209-210 and 231-238) never run with `alloc`. The config docs (src/config.rs:43, 51, 61, 66) say these knobs are "Ignored with `alloc`", so the growth is a documented storage choice. What is not acknowledged is that on-link RA spoofing drives it.

Each Prefix Information option with the A flag forms one address. Each distinct RA source adds one default route. Lifetimes are the attacker's choice, capped at `Duration::MAX` (about 12.4 days). Each new address also adds a solicited-node group and rebuilds the driver's multicast filter list (src/iface/mod.rs:955, also `storage::Vec`). `has_ip_addr` and `in_same_network` scan `ip_addrs` on every packet, and `sync_slaac_state` does a linear search per prefix and per route.

## Failure scenario

A default build runs SLAAC on an Ethernet link. An on-link attacker sends RAs, each with many Prefix Information options (A flag, distinct /64s, valid lifetime 0xffffffff) and a new link-local source. Every RA adds addresses, prefix entries and a route. On an embedded target with a static heap (for example the stm32 example) the heap is exhausted quickly and allocation failure aborts. On a hosted build, memory and per-packet cost grow until the lifetimes run out.

## Reproduction

Test in `mod test` of src/iface/slaac.rs, default features:

```rust
#[test]
fn vfy_ra_flood_unbounded() {
    let mut slaac = Slaac::new(SlaacConfig::default(), Instant::ZERO);
    let now = Instant::from_millis(1);
    for i in 0..1000u16 {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 1, i);
        let mut p = PREFIX;
        p.prefix = Ipv6Addr::new(0x2001, 0xdb8, i, 0, 0, 0, 0, 0);
        slaac.process_advertisement(&src, NdiscRouterFlags::empty(), VALID, Some(p).into_iter(), now);
    }
    std::println!("prefixes={} routes={} cap={}/{}", slaac.prefix.len(), slaac.routes.len(), SLAAC_PREFIX_COUNT, SLAAC_ROUTER_COUNT);
    assert!(slaac.prefix.len() <= SLAAC_PREFIX_COUNT);
}
```

`cargo test --lib vfy_ -- --nocapture`:
```
prefixes=1000 routes=1000 cap=2/2
panicked: assertion failed: slaac.prefix.len() <= SLAAC_PREFIX_COUNT
```

The test covers only the SLAAC tables. The growth of `ip_addrs` and `Routes` follows from `sync_slaac_state` pushing into `storage::Vec` too. That part was confirmed by reading the code, not by a test. The number of prefix options that fit in one RA was not checked.

## Suggested fix

Use `BoundedVec` for the SLAAC prefix and router tables, as the storage/mod.rs guidance says for policy-bound tables. Also cap network-learned entries in `ip_addrs` and `Routes` with `alloc`, for example by counting SLAAC-origin entries against `SLAAC_PREFIX_COUNT` and `SLAAC_ROUTER_COUNT`. Then update the config docs for these knobs.
