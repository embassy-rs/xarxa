#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]
//!
//! ## Feature flags
#![doc = document_features::document_features!(feature_label = r#"<span class="stab portability"><code>{feature}</code></span>"#)]
#![deny(unsafe_code)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

// So that `src/test_device.rs` can name this crate as `xarxa` both here and in the
// integration tests that `#[path]`-include it.
#[cfg(test)]
extern crate self as xarxa;

#[cfg(not(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-ieee802154")))]
compile_error!("You must enable at least one of the following features: medium-ethernet, medium-ip, medium-ieee802154");

#[cfg(all(
    feature = "slaac",
    not(any(feature = "medium-ethernet", feature = "medium-ieee802154"))
))]
compile_error!("The slaac feature needs medium-ethernet or medium-ieee802154.");

#[cfg(not(any(feature = "ipv4", feature = "ipv6")))]
compile_error!("You must enable at least one of the following features: ipv4, ipv6");

#[cfg(all(feature = "tcp-reno", feature = "tcp-cubic"))]
compile_error!("The features tcp-reno and tcp-cubic are mutually exclusive.");

// Must go first so other modules see its macros.
#[macro_use]
mod fmt;

#[macro_use]
mod macros;

pub mod config;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "std")]
pub mod driver_impls;
pub mod error;
#[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
mod fragmentation;
#[cfg(feature = "icmp-errors")]
mod icmp_error;
pub mod iface;
#[cfg(feature = "multicast")]
mod multicast;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
#[cfg(feature = "packet-log")]
mod packet_log;
mod pool;
mod rand;
#[cfg(feature = "_raw")]
pub mod raw;
#[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
mod reassembly;
pub mod route;
#[cfg(feature = "medium-ieee802154")]
mod sixlowpan;
mod stack;
mod storage;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(test)]
mod test_device;
pub mod time;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "async")]
mod waker;
pub mod wire;

/// The driver interface, re-exported for driver crates and code that names their types.
pub use xarxa_driver as driver;

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub use neighbor::{Neighbor, NeighborCache, NeighborState};
#[cfg(feature = "alloc")]
pub use pool::AllocPool;
pub use pool::{Align, Pool, StaticPool, ValidAlign};
pub use stack::Stack;
