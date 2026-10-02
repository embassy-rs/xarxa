//! Get an IPv4 address with DHCP on a TAP interface, then reply to pings on it.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example dhcp -- tap0
//! ```
//!
//! Then, on the host, bridge `tap0` into a network with a DHCP server, or run one
//! on it:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo dnsmasq --no-daemon --interface=tap0 --bind-interfaces \
//!     --dhcp-range=192.168.69.50,192.168.69.90,12h
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::iface::dhcpv4::DhcpConfig;
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress};
use xarxa::{Stack, StaticPool};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let name = std::env::args().nth(1).unwrap_or_else(|| "tap0".to_string());

    let hardware_addr = HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
    let driver = TunTapDriver::new(&name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    static POOL: StaticPool = StaticPool::new();
    let mut stack = Stack::new(&POOL, random_seed());
    let iface = stack.add_iface(Box::new(driver)).unwrap();

    // That's all it takes: the stack installs the address and default route
    // itself once a lease comes in, and keeps it renewed. The parameter request
    // list additionally asks the server for NTP servers (option 42), read raw
    // from the lease below.
    let mut config = DhcpConfig::default();
    config.parameter_request_list = Some(&[1, 3, 6, 42]);
    stack.iface(iface).set_dhcpv4(Some(config)).unwrap();

    let mut generation = stack.iface(iface).config_generation();
    loop {
        let deadline = stack.poll(Instant::now());

        // Report configuration changes.
        let iface_view = stack.iface(iface);
        if iface_view.config_generation() != generation {
            generation = iface_view.config_generation();
            match iface_view.dhcpv4_lease() {
                Some(lease) => {
                    log::info!("DHCP lease: {}", lease.address);
                    log::info!("  router: {:?}", lease.router);
                    log::info!("  DNS servers: {:?}", lease.dns_servers);
                    // Any option can be read raw from the lease, by number.
                    log::info!("  NTP servers (raw option 42): {:?}", lease.options.get(42));
                }
                None => log::info!("DHCP: no lease"),
            }
        }

        // Zero if the deadline has already passed.
        let timeout = deadline - Instant::now();
        wait(fd, Some(timeout.into())).unwrap();
    }
}

/// Quick-and-dirty entropy for the example's PRNG seed. Real firmware should
/// use a hardware RNG or another unpredictable source.
fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
