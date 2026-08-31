//! Run a DHCP server on a TAP interface and print the leases it hands out.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example dhcp_server -- tap0
//! ```
//!
//! Then, on the host, bring the interface up and ask for an address on it:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo busybox udhcpc -i tap0 -f -q
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::Stack;
use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::iface::dhcpv4_server::DhcpServerConfig;
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let name = std::env::args().nth(1).unwrap_or_else(|| "tap0".to_string());

    let hardware_addr = HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
    let driver = TunTapDriver::new(&name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    let server_ip = Ipv4Address::new(192, 168, 69, 1);
    let mut stack = Stack::new(random_seed());
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new(server_ip.into(), 24))
        .unwrap();

    // Lease addresses .50 to .99, naming ourselves as the gateway and DNS server.
    let mut config = DhcpServerConfig::new(Ipv4Address::new(192, 168, 69, 50), Ipv4Address::new(192, 168, 69, 99));
    config.gateway = Some(server_ip);
    config.dns_servers.push(server_ip).unwrap();
    stack.iface(iface).set_dhcpv4_server(Some(config));

    let mut known_leases = Vec::new();
    loop {
        let deadline = stack.poll(Instant::now());

        // Print the lease table whenever it changes.
        let leases: Vec<_> = stack
            .iface(iface)
            .dhcpv4_server_leases()
            .iter()
            .map(|l| (l.address(), l.hardware_addr(), l.state()))
            .collect();
        if leases != known_leases {
            known_leases = leases;
            log::info!("leases:");
            for (address, hardware_addr, state) in &known_leases {
                log::info!("  {} -> {} ({:?})", address, hardware_addr, state);
            }
        }

        let timeout = (deadline != Instant::MAX).then(|| {
            let now = Instant::now();
            if deadline <= now {
                std::time::Duration::ZERO
            } else {
                (deadline - now).into()
            }
        });
        wait(fd, timeout).unwrap();
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
