//! Join an IPv4 multicast group and print the mDNS traffic received on it.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example multicast -- tap0        # TAP (Ethernet medium)
//! cargo run --example multicast -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! # e.g. avahi-browse -a, or:
//! echo hi | socat - UDP4-DATAGRAM:224.0.0.251:5353,bind=:5353
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddr, IpCidr, Ipv4Addr, Ipv6Addr, ListenSocketAddr};
use xarxa::{Stack, StaticPool};

const MDNS_PORT: u16 = 5353;
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let hardware_addr = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    };
    let name = args.first().map(String::as_str).unwrap_or("tap0");

    let driver = TunTapDriver::new(name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    // Create interface
    static POOL: StaticPool = StaticPool::new();
    let mut stack = Stack::new(&POOL, random_seed());
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    stack
        .iface(iface)
        .set_ip_addrs([
            IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24),
            IpCidr::new(IpAddr::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddr::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
        ])
        .unwrap();
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(192, 168, 69, 100), iface)
        .unwrap();
    stack
        .routes_mut()
        .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100), iface)
        .unwrap();

    // Create sockets
    let udp_handle = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(udp_handle)
        .bind(MDNS_PORT, ListenSocketAddr::UNSPECIFIED)
        .unwrap();

    // Join a multicast group to receive mDNS traffic
    stack.iface(iface).join_multicast_group(MDNS_GROUP).unwrap();

    loop {
        let deadline = stack.poll(Instant::now());

        let mut socket = stack.udp_socket(udp_handle);
        while let Ok(packet) = socket.recv() {
            println!("mDNS traffic: {} UDP bytes from {}", packet.len(), packet.meta());
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
