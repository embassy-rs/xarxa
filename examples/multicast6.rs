//! Join an IPv6 multicast group and print the UDP traffic received on it.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example multicast6 -- tap0        # TAP (Ethernet medium)
//! cargo run --example multicast6 -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add fe80::100/64 dev tap0
//! ncat -u ff02::1234%tap0 8123
//! ```
//!
//! Note: If testing with a tap interface in linux, you may need to specify the
//! interface index when addressing, as in the `ncat` line above, which sends
//! packets to the multicast group we join below on tap0.

use std::os::unix::io::AsRawFd;

use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddr, IpCidr, Ipv6Addr, ListenSocketAddr};
use xarxa::{Stack, StaticPool};

const PORT: u16 = 8123;
const GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);
const LOCAL_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x101);
const ROUTER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100);

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let hardware_addr = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
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
        .set_ip_addrs([IpCidr::new(IpAddr::from(LOCAL_ADDR), 64)])
        .unwrap();
    stack.routes_mut().add_default_ipv6_route(ROUTER_ADDR, iface).unwrap();

    // Create sockets
    let udp_handle = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(udp_handle)
        .bind(PORT, ListenSocketAddr::UNSPECIFIED)
        .unwrap();

    // Join a multicast group
    stack.iface(iface).join_multicast_group(GROUP).unwrap();

    loop {
        let deadline = stack.poll(Instant::now());

        let mut socket = stack.udp_socket(udp_handle);
        while let Ok(packet) = socket.recv() {
            println!("traffic: {} UDP bytes from {}", packet.len(), packet.meta());
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
