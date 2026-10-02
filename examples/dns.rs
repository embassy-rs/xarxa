//! Resolve a host name with the DNS client over a TUN/TAP interface.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example dns -- tap0 rust-lang.org            # TAP (Ethernet medium)
//! cargo run --example dns -- --tun tun0 rust-lang.org      # TUN (IP medium)
//! cargo run --example dns -- tap0 rust-lang.org 8.8.8.8    # custom DNS server
//! ```
//!
//! Then, on the host, bring the interface up and NAT it so the DNS server is
//! reachable:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo sysctl net.ipv4.ip_forward=1
//! sudo iptables -t nat -A POSTROUTING -s 192.168.69.0/24 -j MASQUERADE
//! sudo iptables -I FORWARD -i tap0 -j ACCEPT
//! sudo iptables -I FORWARD -o tap0 -j ACCEPT
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::dns::{DnsClient, GetQueryResultError};
use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::DnsType as Type;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddr, IpCidr, Ipv4Addr};
use xarxa::{Stack, StaticPool};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let hardware_addr = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    };
    let name = args.first().map(String::as_str).unwrap_or("tap0");
    let host = args.get(1).map(String::as_str).unwrap_or("rust-lang.org");
    let server: IpAddr = args
        .get(2)
        .map(|s| {
            s.parse::<std::net::IpAddr>()
                .expect("invalid DNS server address")
                .into()
        })
        .unwrap_or(IpAddr::v4(8, 8, 8, 8));

    let driver = TunTapDriver::new(name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

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

    // Off-link traffic routes to the host's address on this interface.
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(192, 168, 69, 100), iface)
        .unwrap();

    let mut dns = DnsClient::new(&mut stack, &[server]).unwrap();
    let query = dns.start_query(&mut stack, host, Type::A).unwrap();
    log::info!("resolving {host} via {server}");

    loop {
        let stack_deadline = stack.poll(Instant::now());
        let dns_deadline = dns.poll(&mut stack, Instant::now());

        match dns.get_query_result(query) {
            Ok(addrs) => {
                log::info!("{host} resolved to {:?}", addrs.as_slice());
                break;
            }
            Err(GetQueryResultError::Failed) => {
                log::error!("query for {host} failed");
                break;
            }
            Err(GetQueryResultError::Pending) => {}
        }

        let deadline = stack_deadline.min(dns_deadline);
        // Zero if the deadline has already passed.
        let timeout = deadline - Instant::now();
        wait(fd, Some(timeout.into())).unwrap();
    }

    dns.remove(&mut stack);
}

/// Quick-and-dirty entropy for the example's PRNG seed. Real firmware should
/// use a hardware RNG or another unpredictable source.
fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
