//! TCP client: bring up a TUN/TAP interface, connect to a remote peer, send
//! a greeting, and print everything received until the remote end closes the
//! connection.
//!
//! On the host, set up the interface and listen for the connection:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! nc -l 1234
//! ```
//!
//! Then run (the remote peer defaults to 192.168.69.100:1234):
//!
//! ```sh
//! cargo run --example tcp_client -- tap0        # TAP (Ethernet medium)
//! cargo run --example tcp_client -- --tun tun0  # TUN (IP medium)
//! cargo run --example tcp_client -- tap0 '[fdaa::100]:1234'
//! ```
//!
//! Anything typed into `nc` is printed by the client. Closing `nc` (ctrl-C) closes
//! the connection and exits the client.

use std::io::Write as _;
use std::os::unix::io::AsRawFd;

use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddr, IpCidr, Ipv4Addr, SocketAddr};
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
    let remote: SocketAddr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("192.168.69.100:1234")
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();

    // The driver and the socket buffers are lent to the stack by reference
    // rather than boxed, as a no-alloc program would. They must be declared
    // before the stack, which holds them until it is dropped.
    let mut driver = TunTapDriver::new(name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();
    let mut rx_buffer = [0u8; 4096];
    let mut tx_buffer = [0u8; 4096];

    static POOL: StaticPool = StaticPool::new();
    let mut stack = Stack::new(&POOL, random_seed());
    let iface = stack.add_iface_borrowed(&mut driver).unwrap();
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

    let tcp_handle = stack.add_tcp_socket_with_bufs(&mut rx_buffer, &mut tx_buffer).unwrap();

    // Local port 0: the stack allocates an ephemeral port.
    let mut socket = stack.tcp_socket(tcp_handle);
    socket.connect(remote, 0).unwrap();
    log::info!("tcp: connecting to {remote} from {}", socket.local_addr().unwrap());

    let mut greeting_sent = false;
    loop {
        let deadline = stack.poll(Instant::now());

        let mut socket = stack.tcp_socket(tcp_handle);

        if !socket.is_active() {
            log::info!("tcp: connection closed");
            break;
        }

        if !greeting_sent && socket.can_send() {
            socket.send_slice(b"Hello over TCP from xarxa!\n").unwrap();
            greeting_sent = true;
        }

        while socket.can_recv() {
            socket
                .recv(|data| {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    stdout.write_all(data).unwrap();
                    stdout.flush().unwrap();
                    (data.len(), ())
                })
                .unwrap();
        }

        // The remote peer closed its transmit half: close ours too.
        if !socket.may_recv() && socket.may_send() {
            socket.close();
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
