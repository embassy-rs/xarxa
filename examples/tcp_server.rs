//! TCP echo server: bring up a TUN/TAP interface and echo back everything
//! received on TCP port 6969.
//!
//! A listener accepts any number of concurrent connections. Each accepted
//! connection gets its own socket (and buffers), removed again when it closes.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example tcp_server -- tap0        # TAP (Ethernet medium)
//! cargo run --example tcp_server -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! nc 192.168.69.1 6969
//! nc fdaa::1 6969
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::Stack;
use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

const PORT: u16 = 6969;

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

    let driver = TunTapDriver::new(name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    let mut stack = Stack::new(random_seed());
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    stack
        .iface(iface)
        .set_ip_addrs([
            IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
            IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
        ])
        .unwrap();

    // Off-link traffic routes to the host's address on this interface.
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 100), iface)
        .unwrap();

    let listener = stack.add_tcp_listener().unwrap();
    stack.tcp_listener(listener).listen(PORT).unwrap();
    log::info!("tcp: listening on port {PORT}");

    let mut connections = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        // Process ingress. The socket operations below (accept, echo, close)
        // make more segments due, which the second poll before sleeping
        // transmits (along with recomputing the wakeup deadline).
        stack.poll(Instant::now());

        // Accept every queued connection attempt into a fresh socket. The
        // socket answers the SYN with a SYN|ACK on the next poll.
        while let Some(token) = stack.tcp_listener(listener).accept() {
            log::info!("tcp: connection from {}", token.remote_endpoint());
            let handle = stack.add_tcp_socket(4096, 4096).unwrap();
            stack.tcp_socket(handle).accept(token).unwrap();
            connections.push(handle);
        }

        connections.retain(|&handle| {
            let mut socket = stack.tcp_socket(handle);

            // Echo: move bytes from the receive buffer to the transmit buffer,
            // dequeueing no more than the transmit buffer has room for.
            while socket.can_recv() && socket.can_send() {
                let free = socket.send_capacity() - socket.send_queue();
                let len = buf.len().min(free);
                let len = socket.recv_slice(&mut buf[..len]).unwrap();
                socket.send_slice(&buf[..len]).unwrap();
            }

            // The remote endpoint closed its transmit half and everything
            // received has been echoed back: close ours too.
            if !socket.may_recv() && socket.may_send() {
                socket.close();
            }

            // A fully closed socket is done: remove it from the stack.
            if !socket.is_open() {
                log::info!("tcp: connection closed");
                drop(socket);
                stack.remove_tcp_socket(handle);
                return false;
            }
            true
        });

        let deadline = stack.poll(Instant::now());

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
