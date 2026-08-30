//! 6LoWPAN example: bring up an IEEE 802.15.4 interface, reply to pings, echo
//! UDP datagrams received on port 6969 and TCP connections on port 50000.
//!
//! This example is designed to run using the Linux ieee802154/6lowpan support,
//! using mac802154_hwsim.
//!
//! mac802154_hwsim allows you to create multiple "virtual" radios and specify
//! which is in range with which. This is very useful for testing without
//! needing real hardware. By default it creates two interfaces `wpan0` and
//! `wpan1` that are in range with each other. You can customize this with
//! the `wpan-hwsim` tool.
//!
//! We'll configure Linux to speak 6lowpan on `wpan0`, and leave `wpan1`
//! unconfigured so xarxa can use it with a raw socket.
//!
//! # Setup
//!
//! ```sh
//! modprobe mac802154_hwsim
//!
//! ip link set wpan0 down
//! ip link set wpan1 down
//! iwpan dev wpan0 set pan_id 0xbeef
//! iwpan dev wpan1 set pan_id 0xbeef
//! ip link add link wpan0 name lowpan0 type lowpan
//! ip link set wpan0 up
//! ip link set wpan1 up
//! ip link set lowpan0 up
//! ```
//!
//! # Running
//!
//! Run it with `sudo ./target/debug/examples/sixlowpan`.
//!
//! You can set wireshark to sniff on interface `wpan0` to see the packets.
//!
//! Ping it with `ping fe80::180b:4242:4242:4242%lowpan0`.
//!
//! Speak UDP with `nc -uv fe80::180b:4242:4242:4242%lowpan0 6969`.
//!
//! Speak TCP with `nc -v fe80::180b:4242:4242:4242%lowpan0 50000`.
//!
//! # Teardown
//!
//! ```sh
//! rmmod mac802154_hwsim
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::Stack;
use xarxa::driver_impls::{RawSocketDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{HardwareAddress, Ieee802154Address, Ieee802154Pan, IpListenEndpoint};

const UDP_PORT: u16 = 6969;
const TCP_PORT: u16 = 50000;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let name = std::env::args().nth(1).unwrap_or_else(|| "wpan1".to_string());

    let hardware_addr = HardwareAddress::Ieee802154(Ieee802154Address::Extended([
        0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ]));
    let driver = RawSocketDriver::new(&name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    let mut stack = Stack::new(random_seed());
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    // The link-local address is derived from the extended address:
    // fe80::180b:4242:4242:4242.
    stack.iface(iface).set_pan_id(Some(Ieee802154Pan(0xbeef)));
    for addr in stack.iface(iface).ip_addrs() {
        log::info!("address {}", addr.cidr);
    }

    let udp_handle = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(udp_handle)
        .bind(UDP_PORT, IpListenEndpoint::UNSPECIFIED)
        .unwrap();

    let listener = stack.add_tcp_listener().unwrap();
    stack.tcp_listener(listener).listen(TCP_PORT).unwrap();
    log::info!("tcp: listening on port {TCP_PORT}");

    let mut connections = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        stack.poll(Instant::now());

        // Echo received datagrams back to their sender.
        let mut socket = stack.udp_socket(udp_handle);
        while let Ok(packet) = socket.recv() {
            let meta = packet.meta();
            log::info!("udp: echoing {} octets to {}", packet.payload().len(), meta);
            let data = packet.payload().to_vec();
            drop(packet); // free the buffer before sending
            socket.send_slice(&data, meta.endpoint).unwrap();
        }

        // Accept every queued connection attempt into a fresh socket.
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
