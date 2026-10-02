//! Send ICMP echo requests ("pings") through a raw socket and receive the
//! replies. Works over IPv4 and IPv6, picked by the target address.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example ping -- tap0                        # TAP, ping the host over IPv4
//! cargo run --example ping -- tap0 fdaa::100              # TAP, ping the host over IPv6
//! cargo run --example ping -- --tun tun0 192.168.69.100   # TUN (IP medium)
//! cargo run --example ping -- tap0 8.8.8.8                # off-link target (needs NAT)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! ```
//!
//! For off-link targets, also NAT the interface:
//!
//! ```sh
//! sudo sysctl net.ipv4.ip_forward=1
//! sudo iptables -t nat -A POSTROUTING -s 192.168.69.0/24 -j MASQUERADE
//! sudo iptables -I FORWARD -i tap0 -j ACCEPT
//! sudo iptables -I FORWARD -o tap0 -j ACCEPT
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::raw::RawMode;
use xarxa::time::{Duration, Instant};
use xarxa::wire::{
    EthernetAddress, HardwareAddress, IPV4_HEADER_LEN, IPV6_HEADER_LEN, Icmpv4Message, Icmpv4Packet, Icmpv6Message,
    Icmpv6Packet, IpAddr, IpCidr, IpProtocol, Ipv4Addr, Ipv4Packet, Ipv6Addr, Ipv6Packet,
};
use xarxa::{Stack, StaticPool};

/// ICMP echo header (type, code, checksum, ident, seq).
const ICMP_HEADER_LEN: usize = 8;
/// Echo data: an 8-byte send timestamp plus padding, 56 bytes like `ping`.
const DATA_LEN: usize = 56;
const INTERVAL: Duration = Duration::from_secs(1);

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let hardware_addr = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    };
    let name = args.first().map(String::as_str).unwrap_or("tap0");
    let target: IpAddr = args
        .get(1)
        .map(|s| s.parse::<std::net::IpAddr>().expect("invalid target address").into())
        .unwrap_or(IpAddr::v4(192, 168, 69, 100));

    let driver = TunTapDriver::new(name, hardware_addr).unwrap();
    let fd = driver.as_raw_fd();

    let seed = random_seed();
    static POOL: StaticPool = StaticPool::new();
    let mut stack = Stack::new(&POOL, seed);
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    stack
        .iface(iface)
        .set_ip_addrs([
            IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24),
            IpCidr::new(IpAddr::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddr::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
        ])
        .unwrap();

    // Off-link traffic routes to the host's addresses on this interface.
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(192, 168, 69, 100), iface)
        .unwrap();
    stack
        .routes_mut()
        .add_default_ipv6_route(Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 0x100), iface)
        .unwrap();

    // A raw socket in IP mode carries whole IP packets, headers included, in
    // both directions: we build the request's IP and ICMP headers ourselves,
    // and replies arrive with theirs still on. The protocol filter selects the
    // ICMP flavor of the target's IP version. The stack processes ICMP itself
    // too, so the socket sees a copy of each matching ingress packet.
    let protocol = match target {
        IpAddr::V4(_) => IpProtocol::Icmp,
        IpAddr::V6(_) => IpProtocol::Icmpv6,
    };
    let handle = stack.add_raw_socket().unwrap();
    stack
        .raw_socket(handle)
        .bind(RawMode::Ip {
            version: Some(target.version()),
            protocol: Some(protocol),
        })
        .unwrap();

    // Tell our replies apart from other ICMP traffic (the host pinging us,
    // NDISC on IPv6) by the echo identifier, like `ping` does with its PID.
    let ident = seed as u16;
    let mut seq: u16 = 0;
    let mut next_send = Instant::now();
    // Echo requests carry their send time as nanoseconds since `start`.
    let start = std::time::Instant::now();
    log::info!("pinging {target} with {DATA_LEN} bytes of data, ident {ident:#06x}");

    loop {
        let stack_deadline = stack.poll(Instant::now());

        let mut socket = stack.raw_socket(handle);

        // Drain received ICMP packets, printing the echo replies to our pings.
        while let Ok(mut packet) = socket.recv() {
            let now = start.elapsed();
            if let Some(reply) = parse_reply(&mut packet, target, ident) {
                let sent = std::time::Duration::from_nanos(u64::from_le_bytes(reply.timestamp));
                let rtt = now.saturating_sub(sent);
                log::info!(
                    "{} bytes from {}: icmp_seq={} time={:.3}ms",
                    reply.data_len,
                    target,
                    reply.seq,
                    rtt.as_secs_f64() * 1000.0,
                );
            }
        }

        // Send the next request when it is due.
        let now = Instant::now();
        if now >= next_send {
            send_request(&mut socket, target, ident, seq, start);
            seq = seq.wrapping_add(1);
            next_send = now + INTERVAL;
        }

        let deadline = stack_deadline.min(next_send);
        // Zero if the deadline has already passed.
        let timeout = deadline - Instant::now();
        wait(fd, Some(timeout.into())).unwrap();
    }
}

/// Build and send one echo request.
fn send_request(
    socket: &mut xarxa::raw::RawSocket<'_, '_>,
    target: IpAddr,
    ident: u16,
    seq: u16,
    start: std::time::Instant,
) {
    let now = start.elapsed().as_nanos() as u64;
    let res = match target {
        IpAddr::V4(dst) => {
            let src = Ipv4Addr::new(192, 168, 69, 1);
            let total = IPV4_HEADER_LEN + ICMP_HEADER_LEN + DATA_LEN;
            socket.send_with(total, |buf| {
                buf.fill(0);
                let mut ip = Ipv4Packet::new_unchecked(buf);
                ip.set_version(4);
                ip.set_header_len(IPV4_HEADER_LEN as u8);
                ip.set_total_len(total as u16);
                ip.set_next_header(IpProtocol::Icmp);
                ip.set_hop_limit(64);
                ip.set_src_addr(src);
                ip.set_dst_addr(dst);
                ip.fill_checksum();
                let mut icmp = Icmpv4Packet::new_unchecked(ip.payload_mut());
                icmp.set_msg_type(Icmpv4Message::EchoRequest);
                icmp.set_msg_code(0);
                icmp.set_echo_ident(ident);
                icmp.set_echo_seq_no(seq);
                icmp.data_mut()[..8].copy_from_slice(&now.to_le_bytes());
                icmp.fill_checksum();
                total
            })
        }
        IpAddr::V6(dst) => {
            // Replies to a link-local target must come from our link-local address.
            let src = if dst.segments()[0] & 0xffc0 == 0xfe80 {
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
            } else {
                Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1)
            };
            let total = IPV6_HEADER_LEN + ICMP_HEADER_LEN + DATA_LEN;
            socket.send_with(total, |buf| {
                buf.fill(0);
                let mut ip = Ipv6Packet::new_unchecked(buf);
                ip.set_version(6);
                ip.set_payload_len((ICMP_HEADER_LEN + DATA_LEN) as u16);
                ip.set_next_header(IpProtocol::Icmpv6);
                ip.set_hop_limit(64);
                ip.set_src_addr(src);
                ip.set_dst_addr(dst);
                let mut icmp = Icmpv6Packet::new_unchecked(ip.payload_mut());
                icmp.set_msg_type(Icmpv6Message::EchoRequest);
                icmp.set_msg_code(0);
                icmp.set_echo_ident(ident);
                icmp.set_echo_seq_no(seq);
                icmp.payload_mut()[..8].copy_from_slice(&now.to_le_bytes());
                icmp.fill_checksum(&src, &dst);
                total
            })
        }
    };
    match res {
        Ok(()) => log::debug!("sent echo request seq={seq}"),
        Err(e) => log::warn!("send failed: {e}"),
    }
}

struct Reply {
    seq: u16,
    data_len: usize,
    timestamp: [u8; 8],
}

/// Parse a received IP packet. If it is an echo reply from the target carrying
/// our identifier, return its sequence number, data length and the timestamp.
fn parse_reply(packet: &mut [u8], target: IpAddr, ident: u16) -> Option<Reply> {
    match target {
        IpAddr::V4(dst) => {
            let mut ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.src_addr() != dst {
                return None;
            }
            let icmp = Icmpv4Packet::new_checked(ip.payload_mut()).ok()?;
            if icmp.msg_type() != Icmpv4Message::EchoReply || icmp.echo_ident() != ident || !icmp.verify_checksum() {
                return None;
            }
            let data = icmp.data();
            Some(Reply {
                seq: icmp.echo_seq_no(),
                data_len: data.len(),
                timestamp: data.get(..8)?.try_into().unwrap(),
            })
        }
        IpAddr::V6(dst) => {
            let mut ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.src_addr() != dst {
                return None;
            }
            let (src_addr, dst_addr) = (ip.src_addr(), ip.dst_addr());
            let icmp = Icmpv6Packet::new_checked(ip.payload_mut()).ok()?;
            if icmp.msg_type() != Icmpv6Message::EchoReply
                || icmp.echo_ident() != ident
                || !icmp.verify_checksum(&src_addr, &dst_addr)
            {
                return None;
            }
            let data = icmp.payload();
            Some(Reply {
                seq: icmp.echo_seq_no(),
                data_len: data.len(),
                timestamp: data.get(..8)?.try_into().unwrap(),
            })
        }
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
