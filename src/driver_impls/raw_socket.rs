use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::driver::PacketBuf;
use crate::driver::{Capabilities, Driver};
use crate::iface::Medium;
use crate::wire::HardwareAddress;

const SIOCGIFMTU: libc::c_ulong = 0x8921;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;
#[cfg(feature = "medium-ethernet")]
const ETH_P_ALL: libc::c_short = 0x0003;
#[cfg(feature = "medium-ieee802154")]
const ETH_P_IEEE802154: libc::c_short = 0x00F6;

#[repr(C)]
#[derive(Debug)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}

fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(lower: libc::c_int, ifreq: &mut ifreq, cmd: libc::c_ulong) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd as _, ifreq as *mut ifreq);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(ifreq.ifr_data)
}

/// A driver over a packet socket bound to a host interface, sending and receiving
/// whole frames.
///
/// Ethernet interfaces carry Ethernet frames ([`Medium::Ethernet`]), `wpan`
/// interfaces carry IEEE 802.15.4 frames ([`Medium::Ieee802154`]). Linux and
/// Android only.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct RawSocketDriver {
    lower: libc::c_int,
    mtu: usize,
    hardware_addr: HardwareAddress,
    /// The buffer the next frame is received into, given by the stack.
    rx_buf: Option<PacketBuf>,
}

impl AsRawFd for RawSocketDriver {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl RawSocketDriver {
    /// Open a packet socket bound to the interface called `name`.
    ///
    /// `hardware_addr` is the address the interface reports to the stack, and picks the
    /// medium: an Ethernet address for an Ethernet interface, an IEEE 802.15.4 one for a
    /// `wpan` interface. It must match the address the host interface is configured with.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    ///
    /// # Errors
    /// - `Unsupported`: for [`HardwareAddress::Ip`], and for an IEEE 802.15.4
    ///   address that is not an extended address.
    /// - the OS error, if the socket cannot be opened or bound, or the interface
    ///   does not exist.
    pub fn new(name: &str, hardware_addr: HardwareAddress) -> io::Result<RawSocketDriver> {
        let medium = hardware_addr.medium();
        if hardware_addr.to_driver().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an IEEE 802.15.4 interface needs an extended hardware address",
            ));
        }

        let protocol = match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => ETH_P_ALL,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => ETH_P_IEEE802154,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "packet sockets carry link-layer frames, not bare IP packets",
                ));
            }
        };

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol.to_be() as i32,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let mut driver = RawSocketDriver {
            lower,
            mtu: 0,
            hardware_addr,
            rx_buf: None,
        };
        let mut ifreq = ifreq_for(name);

        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol.to_be() as u16,
            sll_ifindex: ifreq_ioctl(lower, &mut ifreq, SIOCGIFINDEX)?,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        unsafe {
            let res = libc::bind(
                lower,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let mtu = ifreq_ioctl(lower, &mut ifreq, SIOCGIFMTU)? as usize;
        driver.mtu = match medium {
            // SIOCGIFMTU returns the IP MTU (typically 1500 bytes.)
            // xarxa counts the entire Ethernet packet in the MTU, so add the Ethernet header size to it.
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => mtu + crate::wire::ETHERNET_HEADER_LEN,
            // SIOCGIFMTU returns 127 - (ACK_PSDU - FCS - 1) - FCS.
            //                    127 - (5 - 2 - 1) - 2 = 123
            // For IEEE802154, we want to add (ACK_PSDU - FCS - 1), since that is what SIOCGIFMTU
            // uses as the size of the link layer header.
            //
            // https://github.com/torvalds/linux/blob/7475e51b87969e01a6812eac713a1c8310372e8a/net/mac802154/iface.c#L541
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => mtu + 2,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => unreachable!(),
        };

        Ok(driver)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(self.lower, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0);
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::send(self.lower, buffer.as_ptr() as *const libc::c_void, buffer.len(), 0);
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for RawSocketDriver {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}

impl Driver for RawSocketDriver {
    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::default();
        caps.medium = self.hardware_addr.medium().into();
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn hardware_address(&self) -> crate::driver::HardwareAddress {
        self.hardware_addr.to_driver().unwrap()
    }

    fn rx_wanted(&mut self) -> usize {
        self.rx_buf.is_none() as usize
    }

    fn rx_give(&mut self, buf: PacketBuf) {
        self.rx_buf = Some(buf);
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let Some(mut buf) = self.rx_buf.take() else {
            // No buffer: drop the frame, if there is one, rather than leave it
            // pending. A short read takes the whole frame.
            let _ = self.recv(&mut [0]);
            return None;
        };
        buf.set_len(buf.capacity());
        match self.recv(&mut buf[..]) {
            Ok(size) => {
                buf.set_len(size);
                Some(buf)
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.rx_buf = Some(buf);
                None
            }
            Err(err) => core::panic!("{}", err),
        }
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        match self.send(&buf) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                debug!("phy: tx failed due to WouldBlock");
                Err(buf)
            }
            Err(err) => core::panic!("{}", err),
        }
    }

    fn can_transmit(&mut self) -> bool {
        true
    }
}
