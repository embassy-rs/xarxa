use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::driver::PacketBuf;
use crate::driver::{Capabilities, Driver};
use crate::iface::Medium;
#[cfg(feature = "medium-ethernet")]
use crate::wire::ETHERNET_HEADER_LEN;
use crate::wire::HardwareAddress;

const SIOCGIFMTU: libc::c_ulong = 0x8921;

// Constant definition as per
// https://github.com/golang/sys/blob/master/unix/zerrors_linux_<arch>.go
const TUNSETIFF: libc::c_ulong = if cfg!(any(
    target_arch = "mips",
    all(target_arch = "mips", target_endian = "little"),
    target_arch = "mips64",
    all(target_arch = "mips64", target_endian = "little"),
    target_arch = "powerpc",
    target_arch = "powerpc64",
    all(target_arch = "powerpc64", target_endian = "little"),
    target_arch = "sparc64"
)) {
    0x800454CA
} else {
    0x400454CA
};
#[cfg(feature = "medium-ip")]
const IFF_TUN: libc::c_int = 0x0001;
#[cfg(feature = "medium-ethernet")]
const IFF_TAP: libc::c_int = 0x0002;
const IFF_NO_PI: libc::c_int = 0x1000;

#[repr(C)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

/// A driver for a virtual TUN (IP) or TAP (Ethernet) interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct TunTapDriver {
    lower: libc::c_int,
    mtu: usize,
    hardware_addr: HardwareAddress,
    /// The buffer the next frame is received into, given by the stack.
    rx_buf: Option<PacketBuf>,
}

impl AsRawFd for TunTapDriver {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl TunTapDriver {
    /// Attaches to a TUN/TAP interface called `name`, or creates it if it does not exist.
    ///
    /// `hardware_addr` is the address the interface reports to the stack, and picks the
    /// medium: [`HardwareAddress::Ip`] opens a TUN interface, an Ethernet address opens a
    /// TAP one.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str, hardware_addr: HardwareAddress) -> io::Result<TunTapDriver> {
        let medium = hardware_addr.medium();

        let lower = unsafe {
            let lower = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK);
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let mut ifreq = ifreq_for(name);
        Self::attach_interface_ifreq(lower, medium, &mut ifreq)?;
        let mtu = Self::mtu_ifreq(medium, &mut ifreq)?;

        Ok(TunTapDriver {
            lower,
            mtu,
            hardware_addr,
            rx_buf: None,
        })
    }

    /// Attaches to a TUN/TAP interface specified by file descriptor `fd`.
    ///
    /// On platforms like Android, a file descriptor to a tun interface is exposed.
    /// On these platforms, a TunTapDriver cannot be instantiated with a name.
    ///
    /// `hardware_addr` is the address the interface reports to the stack, and picks the
    /// medium, as in [`new`](Self::new).
    pub fn from_fd(fd: RawFd, hardware_addr: HardwareAddress, mtu: usize) -> io::Result<TunTapDriver> {
        Ok(TunTapDriver {
            lower: fd,
            mtu,
            hardware_addr,
            rx_buf: None,
        })
    }

    fn attach_interface_ifreq(lower: libc::c_int, medium: Medium, ifr: &mut ifreq) -> io::Result<()> {
        let mode = match medium {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => IFF_TUN,
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => IFF_TAP,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TUN/TAP interfaces do not carry IEEE 802.15.4 frames",
                ));
            }
        };
        ifr.ifr_data = mode | IFF_NO_PI;
        ifreq_ioctl(lower, ifr, TUNSETIFF).map(|_| ())
    }

    fn mtu_ifreq(medium: Medium, ifr: &mut ifreq) -> io::Result<usize> {
        let lower = unsafe {
            let lower = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let ip_mtu = ifreq_ioctl(lower, ifr, SIOCGIFMTU).map(|mtu| mtu as usize);

        unsafe {
            libc::close(lower);
        }

        // Propagate error after close, to ensure we always close.
        let ip_mtu = ip_mtu?;

        // SIOCGIFMTU returns the IP MTU (typically 1500 bytes.)
        // xarxa counts the entire Ethernet packet in the MTU, so add the Ethernet header size to it.
        let mtu = match medium {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => ip_mtu,
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => ip_mtu + ETHERNET_HEADER_LEN,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => unreachable!(),
        };

        Ok(mtu)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::read(self.lower, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::write(self.lower, buffer.as_ptr() as *const libc::c_void, buffer.len());
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for TunTapDriver {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}

impl Driver for TunTapDriver {
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
