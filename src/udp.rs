//! UDP sockets.
//!
//! [`Stack::add_udp_socket`](crate::Stack::add_udp_socket) creates a socket inside
//! the stack and returns a [`UdpHandle`] identifying it. All operations go through
//! [`Stack::udp_socket`](crate::Stack::udp_socket), which borrows the socket as a [`UdpSocket`]:
//! receiving only touches the socket state, while sending transmits the datagram
//! immediately.
//!
//! A single [`bind`](UdpSocket::bind) call pins down (parts of) the socket's
//! 4-tuple, local and remote halves at once, each part exact or wildcard. Binding
//! to port 0 allocates an ephemeral port, and binding an identical 4-tuple to
//! another socket's is rejected.
//!
//! Received packets are queued with their IP and UDP headers still in the buffer.
//! The addresses returned in [`UdpMetadata`] are parsed back out of those header
//! bytes.
//!
//! [`UdpMetadata`] also carries the datagram's [`PacketMeta`] in both directions: on
//! receive it is what the driver attached to the packet, on send it is attached to the
//! packet handed to the driver.

use crate::config::{UDP_RX_QUEUE_COUNT, UDP_SOCKET_COUNT};
use crate::storage::BoundedDeque;
use core::fmt;
use core::ops::{Deref, Range};

use crate::driver::PacketBuf;
use crate::driver::PacketMeta;
#[cfg(feature = "icmp-errors")]
use crate::icmp_error::IcmpError;
use crate::iface::IfaceHandle;
use crate::stack::{IfaceBinding, Stack, TxContext, addr_score, alloc_ephemeral_port};
use crate::storage::Slab;
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
#[cfg(feature = "ipv4")]
use crate::wire::{IPV4_HEADER_LEN, Icmpv4DstUnreachable, Icmpv4Message, Ipv4Packet};
#[cfg(feature = "ipv6")]
use crate::wire::{IPV6_HEADER_LEN, Icmpv6DstUnreachable, Icmpv6Message, Ipv6ExtHeader, Ipv6Packet};
use crate::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpVersion, LINK_HEADER_LEN, UDP_HEADER_LEN, UdpPacket,
};

define_handle! {
    /// A handle to a UDP socket added to a [`Stack`].
    ///
    /// [`Stack`]: crate::Stack
    /// [`Stack::remove_udp_socket`]: crate::Stack::remove_udp_socket
    UdpHandle(crate::config::udp_index)
}

/// Metadata for a sent or received UDP datagram.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UdpMetadata {
    /// The remote endpoint: the sender of an incoming datagram, or the destination of
    /// an outgoing one.
    pub endpoint: IpEndpoint,
    /// The local address: the destination of an incoming datagram (always set), or
    /// the source of an outgoing one. If not set on an outgoing datagram (and the
    /// socket is not bound to a single address), a suitable source address is
    /// selected automatically.
    pub local_address: Option<IpAddress>,
    /// The datagram's [packet metadata](PacketMeta): what the driver attached to an
    /// incoming datagram, or what to attach to an outgoing one (an id to tag it with,
    /// a transmit timestamp to request).
    ///
    /// Zero-sized unless a `packetmeta-*` feature is enabled.
    pub meta: PacketMeta,
}

impl<T: Into<IpEndpoint>> From<T> for UdpMetadata {
    fn from(value: T) -> Self {
        Self {
            endpoint: value.into(),
            local_address: None,
            meta: PacketMeta::default(),
        }
    }
}

impl fmt::Display for UdpMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.endpoint)
    }
}

/// Error returned by [`UdpSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    /// The socket is already bound.
    InvalidState,
    /// Another UDP socket holds an identical 4-tuple.
    InUse,
    /// No free port in the ephemeral range (only possible with tens of thousands
    /// of bound sockets).
    NoFreePorts,
    /// The local and remote addresses belong to different address families, or no
    /// local address is available for the given remote.
    Unaddressable,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::InUse => write!(f, "port in use"),
            BindError::NoFreePorts => write!(f, "no free ports"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`UdpSocket::send_slice`] and [`UdpSocket::send_with`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    /// The socket is not bound.
    InvalidState,
    /// The destination address or port is unspecified, or no matching source
    /// address is available.
    Unaddressable,
    /// The payload does not fit in a packet buffer.
    BufferFull,
    /// No packet buffer is free. Wait for one to be freed, then retry.
    NoBuffer,
    /// The interface the packet would go out of has no room for it right now.
    DeviceBusy,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::InvalidState => write!(f, "invalid state"),
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
            SendError::NoBuffer => write!(f, "no buffer"),
            SendError::DeviceBusy => write!(f, "device busy"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`UdpSocket::recv`] and the peek methods.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    /// The socket is not bound.
    InvalidState,
    /// The RX queue is empty.
    Exhausted,
    /// The provided slice is smaller than the payload. (The packet is dropped by
    /// `recv_slice`, but not by `peek_slice`.)
    Truncated,
    /// An ICMP error message quoting a packet this socket sent has arrived
    /// (reported once, taking it clears it). See
    /// [`take_icmp_error`](UdpSocket::take_icmp_error).
    #[cfg(feature = "icmp-errors")]
    IcmpError {
        /// The kind of error.
        error: IcmpError,
        /// The remote endpoint the erring packet was sent to.
        remote: IpEndpoint,
    },
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
            #[cfg(feature = "icmp-errors")]
            RecvError::IcmpError { error, remote } => {
                write!(f, "icmp error from {}: {}", remote, error)
            }
        }
    }
}

impl core::error::Error for RecvError {}

/// UDP socket state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct UdpSocketState {
    /// The local half of the socket's 4-tuple. The address filters the packet's
    /// destination, from any address of any version to one exact address. A zero
    /// port means the socket is not bound.
    local: IpListenEndpoint,
    /// The remote half of the socket's 4-tuple. Specified parts filter ingress
    /// (only matching datagrams are delivered) and are the default destination
    /// for sends. Unspecified parts match any remote.
    remote: IpListenEndpoint,
    /// The interface the socket is bound to. Zero-sized without `iface-bind`.
    binding: IfaceBinding,
    rx_queue: BoundedDeque<PacketBuf, UDP_RX_QUEUE_COUNT>,
    hop_limit: Option<u8>,
    /// The last ICMP error reported against this socket, with the remote endpoint
    /// it is about. A single slot: a newer error overwrites an unread older one.
    #[cfg(feature = "icmp-errors")]
    pending_error: Option<(IcmpError, IpEndpoint)>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl UdpSocketState {
    /// Wake the task waiting to send, if any.
    #[cfg(feature = "async")]
    pub(crate) fn wake_tx(&mut self) {
        self.tx_waker.wake();
    }

    /// Create an unbound UDP socket.
    pub(crate) fn new() -> UdpSocketState {
        UdpSocketState {
            local: IpListenEndpoint::UNSPECIFIED,
            remote: IpListenEndpoint::UNSPECIFIED,
            binding: IfaceBinding::Any,
            rx_queue: BoundedDeque::new(),
            hop_limit: None,
            #[cfg(feature = "icmp-errors")]
            pending_error: None,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Queue an ingress datagram. `buf` must be a full IP packet (IP header
    /// included), truncated to the UDP length.
    pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
        if self.rx_queue.push_back(buf).is_err() {
            trace!("udp: rx queue full, dropping packet");
            return;
        }
        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    /// Score this socket against an ingress datagram.
    ///
    /// `None` if the socket does not match (a specified tuple part differs),
    /// else how specific the match is, so that the most specific socket wins the
    /// datagram. Connected sockets outscore bound-only ones, and exact addresses
    /// outscore wildcards (see [`addr_score`]).
    ///
    /// `dst_is_bcast` relaxes the local-address filter: sockets bound to a
    /// specific address also accept broadcast/multicast traffic on their port.
    /// It never relaxes the IP version.
    ///
    /// `arrival` is the interface the packet came in on, checked against the
    /// socket's interface binding. `None` skips that check: ICMP errors are
    /// delivered regardless of the interface they arrive on.
    fn match_score(
        &self,
        arrival: Option<IfaceHandle>,
        src_addr: &IpAddress,
        src_port: u16,
        dst_addr: &IpAddress,
        dst_port: u16,
        dst_is_bcast: bool,
    ) -> Option<u8> {
        // The local port is always concrete on a bound socket, and must match.
        if self.local.port != dst_port {
            return None;
        }
        let mut score = match arrival {
            Some(arrival) => self.binding.match_score(arrival)?,
            None => 0,
        };
        score += match addr_score(&self.local, dst_addr) {
            Some(score) => score,
            // Bound to one address, and this is broadcast/multicast traffic on
            // its port: it gets it anyway, as long as the version is its own.
            None if dst_is_bcast && self.local.version() == Some(dst_addr.version()) => 2,
            None => return None,
        };
        score += addr_score(&self.remote, src_addr)?;
        if self.remote.port != 0 {
            if self.remote.port != src_port {
                return None;
            }
            score += 1;
        }
        Some(score)
    }
}

/// A received UDP datagram.
///
/// Returned by [`UdpSocket::recv`]. Derefs to the UDP payload.
///
/// This is zero-copy, it contains the owned buffer the packet arrived in. Dropping it frees the buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct RecvPacket {
    buf: PacketBuf,
    meta: UdpMetadata,
    payload: Range<usize>,
}

impl RecvPacket {
    fn new(mut buf: PacketBuf) -> Self {
        let (meta, payload) = parse_datagram(&mut buf);
        Self { buf, meta, payload }
    }

    /// The datagram's metadata: remote endpoint and local address.
    pub fn meta(&self) -> UdpMetadata {
        self.meta
    }

    /// The UDP payload.
    pub fn payload(&self) -> &[u8] {
        &self.buf[self.payload.clone()]
    }

    /// The UDP payload, mutable.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.payload.clone()]
    }
}

impl Deref for RecvPacket {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.payload()
    }
}

/// Parse the addresses and the payload location out of a queued datagram (a full IP
/// packet starting at the IP header).
///
/// The packet was validated on ingress, so this cannot fail.
fn parse_datagram(buf: &mut PacketBuf) -> (UdpMetadata, Range<usize>) {
    let (src_addr, dst_addr, header_len): (IpAddress, IpAddress, usize) =
        match IpVersion::of_packet(buf).expect("queued packet was validated on ingress") {
            #[cfg(feature = "ipv4")]
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_unchecked(&mut buf[..]);
                (
                    packet.src_addr().into(),
                    packet.dst_addr().into(),
                    packet.header_len() as usize,
                )
            }
            #[cfg(feature = "ipv6")]
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_unchecked(&mut buf[..]);
                let src_addr = packet.src_addr();
                let dst_addr = packet.dst_addr();
                let next_header = packet.next_header();
                let mut header_len = IPV6_HEADER_LEN;
                if next_header == IpProtocol::HopByHop {
                    let ext = Ipv6ExtHeader::new_checked(&buf[IPV6_HEADER_LEN..])
                        .expect("queued packet was validated on ingress");
                    header_len += ext.header_len();
                }
                (src_addr.into(), dst_addr.into(), header_len)
            }
        };

    let packet_meta = buf.meta();
    let udp = UdpPacket::new_unchecked(&mut buf[header_len..]);
    let meta = UdpMetadata {
        endpoint: IpEndpoint::new(src_addr, udp.src_port()),
        local_address: Some(dst_addr),
        meta: packet_meta,
    };
    let payload = header_len + UDP_HEADER_LEN..header_len + udp.len() as usize;
    (meta, payload)
}

/// A UDP socket borrowed from a [`Stack`], returned by [`Stack::udp_socket`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::udp_socket`]: crate::Stack::udp_socket
pub struct UdpSocket<'a, 'd> {
    pub(crate) sockets: &'a mut Slab<UdpSocketState, UDP_SOCKET_COUNT>,
    pub(crate) index: usize,
    pub(crate) tx: TxContext<'a, 'd>,
}

impl UdpSocket<'_, '_> {
    /// This socket's state in the slab.
    #[inline]
    fn inner(&self) -> &UdpSocketState {
        self.sockets.get(self.index)
    }

    /// Mutable variant of [`inner`](Self::inner).
    #[inline]
    fn inner_mut(&mut self) -> &mut UdpSocketState {
        self.sockets.get_mut(self.index)
    }

    /// Return the bound local endpoint. The address is the filter the bind
    /// scoped the socket to. A zero port means the socket is not bound.
    #[inline]
    pub fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner().local
    }

    /// Return the bound remote endpoint. Unspecified parts match any remote:
    /// a fully unspecified endpoint means an ordinary unconnected socket.
    #[inline]
    pub fn remote_endpoint(&self) -> IpListenEndpoint {
        self.inner().remote
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method.
    pub fn hop_limit(&self) -> Option<u8> {
        self.inner().hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA
    /// recommended] value (64).
    ///
    /// # Panics
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        assert!(hop_limit != Some(0));
        self.inner_mut().hop_limit = hop_limit
    }

    /// Bind the socket to an interface, or unbind it with `None`.
    ///
    /// A socket bound to an interface only sends and receives packets on it:
    /// - Destinations must be on-link on that iface, or have a route through it.
    /// - Broadcast and multicast destinations go out on that iface only
    /// - Local addresses will be picked from that iface only.
    ///
    /// The socket must be closed. The binding is kept across
    /// [`close`](Self::close), so a socket stays bound to its interface when
    /// it is bound again.
    ///
    /// Two sockets with otherwise identical tuples may coexist if they are
    /// bound to different interfaces. On ingress, a socket bound to the
    /// arrival interface wins over an unbound one with an equal tuple.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is open.
    #[cfg(feature = "iface-bind")]
    pub fn bind_to_iface(&mut self, iface: Option<IfaceHandle>) -> Result<(), BindError> {
        if self.is_open() {
            return Err(BindError::InvalidState);
        }
        self.inner_mut().binding = iface.into();
        Ok(())
    }

    /// Return the interface the socket is bound to, or `None`.
    ///
    /// See [`bind_to_iface`](Self::bind_to_iface).
    #[cfg(feature = "iface-bind")]
    pub fn bound_iface(&self) -> Option<IfaceHandle> {
        self.inner().binding.iface()
    }

    /// Bind the socket, fixing (parts of) its 4-tuple.
    ///
    /// Every UDP socket is identified by the (local address, local port, remote
    /// address, remote port) tuple, and binding pins parts of it down: each part
    /// of `local` and `remote` is either exact or a wildcard (absent or
    /// unspecified address / zero port):
    ///
    /// - `bind(port, ANY)`: server on all addresses of both IP versions.
    /// - `bind((Ipv4Address::UNSPECIFIED, port), ANY)`: server on all IPv4
    ///   addresses, and no IPv6 one.
    /// - `bind((addr, port), ANY)`: server on one address.
    /// - `bind(0, ANY)`: unconnected sender. A free port in the 49152..=65535
    ///   range is allocated, picked at a random starting point.
    /// - `bind((addr, 0), ANY)`: pin the source address, allocate the port.
    /// - `bind(0, remote)`: ordinary connected client. The local address is
    ///   resolved from the routing tables (a connected socket always has a
    ///   concrete local address), and an ephemeral local port is allocated.
    ///
    /// (`ANY` above is [`IpListenEndpoint::UNSPECIFIED`], the fully wildcard
    /// remote.)
    ///
    /// Specified parts of `remote` filter ingress, so only datagrams matching them
    /// are delivered, and are the default destination for sends. The remote half is
    /// not all-or-nothing: e.g. a remote with only the address specified accepts
    /// any port of that one peer.
    ///
    /// A bind is rejected only if another UDP socket holds the *identical*
    /// 4-tuple. Sharing a local port is fine as long as the tuples differ
    /// (e.g. a connected socket next to a wildcard server socket, two sockets
    /// connected to different remotes, or the two halves of a dual stack,
    /// `(Ipv4Address::UNSPECIFIED, port)` and `(Ipv6Address::UNSPECIFIED,
    /// port)`). Distinct overlapping tuples are never ambiguous, since each
    /// datagram is handed to the most specific match. Ephemeral allocation
    /// applies the same rule, so connected sockets can reuse ports held by
    /// sockets with a different remote.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is already bound (see
    /// [is_open](#method.is_open)), `Err(BindError::InUse)` on an identical
    /// bind, `Err(BindError::NoFreePorts)` if the ephemeral range is exhausted,
    /// and `Err(BindError::Unaddressable)` on an address family mismatch or if
    /// no local address is available for the given remote.
    pub fn bind(
        &mut self,
        local: impl Into<IpListenEndpoint>,
        remote: impl Into<IpListenEndpoint>,
    ) -> Result<(), BindError> {
        let mut local: IpListenEndpoint = local.into();
        let remote: IpListenEndpoint = remote.into();
        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        // Neither half may restrict the socket to a family the other excludes.
        // That includes the per-version wildcards, which restrict without naming
        // an address.
        if let (Some(local_version), Some(remote_version)) = (local.version(), remote.version())
            && local_version != remote_version
        {
            return Err(BindError::Unaddressable);
        }

        let binding = self.inner().binding;

        // A fully-specified remote resolves a wildcard local address via a route
        // lookup. A connected socket always has a concrete local address.
        if let Some(remote_addr) = remote.concrete_addr()
            && remote.port != 0
            && local.concrete_addr().is_none()
        {
            local.addr = Some(
                self.tx
                    .get_source_address(binding, &remote_addr)
                    .ok_or(BindError::Unaddressable)?,
            );
        }

        // Only an *identical* 4-tuple conflicts: any difference (a wildcard vs.
        // an exact part included) is resolved by demux picking the most
        // specific match, so nothing is shadowed. The interface binding is part
        // of the identity: same-tuple sockets bound to different interfaces
        // coexist, and a packet arrives on exactly one interface.
        let (sockets, index) = (&self.sockets, self.index);
        let in_use = |local: IpListenEndpoint| {
            sockets
                .iter()
                .any(|(i, s)| i != index && s.local == local && s.remote == remote && s.binding == binding)
        };

        if local.port == 0 {
            local.port = alloc_ephemeral_port(self.tx.rand(), |port| {
                in_use(IpListenEndpoint { addr: local.addr, port })
            })
            .ok_or(BindError::NoFreePorts)?;
        } else if in_use(local) {
            return Err(BindError::InUse);
        }

        let state = self.inner_mut();
        state.local = local;
        state.remote = remote;
        // Sends are possible now, and receives can start failing differently.
        #[cfg(feature = "async")]
        {
            state.rx_waker.wake();
            state.tx_waker.wake();
        }
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        let state = self.inner_mut();
        state.local = IpListenEndpoint::UNSPECIFIED;
        state.remote = IpListenEndpoint::UNSPECIFIED;
        state.rx_queue.clear();
        #[cfg(feature = "icmp-errors")]
        {
            state.pending_error = None;
        }
        // Wake the tasks waiting, so they can notice the socket is closed.
        #[cfg(feature = "async")]
        {
            state.rx_waker.wake();
            state.tx_waker.wake();
        }
    }

    /// Check whether the socket is open (bound to a port).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().local.port != 0
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `recv` calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   incoming data may wake it again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &core::task::Waker) {
        self.inner_mut().rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `send` calls, such as the socket being bound or closed.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   it may be woken again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &core::task::Waker) {
        self.inner_mut().tx_waker.register(waker)
    }

    /// Check whether the RX queue is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.inner().rx_queue.is_empty()
    }

    /// Dequeue a received datagram, as an owned packet ([`RecvPacket`]).
    ///
    /// This is zero-copy: the returned value is the buffer the datagram arrived in.
    ///
    /// Returns `Err(RecvError::InvalidState)` if the socket is not bound, and
    /// `Err(RecvError::Exhausted)` if the RX queue is empty.
    ///
    /// With the `icmp-errors` feature, a pending ICMP error is reported
    /// first, as `Err(RecvError::IcmpError { .. })`, once, clearing it, before
    /// any queued datagrams. See [`take_icmp_error`](Self::take_icmp_error).
    pub fn recv(&mut self) -> Result<RecvPacket, RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        let state = self.inner_mut();
        #[cfg(feature = "icmp-errors")]
        if let Some((error, remote)) = state.pending_error.take() {
            return Err(RecvError::IcmpError { error, remote });
        }
        let buf = state.rx_queue.pop_front().ok_or(RecvError::Exhausted)?;
        Ok(RecvPacket::new(buf))
    }

    /// Dequeue a received datagram, copying the payload into the given slice, and
    /// return the number of octets copied along with its metadata.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the
    /// payload, the packet is dropped and `Err(RecvError::Truncated)` is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let packet = self.recv()?;
        let payload = packet.payload();
        if data.len() < payload.len() {
            return Err(RecvError::Truncated);
        }
        data[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), packet.meta()))
    }

    /// Peek at the next received datagram without dequeueing it, returning its
    /// payload and its metadata.
    ///
    /// Returns `Err(RecvError::InvalidState)` if the socket is not bound, and
    /// `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn peek(&mut self) -> Result<(&[u8], UdpMetadata), RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        let buf = self
            .sockets
            .get_mut(self.index)
            .rx_queue
            .front_mut()
            .ok_or(RecvError::Exhausted)?;
        let (meta, payload) = parse_datagram(buf);
        Ok((&buf[payload], meta))
    }

    /// Peek at the next received datagram without dequeueing it, copying the payload
    /// into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the
    /// payload, no data is copied and `Err(RecvError::Truncated)` is returned. The
    /// packet stays in the queue.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let (payload, meta) = self.peek()?;
        if data.len() < payload.len() {
            return Err(RecvError::Truncated);
        }
        data[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), meta))
    }

    /// Take the pending ICMP error, if one has been reported against this socket:
    /// the kind of error and the remote endpoint the erring packet was sent to.
    ///
    /// When an ICMP error message arrives, from the network (e.g. port
    /// unreachable) or generated locally when neighbor resolution for a
    /// destination fails, it is delivered to the most specific socket matching the
    /// quoted packet's flow, like ordinary ingress demux, and stored here. A single
    /// error is kept (the newest wins), reported once through either this method or
    /// [`recv`](Self::recv), whichever is called first, and cleared by the report.
    /// The RX waker is woken when an error is recorded.
    ///
    /// The remote endpoint is attached so that errors on unconnected sockets are
    /// attributable.
    #[cfg(feature = "icmp-errors")]
    pub fn take_icmp_error(&mut self) -> Option<(IcmpError, IpEndpoint)> {
        self.inner_mut().pending_error.take()
    }

    /// Send a datagram to the given remote endpoint, copying the payload from a slice.
    ///
    /// See [send_with](#method.send_with).
    pub fn send_slice(&mut self, data: &[u8], meta: impl Into<UdpMetadata>) -> Result<(), SendError> {
        self.send_with(data.len(), meta, |buf| {
            buf.copy_from_slice(data);
            data.len()
        })
    }

    /// Send a datagram, building the payload in place.
    ///
    /// The destination is `meta.endpoint`, with unspecified parts defaulted from
    /// the socket's bound remote endpoint. On a connected socket, sending to
    /// `IpEndpoint::UNSPECIFIED` sends to the connected remote. An explicitly
    /// specified destination is honored even on a connected socket.
    ///
    /// The closure gets a `max_size`-byte slice inside a freshly allocated packet
    /// buffer, and returns how many bytes it wrote. The datagram is then sent
    /// immediately. If the destination's neighbor is unresolved, the packet is queued
    /// inside the stack and sent when resolution completes. This still counts as a
    /// successful send.
    ///
    /// `meta.meta` is attached to the packet and handed to the driver with it: an id
    /// to tag the packet with, or a request to timestamp its transmission (see
    /// [`Iface::poll_tx_timestamp`](crate::iface::Iface::poll_tx_timestamp)).
    ///
    /// Returns `Err(SendError::InvalidState)` if the socket is not bound.
    /// Returns `Err(SendError::Unaddressable)` if the destination address or port
    /// is still unspecified after defaulting, the destination's address family does
    /// not match the source address, no source address is available, or the source
    /// address is not assigned to any interface.
    /// Returns `Err(SendError::BufferFull)` if the payload cannot fit in a packet
    /// buffer.
    /// Returns `Err(SendError::NoBuffer)` if every packet buffer is in use.
    pub fn send_with(
        &mut self,
        max_size: usize,
        meta: impl Into<UdpMetadata>,
        f: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SendError> {
        let mut meta = meta.into();
        let (local, remote, binding, hop_limit) = {
            let socket = self.inner();
            (
                socket.local,
                socket.remote,
                socket.binding,
                socket.hop_limit.unwrap_or(64),
            )
        };

        if local.port == 0 {
            return Err(SendError::InvalidState);
        }

        // Default unspecified parts of the destination from the bound remote. Only a
        // concrete remote address is a destination. The per-version wildcards are
        // filters, and leave the destination unspecified.
        if meta.endpoint.addr.is_unspecified()
            && let Some(addr) = remote.concrete_addr()
        {
            meta.endpoint.addr = addr;
        }
        if meta.endpoint.port == 0 {
            meta.endpoint.port = remote.port;
        }
        if !meta.endpoint.is_specified() {
            return Err(SendError::Unaddressable);
        }
        // A bind scoped to one IP version cannot send over the other: the replies
        // would arrive on a version its own ingress filter drops.
        if local
            .version()
            .is_some_and(|version| version != meta.endpoint.addr.version())
        {
            return Err(SendError::Unaddressable);
        }

        // Route the destination first: the source address may come from the
        // egress interface, and the packet is only built once that interface has
        // room for it.
        let route = self
            .tx
            .route(binding, &meta.endpoint.addr)
            .ok_or(SendError::Unaddressable)?;

        // Pick the source address: explicit in the metadata, else the socket's bound
        // address (only a concrete one is an address, the wildcards are filters),
        // else one chosen from the destination.
        let src_addr = match meta.local_address.or(local.concrete_addr()) {
            Some(addr) => addr,
            None => self
                .tx
                .get_source_address_routed(&route, &meta.endpoint.addr)
                .ok_or(SendError::Unaddressable)?,
        };
        if src_addr.version() != meta.endpoint.addr.version() {
            return Err(SendError::Unaddressable);
        }
        // The source address must be assigned to some interface, not necessarily
        // the egress one (weak host model). A stack-selected source is ours by
        // construction, this catches an explicit or bound source address that
        // isn't (or no longer is) ours.
        if !self.tx.has_ip_addr(src_addr) {
            return Err(SendError::Unaddressable);
        }

        // Build the datagram: reserve headroom for the headers below, write the
        // payload, prepend the UDP header.
        let ip_header_len = match meta.endpoint.addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(_) => IPV4_HEADER_LEN,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => IPV6_HEADER_LEN,
        };
        let headroom = LINK_HEADER_LEN + ip_header_len + UDP_HEADER_LEN;

        if !self.tx.can_transmit(route.iface) {
            self.tx.inner.set_tx_starved();
            return Err(SendError::DeviceBusy);
        }
        let Some(mut buf) = PacketBuf::try_new() else {
            self.tx.inner.set_tx_starved();
            return Err(SendError::NoBuffer);
        };
        if max_size > buf.capacity() - headroom {
            return Err(SendError::BufferFull);
        }
        buf.set_meta(meta.meta);
        buf.reserve(headroom);
        buf.set_len(max_size);
        let size = f(&mut buf);
        assert!(size <= max_size);
        buf.set_len(size);

        buf.push_front(UDP_HEADER_LEN);
        let udp_len = buf.len();
        {
            let mut udp = UdpPacket::new_unchecked(&mut buf);
            udp.set_src_port(local.port);
            udp.set_dst_port(meta.endpoint.port);
            udp.set_len(udp_len as u16);
            if self.tx.checksum_caps(route.iface).udp.tx() {
                udp.fill_checksum(&src_addr, &meta.endpoint.addr);
            } else {
                // A zero checksum means "no checksum" on UDP-over-IPv4, and is what a
                // device that computes it itself expects to find in the field.
                udp.set_checksum(0);
            }
        }

        trace!("udp:{}:{}: sending {} octets", local, meta.endpoint, size);

        self.tx
            .transmit_ip(&route, buf, src_addr, meta.endpoint.addr, IpProtocol::Udp, hop_limit);
        Ok(())
    }
}

impl Stack<'_> {
    /// Process an ingress UDP packet: validate it and queue it on the first matching
    /// socket.
    ///
    /// `buf` starts at the UDP header. `ip_header_len` is the length of the IP header
    /// in front of it, which is added back to the buffer before queueing, so that
    /// `recv` can parse the addresses back out of it.
    pub(crate) fn process_udp(
        &mut self,
        iface: IfaceHandle,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        ip_header_len: usize,
        handled_by_raw: bool,
        mut buf: PacketBuf,
    ) {
        let Ok(udp_packet) = UdpPacket::new_checked(&mut buf) else {
            trace!("udp: malformed packet");
            return;
        };
        if self.ifaces.get(iface.index()).checksum_caps().udp.rx() && !udp_packet.verify_checksum(&src_addr, &dst_addr)
        {
            trace!("udp: checksum incorrect");
            return;
        }

        let src_port = udp_packet.src_port();
        let dst_port = udp_packet.dst_port();
        if dst_port == 0 {
            return;
        }
        let udp_len = udp_packet.len() as usize;
        let payload_len = udp_len - UDP_HEADER_LEN;

        // Strip anything past the UDP length, and add the IP header back: the queued
        // packet keeps its headers, and recv() parses the addresses back out of them.
        buf.set_len(udp_len);
        buf.push_front(ip_header_len);

        // Sockets bound to a specific address also accept broadcast/multicast traffic
        // on their port.
        let dst_is_bcast = self.ifaces.get(iface.index()).is_broadcast(&dst_addr) || dst_addr.is_multicast();

        if let Some(index) = demux(
            &self.sockets.udp,
            Some(iface),
            &src_addr,
            src_port,
            &dst_addr,
            dst_port,
            dst_is_bcast,
        ) {
            let socket = self.sockets.udp.get_mut(index);
            trace!(
                "udp:{}: receiving {} octets from {}:{}",
                socket.local, payload_len, src_addr, src_port
            );
            socket.rx_enqueue(buf);
            return;
        }

        trace!("udp: no socket bound to port {}, dropping", dst_port);
        // ICMP port unreachable. The IP header was added back above, so `buf` is
        // the whole original packet again, ready to be quoted. Suppressed when a raw
        // socket got a copy: the application is handling UDP itself, and the error
        // would sabotage its exchange.
        if !handled_by_raw {
            match dst_addr {
                #[cfg(feature = "ipv4")]
                IpAddress::Ipv4(_) => self.transmit_icmpv4_error(
                    iface,
                    &mut buf,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::PortUnreachable.into(),
                ),
                #[cfg(feature = "ipv6")]
                IpAddress::Ipv6(_) => self.transmit_icmpv6_error(
                    iface,
                    &mut buf,
                    Icmpv6Message::DstUnreachable,
                    Icmpv6DstUnreachable::PortUnreachable.into(),
                    0,
                    false,
                ),
            }
        }
    }
}

/// The socket a datagram with this tuple should go to, or `None` if no socket
/// wants it.
///
/// Linear scan, most specific match wins: every candidate whose specified tuple
/// parts all match is scored by how specific those parts are. Connected sockets
/// beat bound-only ones, exact addresses beat per-version wildcards beat
/// wildcards. Ties (only possible between sockets specific in *different* parts)
/// go to the earliest socket.
fn demux(
    sockets: &Slab<UdpSocketState, UDP_SOCKET_COUNT>,
    iface: Option<IfaceHandle>,
    src_addr: &IpAddress,
    src_port: u16,
    dst_addr: &IpAddress,
    dst_port: u16,
    dst_is_bcast: bool,
) -> Option<usize> {
    let mut best: Option<(usize, u8)> = None;
    for (index, socket) in sockets.iter() {
        if let Some(score) = socket.match_score(iface, src_addr, src_port, dst_addr, dst_port, dst_is_bcast)
            && best.is_none_or(|(_, best_score)| score > best_score)
        {
            best = Some((index, score));
        }
    }
    best.map(|(index, _)| index)
}

/// Deliver an ICMP error to the UDP socket whose packet provoked it.
///
/// `local`/`remote` are the flow parsed from the packet quoted in the error, a
/// packet this stack sent. Sockets are scored exactly like ordinary ingress demux
/// (an incoming datagram of this flow travels `remote` → `local`), and the most
/// specific match gets the error.
#[cfg(feature = "icmp-errors")]
pub(crate) fn process_icmp_error(
    sockets: &mut Slab<UdpSocketState, UDP_SOCKET_COUNT>,
    error: IcmpError,
    local: IpEndpoint,
    remote: IpEndpoint,
) {
    if let Some(index) = demux(sockets, None, &remote.addr, remote.port, &local.addr, local.port, false) {
        let socket = sockets.get_mut(index);
        trace!("udp:{}: icmp error from {}: {}", socket.local, remote, error);
        socket.pending_error = Some((error, remote));
        #[cfg(feature = "async")]
        socket.rx_waker.wake();
    }
}

/// Iterator over the UDP sockets of a [`Stack`], returned by [`Stack::udp_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.udp_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.can_recv());
/// }
/// # }
/// ```
pub struct UdpSocketIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> UdpSocketIter<'_, 'd> {
    /// Get the next UDP socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(UdpHandle, UdpSocket<'_, 'd>)> {
        let index = self.stack.sockets.udp.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = UdpHandle::new(index);
        Some((handle, self.stack.udp_socket(handle)))
    }
}

#[cfg(all(test, feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
mod test {
    use super::*;
    use crate::iface::Medium;
    use crate::stack::Stack;
    use crate::test_device::TestDevice;
    use crate::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address};

    fn stack_with_socket() -> (Stack<'static>, UdpHandle) {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_udp_socket().unwrap();
        (stack, handle)
    }

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const OTHER_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 3);
    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    /// The fully wildcard remote: an ordinary unconnected bind.
    const ANY: IpListenEndpoint = IpListenEndpoint::UNSPECIFIED;

    /// A stack with one interface owning `LOCAL_ADDR`, so that binds with a
    /// specified remote can resolve their local address.
    fn stack_with_iface() -> Stack<'static> {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = TestDevice::new(Medium::Ip).install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(handle)
            .add_ip_addr(IpCidr::new(LOCAL_ADDR.into(), 24))
            .unwrap();
        stack
    }

    /// Build a queued-datagram buffer the way ingress does, as a full IPv4 + UDP packet.
    fn queued_packet_from(src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, payload: &[u8]) -> PacketBuf {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut buf = PacketBuf::try_new().unwrap();
        buf.set_len(IPV4_HEADER_LEN + udp_len);
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + udp_len) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut buf[IPV4_HEADER_LEN..]);
            udp.set_src_port(src_port);
            udp.set_dst_port(LOCAL_PORT);
            udp.set_len(udp_len as u16);
            udp.payload_mut().copy_from_slice(payload);
            udp.fill_checksum(&src_addr.into(), &dst_addr.into());
        }
        buf
    }

    fn queued_packet(payload: &[u8]) -> PacketBuf {
        queued_packet_from(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, payload)
    }

    /// Run a packet through the stack's UDP ingress demux.
    fn deliver(stack: &mut Stack, src_addr: Ipv4Address, src_port: u16, payload: &[u8]) {
        deliver_to(stack, src_addr, src_port, LOCAL_ADDR, payload)
    }

    /// Like [`deliver`], with an explicit destination address.
    fn deliver_to(stack: &mut Stack, src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, payload: &[u8]) {
        deliver_on(stack, IfaceHandle::new(0), src_addr, src_port, dst_addr, payload)
    }

    /// Like [`deliver_to`], with an explicit arrival interface.
    fn deliver_on(
        stack: &mut Stack,
        iface: IfaceHandle,
        src_addr: Ipv4Address,
        src_port: u16,
        dst_addr: Ipv4Address,
        payload: &[u8],
    ) {
        let mut buf = queued_packet_from(src_addr, src_port, dst_addr, payload);
        buf.pull_front(IPV4_HEADER_LEN);
        stack.process_udp(iface, src_addr.into(), dst_addr.into(), IPV4_HEADER_LEN, false, buf);
    }

    #[test]
    fn test_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);
        assert!(!socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT, ANY), Ok(()));
        assert!(socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT, ANY), Err(BindError::InvalidState));

        socket.close();
        assert!(!socket.is_open());
        assert_eq!(socket.bind((LOCAL_ADDR, LOCAL_PORT), ANY), Ok(()));
        assert_eq!(
            socket.local_endpoint(),
            IpListenEndpoint {
                addr: Some(LOCAL_ADDR.into()),
                port: LOCAL_PORT
            }
        );
        assert_eq!(socket.remote_endpoint(), IpListenEndpoint::UNSPECIFIED);
    }

    #[test]
    fn test_bind_ephemeral() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h1 = stack.add_udp_socket().unwrap();
        let h2 = stack.add_udp_socket().unwrap();

        stack.udp_socket(h1).bind(0, ANY).unwrap();
        let p1 = stack.udp_socket(h1).local_endpoint().port;
        assert!(p1 >= EPHEMERAL_PORT_MIN);

        // The second allocation must avoid the first socket's port.
        stack.udp_socket(h2).bind(0, ANY).unwrap();
        let p2 = stack.udp_socket(h2).local_endpoint().port;
        assert!(p2 >= EPHEMERAL_PORT_MIN);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_bind_conflicts() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h1 = stack.add_udp_socket().unwrap();
        let h2 = stack.add_udp_socket().unwrap();

        // Identical 4-tuples conflict.
        stack.udp_socket(h1).bind(LOCAL_PORT, ANY).unwrap();
        assert_eq!(stack.udp_socket(h2).bind(LOCAL_PORT, ANY), Err(BindError::InUse));
        // A specific address next to an address-less bind on the same port is
        // fine: the tuples differ, and demux picks the most specific match.
        stack.udp_socket(h2).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        // Two different specific addresses may share a port. (Free a slot first:
        // without `alloc` the socket slab is small.)
        stack.remove_udp_socket(h1);
        let h3 = stack.add_udp_socket().unwrap();
        let h4 = stack.add_udp_socket().unwrap();
        let h5 = stack.add_udp_socket().unwrap();
        stack.udp_socket(h3).bind((LOCAL_ADDR, LOCAL_PORT + 2), ANY).unwrap();
        stack.udp_socket(h4).bind((OTHER_ADDR, LOCAL_PORT + 2), ANY).unwrap();
        // ...but the same specific address may not.
        assert_eq!(
            stack.udp_socket(h5).bind((LOCAL_ADDR, LOCAL_PORT + 2), ANY),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_bind_conflicts_connected() {
        let mut stack = stack_with_iface();
        let h1 = stack.add_udp_socket().unwrap();
        let h2 = stack.add_udp_socket().unwrap();
        let h3 = stack.add_udp_socket().unwrap();
        let h4 = stack.add_udp_socket().unwrap();

        // A connected socket and a wildcard-remote socket share a local port:
        // the 4-tuples differ.
        stack
            .udp_socket(h1)
            .bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT))
            .unwrap();
        stack.udp_socket(h2).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        // So do two sockets connected to different remotes.
        stack
            .udp_socket(h3)
            .bind(LOCAL_PORT, (OTHER_ADDR, REMOTE_PORT))
            .unwrap();

        // The identical local + remote is rejected. (h1's local address was
        // resolved to LOCAL_ADDR, so this bind duplicates its whole tuple.)
        assert_eq!(
            stack
                .udp_socket(h4)
                .bind((LOCAL_ADDR, LOCAL_PORT), (REMOTE_ADDR, REMOTE_PORT)),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_bind_conflicts_per_version() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h1 = stack.add_udp_socket().unwrap();
        let h2 = stack.add_udp_socket().unwrap();
        let h3 = stack.add_udp_socket().unwrap();

        // The two halves of a dual stack are different tuples, so they may
        // share a port, as may the address-less bind that covers both.
        stack
            .udp_socket(h1)
            .bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();
        stack
            .udp_socket(h2)
            .bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();
        stack.udp_socket(h3).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp_socket(h3).close();

        // Identity does distinguish the versions: only the same half conflicts.
        assert_eq!(
            stack.udp_socket(h3).bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_send_per_version_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);
        socket.bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY).unwrap();

        // The bind scopes the socket to IPv6, so an IPv4 destination contradicts it.
        assert_eq!(
            socket.send_slice(b"hi", (REMOTE_ADDR, REMOTE_PORT)),
            Err(SendError::Unaddressable)
        );
    }

    #[test]
    fn test_demux_per_version() {
        // A bind to any IPv6 address takes no IPv4 traffic, not even on the port
        // it holds.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"no");
        assert!(!stack.udp_socket(handle).can_recv());

        // The IPv4 half of the same port does take it.
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"yes");
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"yes");
    }

    #[test]
    fn test_bind_connected() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        let mut socket = stack.udp_socket(handle);

        // Local fully wildcard + exact remote: the ordinary connected client.
        // The local address is resolved from the routing tables, and an
        // ephemeral port is allocated.
        socket.bind(0, (REMOTE_ADDR, REMOTE_PORT)).unwrap();
        let local = socket.local_endpoint();
        assert_eq!(local.addr, Some(LOCAL_ADDR.into()));
        assert!(local.port >= EPHEMERAL_PORT_MIN);
        assert_eq!(
            socket.remote_endpoint(),
            IpListenEndpoint {
                addr: Some(REMOTE_ADDR.into()),
                port: REMOTE_PORT
            }
        );
    }

    #[test]
    fn test_bind_connected_unaddressable() {
        // Without any interface there is no local address for the remote.
        let (mut stack, handle) = stack_with_socket();
        assert_eq!(
            stack.udp_socket(handle).bind(0, (REMOTE_ADDR, REMOTE_PORT)),
            Err(BindError::Unaddressable)
        );

        // Mismatched local/remote address families.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        assert_eq!(
            stack.udp_socket(handle).bind(
                (LOCAL_ADDR, LOCAL_PORT),
                (crate::wire::Ipv6Address::LOCALHOST, REMOTE_PORT)
            ),
            Err(BindError::Unaddressable)
        );
    }

    #[test]
    fn test_connected_demux_filter() {
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT))
            .unwrap();

        // Matching the connected remote: delivered.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"yes");
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"yes");

        // Wrong source address or port: filtered out.
        deliver(&mut stack, OTHER_ADDR, REMOTE_PORT, b"no");
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"no");
        assert!(!stack.udp_socket(handle).can_recv());
    }

    #[test]
    fn test_remote_addr_only_filter() {
        // A partially specified remote: any port of one peer.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(LOCAL_PORT, (REMOTE_ADDR, 0)).unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"a");
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"b");
        deliver(&mut stack, OTHER_ADDR, REMOTE_PORT, b"no");
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"a");
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"b");
        assert!(!stack.udp_socket(handle).can_recv());
    }

    #[test]
    fn test_demux_priority() {
        // When several sockets match a datagram, the most specific one wins,
        // regardless of creation order: connected beats bound-to-address beats
        // wildcard.
        let mut stack = stack_with_iface();
        let h_any = stack.add_udp_socket().unwrap();
        let h_addr = stack.add_udp_socket().unwrap();
        let h_conn = stack.add_udp_socket().unwrap();
        stack.udp_socket(h_any).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp_socket(h_addr).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();
        stack
            .udp_socket(h_conn)
            .bind((LOCAL_ADDR, LOCAL_PORT), (REMOTE_ADDR, REMOTE_PORT))
            .unwrap();

        // From the connected remote: the connected socket wins.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"conn");
        // From another port of the same peer: the address-bound socket.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"addr");
        // To another local address: only the wildcard socket matches.
        deliver_to(&mut stack, REMOTE_ADDR, REMOTE_PORT, OTHER_ADDR, b"any");

        assert_eq!(&*stack.udp_socket(h_conn).recv().unwrap(), b"conn");
        assert!(!stack.udp_socket(h_conn).can_recv());
        assert_eq!(&*stack.udp_socket(h_addr).recv().unwrap(), b"addr");
        assert!(!stack.udp_socket(h_addr).can_recv());
        assert_eq!(&*stack.udp_socket(h_any).recv().unwrap(), b"any");
        assert!(!stack.udp_socket(h_any).can_recv());
    }

    #[test]
    fn test_demux_priority_per_version() {
        // The per-version wildcard sits between the address-less bind and an
        // exact address: it takes its version's traffic away from the
        // dual-stack socket, and gives it up to the exact address in turn.
        let mut stack = stack_with_iface();
        let h_any = stack.add_udp_socket().unwrap();
        let h_v4 = stack.add_udp_socket().unwrap();
        let h_addr = stack.add_udp_socket().unwrap();
        stack.udp_socket(h_any).bind(LOCAL_PORT, ANY).unwrap();
        stack
            .udp_socket(h_v4)
            .bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"v4");
        assert_eq!(&*stack.udp_socket(h_v4).recv().unwrap(), b"v4");
        assert!(!stack.udp_socket(h_any).can_recv());

        stack.udp_socket(h_addr).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"addr");
        assert_eq!(&*stack.udp_socket(h_addr).recv().unwrap(), b"addr");
        assert!(!stack.udp_socket(h_v4).can_recv());
        assert!(!stack.udp_socket(h_any).can_recv());
    }

    #[test]
    fn test_send_defaults_to_remote() {
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        let mut socket = stack.udp_socket(handle);

        // Not bound yet.
        assert_eq!(
            socket.send_slice(b"hi", (REMOTE_ADDR, REMOTE_PORT)),
            Err(SendError::InvalidState)
        );

        // Unconnected socket: a wildcard destination is unaddressable.
        socket.bind(LOCAL_PORT, ANY).unwrap();
        assert_eq!(
            socket.send_slice(b"hi", IpEndpoint::UNSPECIFIED),
            Err(SendError::Unaddressable)
        );
        socket.close();

        // Connected socket: the destination defaults to the bound remote, and
        // an explicit destination overrides it.
        socket.bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT)).unwrap();
        assert_eq!(socket.send_slice(b"hi", IpEndpoint::UNSPECIFIED), Ok(()));
        assert_eq!(socket.send_slice(b"hi", IpEndpoint::new(OTHER_ADDR.into(), 9)), Ok(()));
    }

    /// Packet metadata travels in both directions: what the driver attached to a
    /// received datagram comes back out of `recv`, and what `send` was given reaches
    /// the driver with the frame.
    #[cfg(feature = "packetmeta-id")]
    #[test]
    fn test_packet_meta() {
        let driver = TestDevice::new(Medium::Ip);
        let sent = driver.tx_meta.clone();
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let iface = driver.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(LOCAL_ADDR.into(), 24))
            .unwrap();

        let handle = stack.add_udp_socket().unwrap();
        let mut socket = stack.udp_socket(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();

        // Ingress: the driver's metadata comes out of recv.
        let mut buf = queued_packet(b"abcdef");
        buf.meta_mut().id = 0x1234;
        socket.inner_mut().rx_enqueue(buf);
        assert_eq!(socket.recv().unwrap().meta().meta.id, 0x1234);

        // Egress: the metadata given to send reaches the device.
        let mut meta: UdpMetadata = IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT).into();
        meta.meta.id = 0x5678;
        socket.send_slice(b"hi", meta).unwrap();
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(sent.borrow()[0].id, 0x5678);

        // ... and a plain send carries the default.
        socket
            .send_slice(b"hi", IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT))
            .unwrap();
        assert_eq!(sent.borrow()[1], PacketMeta::default());
    }

    #[test]
    fn test_send_requires_own_src_addr() {
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket().unwrap();
        let mut socket = stack.udp_socket(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();

        let dst = IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT);

        // An explicit source address that isn't ours fails synchronously, the
        // interface's own address works. (Raw sockets, by contrast, may send
        // any source address.)
        assert_eq!(
            socket.send_slice(
                b"hi",
                UdpMetadata {
                    endpoint: dst,
                    local_address: Some(OTHER_ADDR.into()),
                    meta: PacketMeta::default(),
                }
            ),
            Err(SendError::Unaddressable)
        );
        assert_eq!(
            socket.send_slice(
                b"hi",
                UdpMetadata {
                    endpoint: dst,
                    local_address: Some(LOCAL_ADDR.into()),
                    meta: PacketMeta::default(),
                }
            ),
            Ok(())
        );
        socket.close();

        // A bound source address that is no longer ours (the interface's
        // address changed) also fails the send.
        socket
            .bind((LOCAL_ADDR, LOCAL_PORT), (REMOTE_ADDR, REMOTE_PORT))
            .unwrap();
        assert_eq!(socket.send_slice(b"hi", dst), Ok(()));
        stack.ifaces.get_mut(0).ip_addrs.clear();
        stack
            .ifaces
            .get_mut(0)
            .ip_addrs
            .push(crate::iface::IfaceAddr::manual(IpCidr::new(OTHER_ADDR.into(), 24)))
            .unwrap();
        let mut socket = stack.udp_socket(handle);
        assert_eq!(socket.send_slice(b"hi", dst), Err(SendError::Unaddressable));
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_socket_slab_full() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let mut handles = std::vec::Vec::new();
        for _ in 0..UDP_SOCKET_COUNT {
            handles.push(stack.add_udp_socket().unwrap());
        }
        assert_eq!(stack.add_udp_socket(), Err(crate::Full));
        // Removing one makes room again, and its slot is reused.
        stack.remove_udp_socket(handles[1]);
        assert_eq!(stack.add_udp_socket(), Ok(handles[1]));
    }

    #[test]
    fn test_rx_queue_full_drops() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();

        // One more datagram than the queue holds: the extra one is dropped.
        for _ in 0..UDP_RX_QUEUE_COUNT + 1 {
            socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));
        }
        for _ in 0..UDP_RX_QUEUE_COUNT {
            assert!(socket.recv().is_ok());
        }
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));
    }

    #[test]
    fn test_recv() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);

        // Not bound yet.
        assert_eq!(socket.recv().err(), Some(RecvError::InvalidState));
        assert_eq!(socket.peek().err(), Some(RecvError::InvalidState));

        socket.bind(LOCAL_PORT, ANY).unwrap();

        assert!(!socket.can_recv());
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));

        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));
        assert!(socket.can_recv());

        let packet = socket.recv().unwrap();
        assert_eq!(packet.payload(), b"abcdef");
        assert_eq!(&*packet, b"abcdef");
        assert_eq!(
            packet.meta(),
            UdpMetadata {
                endpoint: IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT),
                local_address: Some(LOCAL_ADDR.into()),
                meta: PacketMeta::default(),
            }
        );
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_peek_and_recv_slice() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();
        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));

        let (payload, meta) = socket.peek().unwrap();
        assert_eq!(payload, b"abcdef");
        assert_eq!(meta.endpoint.port, REMOTE_PORT);

        // Peeking does not dequeue.
        let mut slice = [0; 16];
        assert_eq!(socket.peek_slice(&mut slice).unwrap().0, 6);
        assert_eq!(&slice[..6], b"abcdef");

        let (len, meta) = socket.recv_slice(&mut slice).unwrap();
        assert_eq!(&slice[..len], b"abcdef");
        assert_eq!(meta.endpoint, IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT));
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Exhausted));
    }

    #[test]
    fn test_recv_slice_truncated() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp_socket(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();
        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));

        let mut slice = [0; 4];
        // peek_slice keeps the packet...
        assert_eq!(socket.peek_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(socket.can_recv());
        // ...recv_slice drops it.
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(!socket.can_recv());
    }

    #[cfg(feature = "iface-bind")]
    const LOCAL2_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 2, 1);
    #[cfg(feature = "iface-bind")]
    const REMOTE2_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 2, 2);

    /// A stack with two IP-medium interfaces on different subnets:
    /// interface 0 owns `LOCAL_ADDR`, interface 1 owns `LOCAL2_ADDR`.
    #[cfg(feature = "iface-bind")]
    fn stack_with_two_ifaces() -> (
        Stack<'static>,
        IfaceHandle,
        IfaceHandle,
        crate::test_device::Sent,
        crate::test_device::Sent,
    ) {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let d0 = TestDevice::new(Medium::Ip);
        let tx0 = d0.tx.clone();
        let if0 = d0.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(if0)
            .add_ip_addr(IpCidr::new(LOCAL_ADDR.into(), 24))
            .unwrap();
        let d1 = TestDevice::new(Medium::Ip);
        let tx1 = d1.tx.clone();
        let if1 = d1.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(if1)
            .add_ip_addr(IpCidr::new(LOCAL2_ADDR.into(), 24))
            .unwrap();
        (stack, if0, if1, tx0, tx1)
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface() {
        let (mut stack, handle) = stack_with_socket();
        let iface = IfaceHandle::new(0);
        let mut socket = stack.udp_socket(handle);
        assert_eq!(socket.bound_iface(), None);
        socket.bind_to_iface(Some(iface)).unwrap();
        assert_eq!(socket.bound_iface(), Some(iface));

        // The binding cannot change while the socket is open, and is kept
        // across close.
        socket.bind(LOCAL_PORT, ANY).unwrap();
        assert_eq!(socket.bind_to_iface(None), Err(BindError::InvalidState));
        socket.close();
        assert_eq!(socket.bound_iface(), Some(iface));
        socket.bind_to_iface(None).unwrap();
        assert_eq!(socket.bound_iface(), None);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_demux() {
        let (mut stack, if0, if1, _, _) = stack_with_two_ifaces();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind_to_iface(Some(if1)).unwrap();
        stack.udp_socket(handle).bind(LOCAL_PORT, ANY).unwrap();

        // Arrives on the wrong interface: not delivered.
        deliver_on(&mut stack, if0, REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, b"no");
        assert!(!stack.udp_socket(handle).can_recv());

        // On the bound interface: delivered.
        deliver_on(&mut stack, if1, REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, b"yes");
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"yes");
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_demux_scoring() {
        // A socket bound to the arrival interface wins over an unbound one with
        // an equal tuple. Traffic on other interfaces goes to the unbound one.
        let (mut stack, if0, if1, _, _) = stack_with_two_ifaces();
        let h_any = stack.add_udp_socket().unwrap();
        let h_bound = stack.add_udp_socket().unwrap();
        stack.udp_socket(h_any).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp_socket(h_bound).bind_to_iface(Some(if0)).unwrap();
        stack.udp_socket(h_bound).bind(LOCAL_PORT, ANY).unwrap();

        deliver_on(&mut stack, if0, REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, b"bound");
        assert_eq!(&*stack.udp_socket(h_bound).recv().unwrap(), b"bound");
        assert!(!stack.udp_socket(h_any).can_recv());

        deliver_on(&mut stack, if1, REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, b"any");
        assert_eq!(&*stack.udp_socket(h_any).recv().unwrap(), b"any");
        assert!(!stack.udp_socket(h_bound).can_recv());
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_conflicts() {
        // The binding is part of the socket's identity: identical tuples bound
        // to different interfaces (or one bound, one not) coexist. Only the
        // identical tuple with the identical binding conflicts.
        let (mut stack, if0, if1, _, _) = stack_with_two_ifaces();
        let h1 = stack.add_udp_socket().unwrap();
        let h2 = stack.add_udp_socket().unwrap();
        let h3 = stack.add_udp_socket().unwrap();

        stack.udp_socket(h1).bind_to_iface(Some(if0)).unwrap();
        stack.udp_socket(h1).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp_socket(h2).bind_to_iface(Some(if1)).unwrap();
        stack.udp_socket(h2).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp_socket(h3).bind(LOCAL_PORT, ANY).unwrap();

        stack.udp_socket(h3).close();
        stack.udp_socket(h3).bind_to_iface(Some(if0)).unwrap();
        assert_eq!(stack.udp_socket(h3).bind(LOCAL_PORT, ANY), Err(BindError::InUse));
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_send() {
        let (mut stack, _, if1, tx0, tx1) = stack_with_two_ifaces();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind_to_iface(Some(if1)).unwrap();
        stack.udp_socket(handle).bind(LOCAL_PORT, ANY).unwrap();

        // The destination is on-link for interface 0 only: a socket bound to
        // interface 1 has no route to it.
        assert_eq!(
            stack.udp_socket(handle).send_slice(b"hi", (REMOTE_ADDR, REMOTE_PORT)),
            Err(SendError::Unaddressable)
        );

        // A destination on the bound interface's subnet goes out of it.
        stack
            .udp_socket(handle)
            .send_slice(b"hi", (REMOTE2_ADDR, REMOTE_PORT))
            .unwrap();
        assert!(tx0.borrow().is_empty());
        assert_eq!(tx1.borrow().len(), 1);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_send_broadcast() {
        // Broadcast carries no routing information. Unbound it goes out the
        // first interface; bound, out the bound one.
        let (mut stack, _, if1, tx0, tx1) = stack_with_two_ifaces();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind_to_iface(Some(if1)).unwrap();
        stack.udp_socket(handle).bind(LOCAL_PORT, ANY).unwrap();

        stack
            .udp_socket(handle)
            .send_slice(b"hi", (Ipv4Address::BROADCAST, REMOTE_PORT))
            .unwrap();
        assert!(tx0.borrow().is_empty());
        assert_eq!(tx1.borrow().len(), 1);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_resolves_source() {
        // A bind with a fully-specified remote resolves its wildcard local
        // address from the bound interface.
        let (mut stack, _, if1, _, _) = stack_with_two_ifaces();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind_to_iface(Some(if1)).unwrap();
        stack.udp_socket(handle).bind(0, (REMOTE2_ADDR, REMOTE_PORT)).unwrap();
        assert_eq!(stack.udp_socket(handle).local_endpoint().addr, Some(LOCAL2_ADDR.into()));

        // A remote only reachable through another interface does not resolve.
        stack.udp_socket(handle).close();
        assert_eq!(
            stack.udp_socket(handle).bind(0, (REMOTE_ADDR, REMOTE_PORT)),
            Err(BindError::Unaddressable)
        );
    }
}
