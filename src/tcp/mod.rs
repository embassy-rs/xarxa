//! TCP sockets.

// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP, as well as RFC 7323 for some of the TCP options.
// Consult RFC 7414 when implementing a new feature.

use core::fmt::Display;
use core::{fmt, mem};

#[cfg(all(test, feature = "tcp-listener"))]
use crate::config::TCP_LISTENER_BACKLOG;
use crate::config::TCP_SOCKET_COUNT;
use crate::driver::ChecksumCapabilities;
use crate::driver::PacketBuf;
#[cfg(feature = "icmp-errors")]
use crate::icmp_error::IcmpError;
use crate::iface::IfaceHandle;
use crate::rand::Rand;
use crate::stack::{EgressRoute, IfaceBinding, Stack, TxContext, alloc_ephemeral_port};
use crate::storage::Slab;
use crate::time::{Duration, Instant};
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
#[cfg(feature = "ipv4")]
use crate::wire::IPV4_HEADER_LEN;
#[cfg(feature = "ipv6")]
use crate::wire::IPV6_HEADER_LEN;
use crate::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, LINK_HEADER_LEN, TCP_HEADER_LEN, TcpControl, TcpPacket,
    TcpSeqNumber,
};

mod congestion;
#[cfg(feature = "tcp-listener")]
mod listener;
mod repr;
mod ring_buffer;

use self::congestion::Controller as _;
#[cfg(feature = "tcp-listener")]
pub use self::listener::{TcpListener, TcpListenerHandle, TcpListenerIter};
#[cfg(feature = "tcp-listener")]
pub(crate) use self::listener::{TcpListenerState, process_listeners};
pub(crate) use self::repr::TcpRepr;
#[cfg(feature = "tcp-timestamps")]
pub(crate) use self::repr::TcpTimestampRepr;
use self::ring_buffer::RingBuffer;
use crate::storage::Assembler;

/// The IP MTU assumed for TCP segment sizing until the destination has been
/// routed.
///
/// Every `dispatch` refreshes the socket's `ip_mtu` from the routed egress interface
/// before sizing or sending anything, so this only stands in while there is no route.
const DEFAULT_IP_MTU: usize = 1500;

define_handle! {
    /// A handle to a TCP socket added to a [`Stack`].
    ///
    /// [`Stack`]: crate::Stack
    TcpHandle(crate::config::tcp_index)
}

/// Error returned by [`TcpListener::listen`]
///
/// Requires the `tcp-listener` feature.
#[cfg(feature = "tcp-listener")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ListenError {
    InvalidState,
    Unaddressable,
    /// Another TCP listener is bound to the identical endpoint.
    InUse,
}

#[cfg(feature = "tcp-listener")]
impl Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenError::InvalidState => write!(f, "invalid state"),
            ListenError::Unaddressable => write!(f, "unaddressable destination"),
            ListenError::InUse => write!(f, "port in use"),
        }
    }
}

#[cfg(feature = "tcp-listener")]
impl core::error::Error for ListenError {}

/// Error returned by [`TcpListener::accept_with_socket`]
///
/// Requires the `tcp-listener` feature.
#[cfg(feature = "tcp-listener")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AcceptError {
    /// The socket is still open, so it can't be reused for a new connection.
    InvalidState,
    /// The accept queue is empty.
    Exhausted,
}

#[cfg(feature = "tcp-listener")]
impl Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AcceptError::InvalidState => write!(f, "invalid state"),
            AcceptError::Exhausted => write!(f, "exhausted"),
        }
    }
}

#[cfg(feature = "tcp-listener")]
impl core::error::Error for AcceptError {}

/// Error returned by [`TcpSocket::connect`]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectError {
    InvalidState,
    Unaddressable,
    /// No free port in the ephemeral range (only possible with tens of thousands
    /// of open sockets).
    NoFreePorts,
    /// Another TCP socket already holds the identical 4-tuple.
    InUse,
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectError::InvalidState => write!(f, "invalid state"),
            ConnectError::Unaddressable => write!(f, "unaddressable destination"),
            ConnectError::NoFreePorts => write!(f, "no free ports"),
            ConnectError::InUse => write!(f, "4-tuple in use"),
        }
    }
}

impl core::error::Error for ConnectError {}

/// Error returned by [`TcpSocket::send`]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    InvalidState,
}

impl Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SendError::InvalidState => write!(f, "invalid state"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`TcpSocket::recv`]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    InvalidState,
    Finished,
}

impl Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Finished => write!(f, "operation finished"),
        }
    }
}

impl core::error::Error for RecvError {}

/// A TCP socket ring buffer.
pub(crate) type SocketBuffer<'d> = RingBuffer<'d, u8>;

/// The state of a TCP socket, according to [RFC 793].
///
/// There is no `LISTEN` state: a `TcpSocket` only ever represents a single
/// connection (its 4-tuple is fully set from the start).
#[cfg_attr(
    feature = "tcp-listener",
    doc = "",
    doc = "Passive open is the job of [`TcpListener`]."
)]
///
/// [RFC 793]: https://tools.ietf.org/html/rfc793
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Closed => write!(f, "CLOSED"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::Closing => write!(f, "CLOSING"),
            State::LastAck => write!(f, "LAST-ACK"),
            State::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

/// RFC 6298: (2.1) Until a round-trip time (RTT) measurement has been made for a
/// segment sent between the sender and receiver, the sender SHOULD
/// set RTO <- 1 second,
const RTTE_INITIAL_RTO: u32 = 1000;

// Minimum "safety margin" for the RTO that kicks in when the
// variance gets very low.
const RTTE_MIN_MARGIN: u32 = 5;

/// K, according to RFC 6298
const RTTE_K: u32 = 4;

// RFC 6298 (2.4): Whenever RTO is computed, if it is less than 1 second, then the
// RTO SHOULD be rounded up to 1 second.
const RTTE_MIN_RTO: u32 = 1000;

// RFC 6298 (2.5) A maximum value MAY be placed on RTO provided it is at least 60
// seconds
const RTTE_MAX_RTO: u32 = 60_000;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
struct RttEstimator {
    /// true if we have made at least one rtt measurement.
    have_measurement: bool,
    // Using u32 instead of Duration to save space (Duration is i64)
    /// Smoothed RTT
    srtt: u32,
    /// RTT variance.
    rttvar: u32,
    /// Retransmission Time-Out
    rto: u32,
    timestamp: Option<(Instant, TcpSeqNumber)>,
    max_seq_sent: Option<TcpSeqNumber>,
    rto_count: u8,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            have_measurement: false,
            srtt: 0,   // ignored, will be overwritten on first measurement.
            rttvar: 0, // ignored, will be overwritten on first measurement.
            rto: RTTE_INITIAL_RTO,
            timestamp: None,
            max_seq_sent: None,
            rto_count: 0,
        }
    }
}

impl RttEstimator {
    fn retransmission_timeout(&self) -> Duration {
        Duration::from_millis(self.rto as _)
    }

    #[cfg(feature = "tcp-cubic")]
    fn smoothed_rtt(&self) -> u32 {
        if self.have_measurement { self.srtt } else { 0 }
    }

    fn sample(&mut self, new_rtt: u32) {
        if self.have_measurement {
            // RFC 6298 (2.3) When a subsequent RTT measurement R' is made, a host MUST set (...)
            let diff = (self.srtt as i32 - new_rtt as i32).unsigned_abs();
            self.rttvar = (self.rttvar * 3 + diff).div_ceil(4);
            self.srtt = (self.srtt * 7 + new_rtt).div_ceil(8);
        } else {
            // RFC 6298 (2.2) When the first RTT measurement R is made, the host MUST set (...)
            self.have_measurement = true;
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        }

        // RFC 6298 (2.2), (2.3)
        let margin = RTTE_MIN_MARGIN.max(self.rttvar * RTTE_K);
        self.rto = (self.srtt + margin).clamp(RTTE_MIN_RTO, RTTE_MAX_RTO);

        self.rto_count = 0;

        trace!(
            "rtte: sample={:?} srtt={:?} rttvar={:?} rto={:?}",
            new_rtt, self.srtt, self.rttvar, self.rto
        );
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self.max_seq_sent.map(|max_seq_sent| seq > max_seq_sent).unwrap_or(true) {
            self.max_seq_sent = Some(seq);
            if self.timestamp.is_none() {
                self.timestamp = Some((timestamp, seq));
                trace!("rtte: sampling at seq={:?}", seq);
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if let Some((sent_timestamp, sent_seq)) = self.timestamp
            && seq >= sent_seq
        {
            self.sample((timestamp - sent_timestamp).total_millis() as u32);
            self.timestamp = None;
        }
    }

    fn on_rto(&mut self) {
        // RFC 6298 (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        self.rto = (self.rto * 2).min(RTTE_MAX_RTO);
        trace!("rtte: doubling rto to {:?}", self.rto);

        // RFC 6298: a TCP implementation MAY clear SRTT and RTTVAR after
        // backing off the timer multiple times as it is likely that the current
        // SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
        // are cleared, they should be initialized with the next RTT sample
        // taken per (2.2) rather than using (2.3).
        self.rto_count += 1;
        if self.rto_count >= 3 {
            self.rto_count = 0;
            self.have_measurement = false;
            trace!("rtte: too many retransmissions, clearing srtt, rttvar.");
        }
    }

    fn on_retransmit(&mut self) {
        if self.timestamp.is_some() {
            trace!("rtte: abort sampling due to retransmit");
        }
        self.timestamp = None;
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Timer {
    Idle { keep_alive_at: Option<Instant> },
    Retransmit { expires_at: Instant },
    FastRetransmit,
    ZeroWindowProbe { expires_at: Instant, delay: Duration },
    Close { expires_at: Instant },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

impl Timer {
    fn new() -> Timer {
        Timer::Idle { keep_alive_at: None }
    }

    fn should_keep_alive(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } if timestamp >= keep_alive_at => true,
            _ => false,
        }
    }

    fn should_retransmit(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Retransmit { expires_at } if timestamp >= expires_at => true,
            Timer::FastRetransmit => true,
            _ => false,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn should_zero_window_probe(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::ZeroWindowProbe { expires_at, .. } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> Instant {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } => keep_alive_at,
            Timer::Idle { keep_alive_at: None } => Instant::MAX,
            Timer::ZeroWindowProbe { expires_at, .. } => expires_at,
            Timer::Retransmit { expires_at, .. } => expires_at,
            Timer::FastRetransmit => Instant::MIN,
            Timer::Close { expires_at } => expires_at,
        }
    }

    fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval),
        }
    }

    fn set_keep_alive(&mut self) {
        if let Timer::Idle { keep_alive_at } = self
            && keep_alive_at.is_none()
        {
            *keep_alive_at = Some(Instant::from_millis(0))
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
        if let Timer::Idle { keep_alive_at } = self {
            *keep_alive_at = interval.map(|interval| timestamp + interval)
        }
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. } | Timer::FastRetransmit | Timer::Retransmit { .. } | Timer::ZeroWindowProbe { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                }
            }
            Timer::Close { .. } => (),
        }
    }

    fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY,
        }
    }

    fn set_for_zero_window_probe(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::ZeroWindowProbe {
            expires_at: timestamp + delay,
            delay,
        }
    }

    fn rewind_zero_window_probe(&mut self, timestamp: Instant) {
        if let Timer::ZeroWindowProbe { mut delay, .. } = *self {
            delay = (delay * 2).min(Duration::from_millis(RTTE_MAX_RTO as _));
            *self = Timer::ZeroWindowProbe {
                expires_at: timestamp + delay,
                delay,
            }
        }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Timer::Idle { .. })
    }

    fn is_zero_window_probe(&self) -> bool {
        matches!(self, Timer::ZeroWindowProbe { .. })
    }

    fn is_retransmit(&self) -> bool {
        matches!(self, Timer::Retransmit { .. } | Timer::FastRetransmit)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Tuple {
    local: IpEndpoint,
    remote: IpEndpoint,
}

impl Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.local, self.remote)
    }
}

/// The state of a TCP socket, stored in the stack's socket slab. The public API
/// lives on [`TcpSocket`], the view of one of these borrowed from the stack.
#[derive(Debug)]
pub(crate) struct TcpSocketState<'d> {
    state: State,
    timer: Timer,
    rtte: RttEstimator,
    assembler: Assembler,
    rx_buffer: SocketBuffer<'d>,
    rx_fin_received: bool,
    tx_buffer: SocketBuffer<'d>,
    /// Interval after which, if no inbound packets are received, the connection is aborted.
    timeout: Option<Duration>,
    /// Interval at which keep-alive packets will be sent.
    keep_alive: Option<Duration>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    /// Current 4-tuple (local and remote endpoints).
    tuple: Option<Tuple>,
    /// The interface the socket is bound to. Zero-sized without `iface-bind`.
    /// User configuration, kept across `reset` like the hop limit.
    binding: IfaceBinding,
    /// The last ICMP error reported against this connection. A single slot: a
    /// newer error overwrites an unread older one.
    #[cfg(feature = "icmp-errors")]
    icmp_error: Option<IcmpError>,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no: TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no: TcpSeqNumber,
    /// The last sequence number sent.
    /// I.e. in an idle socket, local_seq_no+tx_buffer.len().
    remote_last_seq: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx_buffer.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last window length sent.
    remote_last_win: u16,
    /// The sending window scaling factor advertised to remotes which support RFC 1323.
    /// It is zero if the window <= 64KiB and/or the remote does not support it.
    remote_win_shift: u8,
    /// The remote window size, relative to local_seq_no
    /// I.e. we're allowed to send octets until local_seq_no+remote_win_len
    remote_win_len: usize,
    /// The receive window scaling factor for remotes which support RFC 1323, None if unsupported.
    remote_win_scale: Option<u8>,
    /// Whether or not the remote supports selective ACK as described in RFC 2018.
    #[cfg(feature = "tcp-sack")]
    remote_has_sack: bool,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss: usize,
    /// The IP MTU of the interface this connection's packets go out of, as of the
    /// last `dispatch` that routed the destination. Feeds the local MSS: cached
    /// here because the send decision (`seq_to_transmit`) is also made from
    /// `poll_at`, which has no access to the stack's routing state.
    ip_mtu: usize,
    /// The timestamp of the last packet received.
    remote_last_ts: Option<Instant>,
    /// The sequence number of the last packet received, used for sACK
    #[cfg(feature = "tcp-sack")]
    local_rx_last_seq: Option<TcpSeqNumber>,
    /// The ACK number of the last packet received.
    local_rx_last_ack: Option<TcpSeqNumber>,
    /// The number of packets received directly after
    /// each other which have the same ACK number.
    local_rx_dup_acks: u8,
    /// If a fast retransmit needs to occur
    pending_fast_retransmit: bool,

    /// Duration for Delayed ACK. If None no ACKs will be delayed.
    ack_delay: Option<Duration>,
    /// Delayed ack timer. If set, packets containing exclusively
    /// ACK or window updates (ie, no data) won't be sent until expiry.
    ack_delay_timer: AckDelayTimer,

    /// Used for rate-limiting: No more challenge ACKs will be sent until this instant.
    challenge_ack_timer: Instant,

    /// Nagle's Algorithm enabled.
    nagle: bool,

    /// The last three SACK ranges that were sent to the remote.
    #[cfg(feature = "tcp-sack")]
    local_sack_history: [Option<(TcpSeqNumber, TcpSeqNumber)>; 3],

    /// The congestion control algorithm.
    congestion_controller: congestion::Congestion,

    /// Whether the TCP timestamp option (RFC 7323) is in use on this connection.
    /// We offer it in the SYN of every connection we open, and answer with it if
    /// the peer offered it; it stays on only if both ends did.
    #[cfg(feature = "tcp-timestamps")]
    timestamps: bool,

    /// The last tsval received from the peer, echoed back as tsecr in every
    /// segment we send. Zero until the first segment carrying a timestamp.
    #[cfg(feature = "tcp-timestamps")]
    last_remote_tsval: u32,

    /// Random offset added to every tsval this connection sends.
    /// - Avoids leaking system uptime
    /// - Prevents correlating connections for hosts behind NAT.
    #[cfg(feature = "tcp-timestamps")]
    tsval_offset: u32,

    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

const DEFAULT_MSS: usize = 536;

/// Minimum MSS we accept from the remote, same value as Linux's `TCP_MIN_SND_MSS`.
/// Without it, a peer advertising a tiny MSS could force segments to carry little
/// or no payload once the TCP options length is subtracted from the effective MSS,
/// stalling the connection in an endless stream of empty segments.
const MIN_REMOTE_MSS: usize = 48;

impl<'d> TcpSocketState<'d> {
    #[allow(unused_comparisons)] // small usize platforms always pass rx_capacity check
    /// Create a socket using the given buffers.
    pub(crate) fn new(rx_buffer: SocketBuffer<'d>, tx_buffer: SocketBuffer<'d>) -> TcpSocketState<'d> {
        let rx_capacity = rx_buffer.capacity();

        // From RFC 1323:
        // [...] the above constraints imply that 2 * the max window size must be less
        // than 2**31 [...] Thus, the shift count must be limited to 14 (which allows
        // windows of 2**30 = 1 Gbyte).
        #[cfg(not(target_pointer_width = "16"))] // Prevent overflow
        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - rx_capacity.leading_zeros() as usize;

        TcpSocketState {
            state: State::Closed,
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            assembler: Assembler::new(),
            tx_buffer,
            rx_buffer,
            rx_fin_received: false,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            tuple: None,
            binding: IfaceBinding::Any,
            #[cfg(feature = "icmp-errors")]
            icmp_error: None,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win: 0,
            remote_win_len: 0,
            remote_win_shift: rx_cap_log2.saturating_sub(16) as u8,
            remote_win_scale: None,
            #[cfg(feature = "tcp-sack")]
            remote_has_sack: false,
            remote_mss: DEFAULT_MSS,
            ip_mtu: DEFAULT_IP_MTU,
            remote_last_ts: None,
            local_rx_last_ack: None,
            #[cfg(feature = "tcp-sack")]
            local_rx_last_seq: None,
            local_rx_dup_acks: 0,
            pending_fast_retransmit: false,
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            nagle: true,
            #[cfg(feature = "tcp-sack")]
            local_sack_history: [None, None, None],
            #[cfg(feature = "tcp-timestamps")]
            timestamps: false,
            #[cfg(feature = "tcp-timestamps")]
            last_remote_tsval: 0,
            #[cfg(feature = "tcp-timestamps")]
            tsval_offset: 0,
            congestion_controller: congestion::Congestion::new(),
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    #[inline]
    fn scaled_window(&self) -> u16 {
        u16::try_from(self.rx_buffer.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
    }

    /// Return the last window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    ///
    /// Unlike `remote_last_win`, we take into account new packets received (but not acknowledged)
    /// since the last window update and adjust the window length accordingly. This ensures a fair
    /// comparison between the last window length and the new window length we're going to
    /// advertise.
    #[inline]
    fn last_scaled_window(&self) -> Option<u16> {
        let last_ack = self.remote_last_ack?;
        let next_ack = self.remote_seq_no + self.rx_buffer.len();

        let last_win = (self.remote_last_win as usize) << self.remote_win_shift;
        let last_win_adjusted = last_ack + last_win - next_ack;

        Some(u16::try_from(last_win_adjusted >> self.remote_win_shift).unwrap_or(u16::MAX))
    }

    /// Whether the socket is open: it processes incoming and dispatches
    /// outgoing packets. `false` means it can be reused for a new connection.
    fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true,
        }
    }

    /// Return the socket to the closed state, ready to be reused by `connect`
    /// or `TcpListener::accept_with_socket`. Everything the user configured
    /// (hop limit, timeout, keep-alive, Nagle, ACK delay) is kept; everything
    /// belonging to the connection is cleared.
    fn reset(&mut self) {
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - self.rx_buffer.capacity().leading_zeros() as usize;

        self.state = State::Closed;
        self.timer = Timer::new();
        self.rtte = RttEstimator::default();
        self.assembler = Assembler::new();
        self.tx_buffer.clear();
        self.rx_buffer.clear();
        self.rx_fin_received = false;
        self.tuple = None;
        #[cfg(feature = "icmp-errors")]
        {
            self.icmp_error = None;
        }
        self.local_seq_no = TcpSeqNumber::default();
        #[cfg(feature = "tcp-sack")]
        {
            self.local_rx_last_seq = None;
        }
        self.local_rx_last_ack = None;
        self.local_rx_dup_acks = 0;
        self.pending_fast_retransmit = false;
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win = 0;
        self.remote_win_len = 0;
        self.remote_win_scale = None;
        #[cfg(feature = "tcp-sack")]
        {
            self.remote_has_sack = false;
        }
        self.remote_win_shift = rx_cap_log2.saturating_sub(16) as u8;
        self.remote_mss = DEFAULT_MSS;
        self.ip_mtu = DEFAULT_IP_MTU;
        self.remote_last_ts = None;
        #[cfg(feature = "tcp-timestamps")]
        {
            self.last_remote_tsval = 0;
        }
        self.ack_delay_timer = AckDelayTimer::Idle;
        self.challenge_ack_timer = Instant::from_secs(0);
        self.congestion_controller = congestion::Congestion::new();
        #[cfg(feature = "tcp-sack")]
        {
            self.local_sack_history = [None, None, None];
        }

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    #[cfg(test)]
    fn random_seq_no(_rand: &mut Rand) -> TcpSeqNumber {
        TcpSeqNumber(10000)
    }

    #[cfg(not(test))]
    fn random_seq_no(rand: &mut Rand) -> TcpSeqNumber {
        TcpSeqNumber(rand.rand_u32() as i32)
    }

    #[cfg(all(test, feature = "tcp-timestamps"))]
    fn random_tsval_offset(_rand: &mut Rand) -> u32 {
        0
    }

    #[cfg(all(not(test), feature = "tcp-timestamps"))]
    fn random_tsval_offset(rand: &mut Rand) -> u32 {
        rand.rand_u32()
    }

    /// Number of octets transmitted but not yet ACKed.
    fn flight_size(&self) -> usize {
        self.remote_last_seq - self.local_seq_no
    }

    fn cwnd_remaining(&self) -> usize {
        self.congestion_controller.window().saturating_sub(self.flight_size())
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            trace!("state={}=>{}", self.state, state);
        }

        self.state = state;

        #[cfg(feature = "async")]
        {
            // Wake all tasks waiting. Even if we haven't received/sent data, this
            // is needed because return values of functions may change depending on the state.
            // For example, a pending read has to fail with an error if the socket is closed.
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    fn reply(repr: &TcpRepr) -> TcpRepr<'static> {
        TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            #[cfg(feature = "tcp-sack")]
            sack_permitted: false,
            #[cfg(feature = "tcp-sack")]
            sack_ranges: [None, None, None],
            #[cfg(feature = "tcp-timestamps")]
            timestamp: None,
            payload: &[],
            payload2: &[],
        }
    }

    pub(crate) fn rst_reply(repr: &TcpRepr) -> TcpRepr<'static> {
        debug_assert!(repr.control != TcpControl::Rst);

        let mut reply_repr = Self::reply(repr);

        // See https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for explanation
        // of why we sometimes send an RST and sometimes an RST|ACK
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        reply_repr
    }

    /// The timestamp option to put on an outgoing segment, echoing `tsecr`.
    ///
    /// `None` if timestamps are not in use on this connection. The tsval is the
    /// poll clock in milliseconds, offset by this connection's random value:
    /// monotonic, and at the granularity RFC 7323 asks for.
    #[cfg(feature = "tcp-timestamps")]
    fn timestamp_repr(&self, now: Instant, tsecr: u32) -> Option<TcpTimestampRepr> {
        self.timestamps.then(|| {
            let tsval = (now.total_millis() as u32).wrapping_add(self.tsval_offset);
            TcpTimestampRepr::new(tsval, tsecr)
        })
    }

    fn ack_reply(&mut self, _now: Instant, repr: &TcpRepr) -> TcpRepr<'static> {
        let mut reply_repr = Self::reply(repr);
        // Echo the incoming tsval, if the segment we are replying to carried one.
        #[cfg(feature = "tcp-timestamps")]
        {
            reply_repr.timestamp = repr
                .timestamp
                .and_then(|tcp_ts| self.timestamp_repr(_now, tcp_ts.tsval));
        }

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.remote_last_seq;
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
        self.remote_last_ack = reply_repr.ack_number;

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();
        self.remote_last_win = reply_repr.window_len;

        // If the remote supports selective acknowledgement, add the option to the outgoing
        // segment.
        #[cfg(feature = "tcp-sack")]
        if self.remote_has_sack {
            // NOTE(unwrap): ack_number is set to Some above.
            let ack = reply_repr.ack_number.unwrap();
            reply_repr.sack_ranges = self.generate_sack_ranges(ack);
        }

        reply_repr
    }

    fn challenge_ack_reply(&mut self, now: Instant, repr: &TcpRepr) -> Option<TcpRepr<'static>> {
        if now < self.challenge_ack_timer {
            return None;
        }

        // Rate-limit to 1 per second max.
        self.challenge_ack_timer = now + Duration::from_secs(1);

        Some(self.ack_reply(now, repr))
    }

    /// Whether a segment arriving on `arrival` passes the socket's interface
    /// binding. Checked by ingress demux alongside [`accepts`](Self::accepts).
    pub(crate) fn binding_matches(&self, arrival: IfaceHandle) -> bool {
        self.binding.matches(arrival)
    }

    pub(crate) fn accepts(&self, src_addr: &IpAddress, dst_addr: &IpAddress, repr: &TcpRepr) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // Reject packets not matching the 4-tuple.
        let Some(tuple) = &self.tuple else {
            return false;
        };
        *dst_addr == tuple.local.addr
            && repr.dst_port == tuple.local.port
            && *src_addr == tuple.remote.addr
            && repr.src_port == tuple.remote.port
    }

    /// Process an ICMP error message reported against this connection.
    ///
    /// `seq` is the sequence number of the quoted (erring) segment. It must fall
    /// within the send window, so blindly spoofed errors cannot affect the
    /// connection (RFC 5927).
    ///
    /// During the handshake (SYN-SENT / SYN-RECEIVED) any error aborts the
    /// connection, which makes a connect to an unreachable destination fail fast
    /// instead of running out the SYN retransmission timer. On a
    /// synchronized connection every error is treated as soft and advisory (as
    /// RFC 5927 recommends, to resist off-path connection-reset attacks): it is
    /// recorded for [`take_icmp_error`](TcpSocket::take_icmp_error) and the
    /// connection carries on.
    #[cfg(feature = "icmp-errors")]
    pub(crate) fn process_icmp_error(&mut self, error: IcmpError, seq: TcpSeqNumber) {
        // The quoted segment must be one we actually have in flight.
        if seq < self.local_seq_no || seq > self.remote_last_seq {
            trace!("icmp error quoting out-of-window seq, ignoring");
            return;
        }
        self.icmp_error = Some(error);
        match self.state {
            State::SynSent | State::SynReceived => {
                debug!("{} during handshake, aborting connection", error);
                self.set_state(State::Closed);
                self.tuple = None;
            }
            _ => {
                trace!("icmp error {}, recorded as soft error", error);
            }
        }
    }

    pub(crate) fn process(
        &mut self,
        now: Instant,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        repr: &TcpRepr,
    ) -> Option<TcpRepr<'static>> {
        debug_assert!(self.accepts(src_addr, dst_addr, repr));
        // Ingress reprs come from `parse`, which never splits the payload.
        debug_assert!(repr.payload2.is_empty());

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state {
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgements for
            // all of the control flags we sent.
            _ => (false, false),
        };
        let control_len = (sent_syn as usize) + (sent_fin as usize);

        // Reject unacceptable acknowledgements.
        match (self.state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                debug!("unacceptable RST (expecting RST|ACK) in response to initial SYN");
                return None;
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    debug!("unacceptable RST|ACK in response to initial SYN");
                    return None;
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpControl::Rst, _) => (),
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    debug!("unacceptable SYN|ACK in response to initial SYN");
                    return Some(Self::rst_reply(repr));
                }
            }
            // TCP simultaneous open.
            // This is required by RFC 9293, which states "A TCP implementation MUST support
            // simultaneous open attempts (MUST-10)."
            (State::SynSent, TcpControl::Syn, None) => (),
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // If the sequence number matches, ignore it instead of RSTing.
                // I'm not sure why, I think it may be a workaround for broken TCP
                // servers, or a defense against reordering. Either way, if Linux
                // does it, we do too.
                if ack_number == self.local_seq_no + 1 {
                    debug!("expecting a SYN|ACK, received an ACK with the right ack_number, ignoring.");
                    return None;
                }

                debug!("expecting a SYN|ACK, received an ACK with the wrong ack_number, sending RST.");
                return Some(Self::rst_reply(repr));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                debug!("expecting a SYN|ACK");
                return None;
            }
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                debug!("expecting an ACK");
                return None;
            }
            // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
            (State::SynReceived, _, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    debug!("unacceptable ACK in response to SYN|ACK");
                    return Some(Self::rst_reply(repr));
                }
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, _, Some(ack_number)) => {
                let unacknowledged = self.tx_buffer.len() + control_len;

                // Acceptable ACK range (both inclusive)
                let mut ack_min = self.local_seq_no;
                let ack_max = self.local_seq_no + unacknowledged;

                // If we have sent a SYN, it MUST be acknowledged.
                if sent_syn {
                    ack_min += 1;
                }

                if ack_number < ack_min {
                    debug!("duplicate ACK ({} not in {}...{})", ack_number, ack_min, ack_max);
                    return None;
                }

                if ack_number > ack_max {
                    debug!("unacceptable ACK ({} not in {}...{})", ack_number, ack_min, ack_max);
                    return self.challenge_ack_reply(now, repr);
                }
            }
        }

        let window_start = self.remote_seq_no + self.rx_buffer.len();
        let window_end = if let Some(last_ack) = self.remote_last_ack {
            last_ack + ((self.remote_last_win as usize) << self.remote_win_shift)
        } else {
            window_start
        };
        let segment_start = repr.seq_number;
        let segment_end = repr.seq_number + repr.payload.len();

        let (payload, payload_offset) = match self.state {
            // In the SYN-SENT state, we have not yet synchronized with the remote end.
            State::SynSent => (&[][..], 0),
            _ => {
                // https://www.rfc-editor.org/rfc/rfc9293.html#name-segment-acceptability-tests
                let segment_in_window = match (segment_start == segment_end, window_start == window_end) {
                    (true, _) if segment_end == window_start - 1 => {
                        debug!("received a keep-alive or window probe packet, will send an ACK");
                        false
                    }
                    (true, true) => {
                        if window_start == segment_start {
                            true
                        } else {
                            debug!("zero-length segment not inside zero-length window, will send an ACK.");
                            false
                        }
                    }
                    (true, false) => {
                        if window_start <= segment_start && segment_start < window_end {
                            true
                        } else {
                            debug!("zero-length segment not inside window, will send an ACK.");
                            false
                        }
                    }
                    (false, true) => {
                        debug!("non-zero-length segment with zero receive window, will only send an ACK");
                        false
                    }
                    (false, false) => {
                        if (window_start <= segment_start && segment_start < window_end)
                            || (window_start < segment_end && segment_end <= window_end)
                        {
                            true
                        } else {
                            debug!(
                                "segment not in receive window ({}..{} not intersecting {}..{}), will send challenge ACK",
                                segment_start, segment_end, window_start, window_end
                            );
                            false
                        }
                    }
                };

                if segment_in_window {
                    let overlap_start = window_start.max(segment_start);
                    let overlap_end = window_end.min(segment_end);

                    // the checks done above imply this.
                    debug_assert!(overlap_start <= overlap_end);

                    (
                        &repr.payload[overlap_start - segment_start..overlap_end - segment_start],
                        overlap_start - window_start,
                    )
                } else {
                    // Out-of-window RSTs are silently dropped, per RFC 9293
                    // (3.10.7.4) and RFC 5961 (3.2): no reply is sent, and the
                    // TIME-WAIT timer below is not refreshed. RST senders don't
                    // need a reply to make progress.
                    if repr.control == TcpControl::Rst {
                        debug!("dropping out-of-window RST");
                        return None;
                    }

                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not have realized we've closed the connection.
                    if self.state == State::TimeWait {
                        self.timer.set_for_close(now);
                    }

                    // Segments carrying data are exempt from challenge ACK rate
                    // limiting: an out-of-window data segment is a retransmission
                    // whose ACK was lost, or a window probe, and per RFC 9293
                    // (3.10.7.4, 3.8.6.1) it should elicit an ACK so the remote
                    // can make progress. Withholding these ACKs strands the
                    // remote in retransmission backoff or persist state. The
                    // rate limit exists to break ACK loops between desynced
                    // peers, and exempting data segments cannot sustain such a
                    // loop: the remote paces them with its retransmission and
                    // persist timers, and the data it may send in response to a
                    // duplicate ACK of ours (fast recovery) is bounded by its
                    // send window, which never advances during a desync.
                    //
                    // The exemption covers FIN (a retransmitted final segment is
                    // the same lost-ACK situation) but not SYN: a SYN in a
                    // synchronized state is a challenge ACK situation (RFC 5961
                    // 4.2), and challenge ACKs should be throttled (RFC 5961 7).
                    // One per second is ample for a restarted peer to complete
                    // the challenge exchange, since it retransmits its SYN on
                    // its own timer.
                    if !repr.payload.is_empty()
                        && matches!(repr.control, TcpControl::None | TcpControl::Psh | TcpControl::Fin)
                    {
                        return Some(self.ack_reply(now, repr));
                    }

                    return self.challenge_ack_reply(now, repr);
                }
            }
        };

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        let mut ack_all = false;
        if repr.control != TcpControl::Rst
            && let Some(ack_number) = repr.ack_number
        {
            // Sequence number corresponding to the first byte in `tx_buffer`.
            // This normally equals `local_seq_no`, but is 1 higher if we have sent a SYN,
            // as the SYN occupies 1 sequence number "before" the data.
            let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);

            if ack_number >= tx_buffer_start_seq {
                ack_len = ack_number - tx_buffer_start_seq;

                // We could've sent data before the FIN, so only remove FIN from the sequence
                // space if all of that data is acknowledged.
                if sent_fin && self.tx_buffer.len() + 1 == ack_len {
                    ack_len -= 1;
                    trace!("received ACK of FIN");
                    ack_of_fin = true;
                }

                ack_all = self.remote_last_seq <= ack_number;
            }
        }

        // Disregard control flags we don't care about or shouldn't act on yet.
        let mut control = repr.control;
        control = control.quash_psh();

        // If a FIN is received at the end of the current segment, but
        // we have a hole in the assembler before the current segment, disregard this FIN.
        if control == TcpControl::Fin && window_start < segment_start {
            trace!(
                "ignoring FIN because we don't have full data yet. window_start={} segment_start={}",
                window_start, segment_start
            );
            control = TcpControl::None;
        }

        // Validate and update the state.
        match (self.state, control) {
            // RSTs close the socket.
            (_, TcpControl::Rst) => {
                trace!("received RST");
                self.set_state(State::Closed);
                self.tuple = None;
                return None;
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.set_state(State::Established);
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            // SYN packets in the SYN-SENT state change it to SYN-RECEIVED.
            (State::SynSent, TcpControl::Syn) => {
                if repr.ack_number.is_some() {
                    trace!("received SYN|ACK");
                } else {
                    trace!("received SYN");
                }
                if let Some(max_seg_size) = repr.max_seg_size {
                    // Treat a zero MSS as if the option were absent, like Linux does.
                    if max_seg_size != 0 {
                        self.remote_mss = (max_seg_size as usize).max(MIN_REMOTE_MSS);
                        self.congestion_controller.set_mss(self.remote_mss);
                    }
                }

                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_last_ack = Some(repr.seq_number);
                #[cfg(feature = "tcp-sack")]
                {
                    self.remote_has_sack = repr.sack_permitted;
                }
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                // Timestamps stay on only if the remote offered them too.
                #[cfg(feature = "tcp-timestamps")]
                {
                    self.timestamps = repr.timestamp.is_some();
                }

                if repr.ack_number.is_some() {
                    self.set_state(State::Established);
                } else {
                    self.set_state(State::SynReceived);
                }
            }

            (State::Established, TcpControl::None) => {}

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                }
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(now);
                } else {
                    self.set_state(State::Closing);
                }
            }

            (State::FinWait2, TcpControl::None) => {}

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::TimeWait);
                self.timer.set_for_close(now);
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(now);
                }
            }

            (State::CloseWait, TcpControl::None) => {}

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                if ack_of_fin {
                    // Clear the remote endpoint, or we'll send an RST there.
                    self.set_state(State::Closed);
                    self.tuple = None;
                } else if ack_len == 0 {
                    // Duplicate ACK; our FIN has not been acknowledged.
                    // Per RFC 9293 (3.10.7.4), send a challenge ACK.
                    return self.challenge_ack_reply(now, repr);
                }
                // Partial ACK: fall through to advance SND.UNA normally.
            }

            _ => {
                debug!("unexpected packet {}", repr);
                return None;
            }
        }

        // Update remote state.
        self.remote_last_ts = Some(now);

        // RFC 1323: The window field (SEG.WND) in the header of every incoming segment, with the
        // exception of SYN segments, is left-shifted by Snd.Wind.Scale bits before updating SND.WND.
        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.remote_win_scale.unwrap_or(0),
        };
        let new_remote_win_len = (repr.window_len as usize) << (scale as usize);
        let is_window_update = new_remote_win_len != self.remote_win_len;
        self.remote_win_len = new_remote_win_len;

        self.congestion_controller.set_remote_window(new_remote_win_len);

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx_buffer.len() >= ack_len);
            trace!(
                "tx buffer: dequeueing {} octets (now {})",
                ack_len,
                self.tx_buffer.len() - ack_len
            );
            self.tx_buffer.dequeue_allocated(ack_len);

            // There's new room available in tx_buffer, wake the waiting task if any.
            #[cfg(feature = "async")]
            self.tx_waker.wake();
        }

        if let Some(ack_number) = repr.ack_number {
            // TODO: When flow control is implemented,
            // refractor the following block within that implementation

            match self.local_rx_last_ack {
                // Duplicate ACK if payload empty and ACK doesn't move send window ->
                // Increment duplicate ACK count, notify congestion controller and
                // set for retransmit if we just received the third duplicate ACK
                Some(last_rx_ack)
                    if repr.payload.is_empty()
                        && last_rx_ack == ack_number
                        && ack_number < self.remote_last_seq
                        && !is_window_update =>
                {
                    // Increment duplicate ACK count
                    self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);

                    debug!(
                        "received duplicate ACK for seq {} (duplicate nr {}{})",
                        ack_number,
                        self.local_rx_dup_acks,
                        if self.local_rx_dup_acks == u8::MAX { "+" } else { "" }
                    );

                    if self.local_rx_dup_acks == 3 {
                        self.timer.set_for_fast_retransmit();
                        debug!("started fast retransmit");
                    }

                    // Notify of duplicate ACK
                    let in_flight = self.flight_size();
                    self.congestion_controller.on_dup_ack(now, self.remote_mss, in_flight);
                }

                // No duplicate ACK means we reset the duplicate ACK count
                // and notify the congestion controller of the fresh ACK
                _ => {
                    if self.local_rx_dup_acks > 0 {
                        self.local_rx_dup_acks = 0;
                        debug!("reset duplicate ACK count");
                    }
                    self.local_rx_last_ack = Some(ack_number);

                    // Notify of fresh ACK
                    self.rtte.on_ack(now, ack_number);
                    let new_flight_size = self.flight_size().saturating_sub(ack_len);
                    self.congestion_controller
                        .on_ack(now, ack_len, new_flight_size, &self.rtte);
                }
            };

            // We've processed everything in the incoming segment, so advance the local
            // sequence number past it.
            self.local_seq_no = ack_number;

            // During retransmission, if an earlier segment got lost but later was
            // successfully received, self.local_seq_no can move past self.remote_last_seq.
            // Do not attempt to retransmit the latter segments; not only this is pointless
            // in theory but also impossible in practice, since they have been already
            // deallocated from the buffer.
            if self.remote_last_seq < self.local_seq_no {
                self.remote_last_seq = self.local_seq_no
            }
        }

        // update last remote tsval
        #[cfg(feature = "tcp-timestamps")]
        if let Some(timestamp) = repr.timestamp {
            self.last_remote_tsval = timestamp.tsval;
        }

        // update timers.
        match self.timer {
            Timer::Retransmit { .. } | Timer::FastRetransmit => {
                if ack_all {
                    // RFC 6298: (5.2) ACK of all outstanding data turn off the retransmit timer.
                    self.timer.set_for_idle(now, self.keep_alive);
                } else if ack_len > 0 {
                    // (5.3) ACK of new data in ESTABLISHED state restart the retransmit timer.
                    let rto = self.rtte.retransmission_timeout();
                    self.timer.set_for_retransmit(now, rto);
                }
            }
            Timer::Idle { .. } => {
                // any packet on idle refresh the keepalive timer.
                self.timer.set_for_idle(now, self.keep_alive);
            }
            _ => {}
        }

        // start/stop the Zero Window Probe timer.
        if self.remote_win_len == 0 && !self.tx_buffer.is_empty() && (self.timer.is_idle() || ack_len > 0) {
            let delay = self.rtte.retransmission_timeout();
            trace!("starting zero-window-probe timer for t+{}", delay);
            self.timer.set_for_zero_window_probe(now, delay);
        }
        if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
            trace!("stopping zero-window-probe timer");
            self.timer.set_for_idle(now, self.keep_alive);
        }

        let payload_len = payload.len();
        if payload_len == 0 {
            return None;
        }

        let assembler_was_empty = self.assembler.is_empty();

        // Try adding payload octets to the assembler.
        let Ok(contig_len) = self.assembler.add_then_remove_front(payload_offset, payload_len) else {
            debug!(
                "assembler: too many holes to add {} octets at offset {}",
                payload_len, payload_offset
            );
            // The payload is dropped, but the segment still arrived out of
            // order, so send the immediate duplicate ACK of RFC 5681 anyway.
            // It restates the current ACK and the held SACK ranges, giving the
            // sender its loss signal instead of leaving it to the RTO.
            return Some(self.ack_reply(now, repr));
        };

        // assembler accepted segment, track sequence number for SACK generation
        #[cfg(feature = "tcp-sack")]
        {
            self.local_rx_last_seq = Some(repr.seq_number);
        }

        // Place payload octets into the buffer.
        trace!(
            "rx buffer: receiving {} octets at offset {}",
            payload_len, payload_offset
        );
        let len_written = self.rx_buffer.write_unallocated(payload_offset, payload);
        debug_assert!(len_written == payload_len);

        if contig_len != 0 {
            // Enqueue the contiguous data octets in front of the buffer.
            trace!(
                "rx buffer: enqueueing {} octets (now {})",
                contig_len,
                self.rx_buffer.len() + contig_len
            );
            self.rx_buffer.enqueue_unallocated(contig_len);

            // There's new data in rx_buffer, notify waiting task if any.
            #[cfg(feature = "async")]
            self.rx_waker.wake();
        }

        if !self.assembler.is_empty() {
            // Print the ranges recorded in the assembler.
            trace!("assembler: {}", self.assembler);
        }

        // Handle delayed acks
        if let Some(ack_delay) = self.ack_delay
            && self.ack_to_transmit()
        {
            self.ack_delay_timer = match self.ack_delay_timer {
                AckDelayTimer::Idle => {
                    trace!("starting delayed ack timer");
                    AckDelayTimer::Waiting(now + ack_delay)
                }
                AckDelayTimer::Waiting(_) if self.immediate_ack_to_transmit() => {
                    trace!("delayed ack timer already started, forcing expiry");
                    AckDelayTimer::Immediate
                }
                timer @ AckDelayTimer::Waiting(_) => {
                    trace!("waiting until delayed ack timer expires");
                    timer
                }
                AckDelayTimer::Immediate => {
                    trace!("delayed ack timer already force-expired");
                    AckDelayTimer::Immediate
                }
            };
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because xarxa assumes that it can always transmit zero or one
            // packets for every packet it receives.
            trace!("ACKing incoming segment");
            Some(self.ack_reply(now, repr))
        } else {
            None
        }
    }

    fn timed_out(&self, timestamp: Instant) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => timestamp >= remote_last_ts + timeout,
            (_, _) => false,
        }
    }

    fn seq_to_transmit(&self) -> bool {
        // Fast retransmits should always send, even if later congestion checks would disallow
        if self.pending_fast_retransmit && !self.tx_buffer.is_empty() {
            return true;
        }

        let ip_header_len = match self.tuple.unwrap().local.addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(_) => crate::wire::IPV4_HEADER_LEN,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => crate::wire::IPV6_HEADER_LEN,
        };

        // The effective max segment size, taking into account our and remote's limits.
        // Per RFC 6691 §2 the advertised MSS counts payload only and excludes TCP options, so
        // subtract the options a data segment carries.
        //
        // This options length must mirror `TcpRepr::header_len()` for the data
        // segment `dispatch` will build (which sizes the payload from
        // `header_len()` directly), or the send decision drifts from the
        // actual segment sizing.
        let local_mss = self.ip_mtu - ip_header_len - TCP_HEADER_LEN;

        #[cfg(feature = "tcp-timestamps")]
        let mut options_len: usize = if self.timestamps { 10 } else { 0 };
        #[cfg(not(feature = "tcp-timestamps"))]
        let mut options_len: usize = 0;

        #[cfg(feature = "tcp-sack")]
        {
            let sack_blocks = self.sack_range_count();
            if sack_blocks > 0 {
                options_len += sack_blocks * 8 + 2;
            }
        }
        // Options are padded to a multiple of four bytes on the wire.
        options_len = options_len.next_multiple_of(4);

        let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq = self.local_seq_no + core::cmp::min(self.remote_win_len, self.tx_buffer.len());

        // Max amount of octets we can send.
        let capped_send_seq = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // compare max bytes allowed by cwnd with max bytes allowed by remote
        let max_send = capped_send_seq.min(self.cwnd_remaining());

        // Can we send at least 1 octet?
        let mut can_send = max_send != 0;
        // Can we send at least 1 full segment?
        let can_send_full = max_send >= effective_mss;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        // If we're applying the Nagle algorithm we don't want to send more
        // until one of:
        // * There's no data in flight
        // * We can send a full packet
        // * We have all the data we'll ever send (we're closing send)
        if self.nagle && data_in_flight && !can_send_full && !want_fin {
            can_send = false;
        }

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();

        can_send || can_fin
    }

    fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether to send ACK immediately due to the amount of unacknowledged data.
    ///
    /// RFC 9293 states "An ACK SHOULD be generated for at least every second full-sized segment or
    /// 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the
    /// segments to be acknowledged, or the default value if not specified) (SHLD-19)."
    ///
    /// Note that the RFC above only says "at least 2*RMSS bytes", which is not a hard requirement.
    /// In practice, we follow the Linux kernel's empirical value of sending an ACK for every RMSS
    /// byte of new data. For details, see
    /// <https://elixir.bootlin.com/linux/v6.11.4/source/net/ipv4/tcp_input.c#L5747>.
    fn immediate_ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack + self.remote_mss < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether we should send ACK immediately due to significant window updates.
    ///
    /// ACKs with significant window updates should be sent immediately to let the sender know that
    /// more data can be sent. According to the Linux kernel implementation, "significant" means
    /// doubling the receive window. The Linux kernel implementation can be found at
    /// <https://elixir.bootlin.com/linux/v6.9.9/source/net/ipv4/tcp.c#L1472>.
    fn window_to_update(&self) -> bool {
        match self.state {
            State::SynSent | State::SynReceived | State::Established | State::FinWait1 | State::FinWait2 => {
                let new_win = self.scaled_window();
                if let Some(last_win) = self.last_scaled_window() {
                    new_win > 0 && new_win / 2 >= last_win
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// The number of SACK blocks the next emitted ACK will carry.
    ///
    /// Matches the count `generate_sack_ranges()` will produce: that function
    /// fills any slots the history leaves open from the assembler, so the count
    /// is the number of islands, capped at 3.
    #[cfg(feature = "tcp-sack")]
    fn sack_range_count(&self) -> usize {
        if self.remote_has_sack {
            self.assembler.iter_data().take(3).count()
        } else {
            0
        }
    }

    /// Build the SACK blocks for an outgoing ACK, per RFC 2018, and record
    /// what was reported in `local_sack_history`.
    ///
    /// First block contains the triggering island (if it forms an island).
    /// Subsequent blocks are filled from history, and then from the assembler.
    /// Blocks are mapped into the current islands before reporting them.
    #[cfg(feature = "tcp-sack")]
    fn generate_sack_ranges(&mut self, ack: TcpSeqNumber) -> [Option<(u32, u32)>; 3] {
        if self.assembler.is_empty() {
            // Also drop the triggering sequence number: with no islands held it
            // can only go stale, and after a full sequence wrap a stale value
            // could land inside an unrelated future island and be promoted to
            // the first block.
            self.local_rx_last_seq = None;
            self.local_sack_history = [None, None, None];
            return [None, None, None];
        }

        debug!("sending SACK option with current assembler ranges");

        let mut blocks = [None, None, None];
        let mut n = 0;

        let find_block = |seq: TcpSeqNumber| {
            self.assembler
                .iter_data()
                .map(|(l, r)| (ack + l, ack + r))
                .find(|&(l, r)| l <= seq && seq < r)
        };

        // RFC 2018: the first SACK block MUST specify the contiguous block of
        // data containing the segment which triggered this ACK, unless that
        // segment advanced the Acknowledgment Number field in the header.
        if let Some(seq) = self.local_rx_last_seq
            && let Some(block) = find_block(seq)
        {
            blocks[0] = Some(block);
            n = 1;
        }

        // RFC 2018: The SACK option SHOULD be filled out by repeating the most
        // recently reported SACK blocks that are not subsets of a SACK block
        // already included in the SACK option being constructed.
        //
        // Maps each old block onto its current island, ensuring no duplicates.
        for block in self.local_sack_history.iter().flatten() {
            if n == blocks.len() {
                break;
            }
            if let Some(island) = find_block(block.0)
                && !blocks[..n].contains(&Some(island))
            {
                blocks[n] = Some(island);
                n += 1;
            }
        }

        // Remaining holes are filled from the assembler, lowest island first.
        for island in self.assembler.iter_data().map(|(l, r)| (ack + l, ack + r)) {
            if n == blocks.len() {
                break;
            }
            if !blocks[..n].contains(&Some(island)) {
                blocks[n] = Some(island);
                n += 1;
            }
        }

        self.local_sack_history = blocks;

        // convert blocks to wire representation
        blocks.map(|block| block.map(|(l, r)| (l.0 as u32, r.0 as u32)))
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut TxContext<'_, '_>, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut TxContext<'_, '_>, (Option<EgressRoute>, IpAddress, IpAddress, u8, TcpRepr)) -> Result<(), E>,
    {
        if self.tuple.is_none() {
            return Ok(());
        }

        // NOTE(unwrap): we check tuple is not None above.
        let tuple = self.tuple.unwrap();

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(cx.now());
        }

        self.congestion_controller.pre_transmit(cx.now());

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(cx.now()) {
            // If a timeout expires, we should abort the connection.
            debug!("timeout exceeded");
            self.set_state(State::Closed);
        } else if self.timer.should_retransmit(cx.now()) {
            if let Timer::Retransmit { .. } = self.timer {
                // If a retransmit timer expired, we should resend data starting at the last ACK.
                debug!("retransmitting after rto");

                // Inform the congestion controller that we're retransmitting and should enter the slow start state
                let in_flight = self.flight_size();
                self.congestion_controller.on_rto(cx.now(), in_flight);

                // Rewind "last sequence number sent", as if we never
                // had sent them. This will cause all data in the queue
                // to be sent again.
                self.remote_last_seq = self.local_seq_no;

                // Inform RTTE, so that it can can handle RTO backoff
                self.rtte.on_rto();
            } else {
                // If a fast rentrasmit timer expired, we should resend only the earliest unAcked segment
                debug!("retransmitting for fast-retransmit");

                // Inform the congestion controller that we're doing a fast retransmit and should enter the fast recovery state
                let in_flight = self.flight_size();
                self.congestion_controller.on_loss(cx.now(), in_flight);

                self.pending_fast_retransmit = true;
            }

            // Clear the `should_retransmit` state. If we can't retransmit right
            // now for whatever reason (like zero window), this avoids an
            // infinite polling loop where `poll_at` says "now" but `dispatch`
            // can't actually do anything.
            self.timer.set_for_idle(cx.now(), self.keep_alive);

            // Inform RTTE, so that it can avoid bogus measurements.
            self.rtte.on_retransmit();
        }

        // Route the destination now, before deciding whether to send: the egress
        // interface's MTU feeds the MSS, which the send decision and segment
        // sizing depend on. The decision is handed to `emit` so the packet is
        // never routed a second time. With no route, keep the last known MTU and
        // proceed. The segment is built and dropped at emit time, so socket
        // state still advances and the retransmit timer owns recovery.
        //
        // The source address must still be assigned to some interface, not
        // necessarily the egress one (weak host model). A source address that is
        // no longer ours is treated exactly like a routing failure: dropped at
        // emit, socket unaffected. The address may come back (e.g. a DHCP
        // renewal), and the retransmit timer owns recovery in the meantime.
        let route = if cx.has_ip_addr(tuple.local.addr) {
            cx.route(self.binding, &tuple.remote.addr)
        } else {
            debug!(
                "source address {} not assigned to any interface, dropping packet",
                tuple.local.addr
            );
            None
        };
        if let Some(route) = &route {
            self.ip_mtu = route.ip_mtu;
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit() {
            // If we have data to transmit and it fits into partner's window, do it.
            trace!("outgoing segment will send data or flags");
        } else if self.ack_to_transmit() && self.delayed_ack_expired(cx.now()) {
            // If we have data to acknowledge, do it.
            trace!("outgoing segment will acknowledge");
        } else if self.window_to_update() {
            // If we have window length increase to advertise, do it.
            trace!("outgoing segment will update window");
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
            trace!("outgoing segment will abort connection");
        } else if self.timer.should_keep_alive(cx.now()) {
            // If we need to transmit a keep-alive packet, do it.
            trace!("keep-alive timer expired");
        } else if self.timer.should_zero_window_probe(cx.now()) {
            trace!("sending zero-window probe");
        } else if self.timer.should_close(cx.now()) {
            // If we have spent enough time in the TIME-WAIT state, close the socket.
            trace!("TIME-WAIT timer expired");
            self.reset();
            return Ok(());
        } else {
            return Ok(());
        }

        // The hop limit, and the IP header length that feeds the MSS calculation.
        let hop_limit = self.hop_limit.unwrap_or(64);
        let ip_header_len = match tuple.local.addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(_) => IPV4_HEADER_LEN,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => IPV6_HEADER_LEN,
        };

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: tuple.local.port,
            dst_port: tuple.remote.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx_buffer.len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            #[cfg(feature = "tcp-sack")]
            sack_permitted: false,
            #[cfg(feature = "tcp-sack")]
            sack_ranges: [None, None, None],
            #[cfg(feature = "tcp-timestamps")]
            timestamp: self.timestamp_repr(cx.now(), self.last_remote_tsval),
            payload: &[],
            payload2: &[],
        };

        // We fill blocks before payload sizing to ensure the options header length
        // is taken into account.
        #[cfg(feature = "tcp-sack")]
        match self.state {
            State::Closed | State::SynSent | State::SynReceived => {}
            _ => {
                if self.remote_has_sack
                    && let Some(ack) = repr.ack_number
                {
                    repr.sack_ranges = self.generate_sack_ranges(ack);
                }
            }
        }

        let mut is_zero_window_probe = false;

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                repr.seq_number = self.local_seq_no;
                // window len must NOT be scaled in SYNs.
                repr.window_len = u16::try_from(self.rx_buffer.window()).unwrap_or(u16::MAX);
                if self.state == State::SynSent {
                    repr.ack_number = None;
                    repr.window_scale = Some(self.remote_win_shift);
                    #[cfg(feature = "tcp-sack")]
                    {
                        repr.sack_permitted = true;
                    }
                } else {
                    #[cfg(feature = "tcp-sack")]
                    {
                        repr.sack_permitted = self.remote_has_sack;
                    }
                    repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established | State::FinWait1 | State::Closing | State::CloseWait | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Maximum size we're allowed to send. This can be limited by 4 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                // 4. Our congestion window
                let options_len = repr.header_len() - TCP_HEADER_LEN;
                let local_mss = self.ip_mtu - ip_header_len - TCP_HEADER_LEN;
                let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

                let offset = if self.pending_fast_retransmit {
                    let size = effective_mss.min(self.tx_buffer.len());
                    repr.seq_number = self.local_seq_no;
                    // The ring buffer hands out contiguous slices, so a segment
                    // straddling its wrap point comes as two chunks.
                    repr.payload = self.tx_buffer.get_allocated(0, size);
                    repr.payload2 = self
                        .tx_buffer
                        .get_allocated(repr.payload.len(), size - repr.payload.len());

                    self.pending_fast_retransmit = false;

                    0
                } else {
                    // Right edge of window, ie the max sequence number we're allowed to send.
                    let win_right_edge = self.local_seq_no + self.remote_win_len;

                    // Max amount of octets we're allowed to send according to the remote window.
                    let mut win_limit = if win_right_edge >= self.remote_last_seq {
                        win_right_edge - self.remote_last_seq
                    } else {
                        // This can happen if we've sent some data and later the remote side
                        // has shrunk its window so that data is no longer inside the window.
                        // This should be very rare and is strongly discouraged by the RFCs,
                        // but it does happen in practice.
                        // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                        0
                    };

                    // To send a zero-window-probe, force the window limit to at least 1 byte.
                    if win_limit == 0 && self.timer.should_zero_window_probe(cx.now()) {
                        win_limit = 1;
                        is_zero_window_probe = true;
                    }

                    // Maximum size we're allowed to send. This can be limited by 4 factors:
                    // 1. remote window
                    // 2. congestion window
                    // 3. MSS the remote is willing to accept, probably determined by their MTU
                    // 4. MSS we can send, determined by our MTU.
                    let size = if is_zero_window_probe {
                        // Zero-window probes are exempt from the congestion window: they
                        // are sent precisely when normal transmission is impossible, and
                        // an empty segment elicits no reply, so capping the probe to a
                        // zero length would stall the connection if a window update from
                        // the remote got lost.
                        win_limit.min(effective_mss)
                    } else {
                        win_limit.min(effective_mss).min(self.cwnd_remaining())
                    };

                    let offset = self.flight_size();
                    // The ring buffer hands out contiguous slices, so a segment
                    // straddling its wrap point comes as two chunks.
                    repr.payload = self.tx_buffer.get_allocated(offset, size);
                    repr.payload2 = self
                        .tx_buffer
                        .get_allocated(offset + repr.payload.len(), size - repr.payload.len());
                    offset
                };

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload_len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing => repr.control = TcpControl::Fin,
                        State::Established | State::CloseWait if repr.payload_len() != 0 => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.
        let is_keep_alive;
        if self.timer.should_keep_alive(cx.now()) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            repr.payload = b"\x00"; // RFC 1122 says we should do this
            is_keep_alive = true;
        } else {
            is_keep_alive = false;
        }

        // Trace a summary of what will be sent.
        if is_keep_alive {
            trace!("sending a keep-alive");
        } else if repr.payload_len() != 0 {
            trace!(
                "tx buffer: sending {} octets at offset {}",
                repr.payload_len(),
                self.flight_size()
            );
        }
        if repr.control != TcpControl::None || repr.payload_len() == 0 {
            let flags = match (repr.control, repr.ack_number) {
                (TcpControl::Syn, None) => "SYN",
                (TcpControl::Syn, Some(_)) => "SYN|ACK",
                (TcpControl::Fin, Some(_)) => "FIN|ACK",
                (TcpControl::Rst, Some(_)) => "RST|ACK",
                (TcpControl::Psh, Some(_)) => "PSH|ACK",
                (TcpControl::None, Some(_)) => "ACK",
                _ => "<unreachable>",
            };
            trace!("sending {}", flags);
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let max_segment_size = self.ip_mtu - ip_header_len - TCP_HEADER_LEN;
            repr.max_seg_size = Some(max_segment_size as u16);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        emit(cx, (route, tuple.local.addr, tuple.remote.addr, hop_limit, repr))?;

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(cx.now(), self.keep_alive);

        // Reset delayed-ack timer
        match self.ack_delay_timer {
            AckDelayTimer::Idle => {}
            AckDelayTimer::Waiting(_) => {
                trace!("stop delayed ack timer")
            }
            AckDelayTimer::Immediate => {
                trace!("stop delayed ack timer (was force-expired)")
            }
        }
        self.ack_delay_timer = AckDelayTimer::Idle;

        // Leave the rest of the state intact if sending a zero-window probe.
        if is_zero_window_probe {
            self.timer.rewind_zero_window_probe(cx.now());
            return Ok(());
        }

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive {
            return Ok(());
        }

        // We've sent a packet successfully, so we can update the internal state now.
        // Use max() so a fast-retransmit segment (whose seq_number is local_seq_no, well
        // behind the current frontier) doesn't rewind the tracked "highest sent" sequence.
        self.remote_last_seq = self.remote_last_seq.max(repr.seq_number + repr.segment_len());
        self.remote_last_ack = repr.ack_number;
        self.remote_last_win = repr.window_len;

        if repr.segment_len() > 0 {
            self.rtte.on_send(cx.now(), repr.seq_number + repr.segment_len());
            self.congestion_controller.post_transmit(cx.now(), repr.segment_len());
        }

        if repr.segment_len() > 0 && !self.timer.is_retransmit() {
            // RFC 6298 (5.1) Every time a packet containing data is sent (including a
            // retransmission), if the timer is not running, start it running
            // so that it will expire after RTO seconds.
            let rto = self.rtte.retransmission_timeout();
            self.timer.set_for_retransmit(cx.now(), rto);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.tuple = None;
            // Wake tx now so that async users can wait for the RST to be sent.
            #[cfg(feature = "async")]
            self.tx_waker.wake();
        }

        Ok(())
    }

    /// The next time the socket should be polled.
    ///
    /// [`Instant::MIN`] means "poll immediately", [`Instant::MAX`] means "no need to
    /// poll unless something external happens".
    #[allow(clippy::if_same_then_else)]
    pub(crate) fn poll_at(&self) -> Instant {
        // The logic here mirrors the beginning of dispatch() closely.
        if self.tuple.is_none() {
            // No one to talk to, nothing to transmit.
            Instant::MAX
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            Instant::MIN
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            Instant::MIN
        } else if self.seq_to_transmit() {
            // We have a data or flag packet to transmit.
            Instant::MIN
        } else if self.window_to_update() {
            // The receive window has been raised significantly.
            Instant::MIN
        } else {
            let want_ack = self.ack_to_transmit();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer) {
                (false, _) => Instant::MAX,
                (true, AckDelayTimer::Idle) => Instant::MIN,
                (true, AckDelayTimer::Waiting(t)) => t,
                (true, AckDelayTimer::Immediate) => Instant::MIN,
            };

            let timeout_poll_at = match (self.remote_last_ts, self.timeout) {
                // If we're transmitting or retransmitting data, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) => remote_last_ts + timeout,
                // Otherwise we have no timeout.
                (_, _) => Instant::MAX,
            };

            // We wait for the earliest of our timers to fire.
            self.timer.poll_at().min(timeout_poll_at).min(delayed_ack_poll_at)
        }
    }

    /// [`poll_at`](Self::poll_at) for a socket whose segment was held back
    /// ([`Blocked`]). Wanting to send is not a reason to poll: the device wakes
    /// the poll task when it has room, and every timer that fires in the meantime
    /// would only produce the same held-back segment. The one exception is the
    /// connection timeout, which must abort the connection even if the device
    /// never frees up.
    pub(crate) fn poll_at_blocked(&self) -> Instant {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => remote_last_ts + timeout,
            (_, _) => Instant::MAX,
        }
    }
}

/// Copy a TCP segment out of the socket state into a fresh packet buffer, with
/// headroom reserved for the IP and Ethernet headers below it. `None` if the
/// pool is empty.
pub(crate) fn build_tcp_packet(
    repr: &TcpRepr<'_>,
    src_addr: &IpAddress,
    dst_addr: &IpAddress,
    checksum_caps: &ChecksumCapabilities,
) -> Option<PacketBuf> {
    let ip_header_len = match dst_addr {
        #[cfg(feature = "ipv4")]
        IpAddress::Ipv4(_) => IPV4_HEADER_LEN,
        #[cfg(feature = "ipv6")]
        IpAddress::Ipv6(_) => IPV6_HEADER_LEN,
    };
    let mut buf = PacketBuf::try_new()?;
    buf.reserve(LINK_HEADER_LEN + ip_header_len);
    buf.set_len(repr.buffer_len());
    let mut packet = TcpPacket::new_unchecked(&mut buf);
    repr.emit(&mut packet, src_addr, dst_addr, checksum_caps);
    Some(buf)
}

/// Deliver an ICMP error to the TCP connection whose segment provoked it: exact
/// 4-tuple match against the flow quoted in the error. `local`/`remote` are the
/// quoted packet's source and destination, since the quote is a segment this
/// stack sent.
#[cfg(feature = "icmp-errors")]
pub(crate) fn process_icmp_error(
    sockets: &mut Slab<TcpSocketState, TCP_SOCKET_COUNT>,
    error: IcmpError,
    local: IpEndpoint,
    remote: IpEndpoint,
    seq: TcpSeqNumber,
) {
    for (_, socket) in sockets.iter_mut() {
        if socket.state != State::Closed
            && let Some(tuple) = &socket.tuple
            && tuple.local == local
            && tuple.remote == remote
        {
            socket.process_icmp_error(error, seq);
            return;
        }
    }
}

/// A segment could not be transmitted right now: the egress device has no room,
/// or the packet pool is empty. The socket is left as if it had never tried, and
/// [`Stack::poll`](crate::Stack::poll) retries once the device frees a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Blocked;

/// Drive the socket's egress until it has nothing more it wants to transmit right
/// now: data and flag segments, ACKs, window updates, retransmissions, probes.
/// Called from [`Stack::poll`](crate::Stack::poll), which is the only place TCP
/// segments are transmitted from.
///
/// Each emitted segment goes down the stack's egress path
/// ([`TxContext::transmit_ip`]): routing, IP header construction, and neighbor
/// resolution.
///
/// Returns [`Blocked`] if it stopped because the egress device has no room (or
/// the pool is empty). The socket's state is untouched by the segment it could
/// not send, so nothing is lost and no retransmission timer has to cover it.
pub(crate) fn flush(state: &mut TcpSocketState<'_>, cx: &mut TxContext<'_, '_>) -> Result<(), Blocked> {
    loop {
        let mut emitted = false;
        state.dispatch(cx, |cx, (route, src_addr, dst_addr, hop_limit, repr)| {
            emitted = true;
            // No route drops the segment and leaves the socket as if it had been
            // sent: the retransmit timer owns recovery. A full device or an empty
            // pool instead holds the segment back, socket untouched.
            let Some(route) = route else {
                debug!("no route to {}, dropping packet", dst_addr);
                return Ok(());
            };
            if !cx.can_transmit(route.iface) {
                trace!("device has no room for segment to {}, holding it back", dst_addr);
                return Err(Blocked);
            }
            let Some(buf) = build_tcp_packet(&repr, &src_addr, &dst_addr, &cx.checksum_caps(route.iface)) else {
                trace!("no packet buffer for segment to {}, holding it back", dst_addr);
                return Err(Blocked);
            };
            cx.transmit_ip(&route, buf, src_addr, dst_addr, IpProtocol::Tcp, hop_limit);
            Ok(())
        })?;
        if !emitted {
            return Ok(());
        }
    }
}

/// A Transmission Control Protocol socket, borrowed from a [`Stack`] by
/// [`Stack::tcp_socket`].
///
#[cfg_attr(
    not(feature = "tcp-listener"),
    doc = "A TCP socket represents a single connection (connecting or connected): its",
    doc = "4-tuple is fully set from the start, by [`connect`](Self::connect)."
)]
#[cfg_attr(
    feature = "tcp-listener",
    doc = "A TCP socket represents a single connection (connecting or connected): its",
    doc = "4-tuple is fully set from the start, by [`connect`](Self::connect) or by",
    doc = "[`TcpListener::accept`]. Passive open lives in [`TcpListener`]."
)]
///
/// [`Stack`]: crate::Stack
/// [`Stack::tcp_socket`]: crate::Stack::tcp_socket
pub struct TcpSocket<'a, 'd> {
    pub(crate) sockets: &'a mut Slab<TcpSocketState<'d>, TCP_SOCKET_COUNT>,
    pub(crate) index: usize,
    pub(crate) tx: TxContext<'a, 'd>,
}

impl<'d> TcpSocket<'_, 'd> {
    /// This socket's state in the slab.
    #[inline]
    fn inner(&self) -> &TcpSocketState<'d> {
        self.sockets.get(self.index)
    }

    /// Mutable variant of [`inner`](Self::inner).
    #[inline]
    fn inner_mut(&mut self) -> &mut TcpSocketState<'d> {
        self.sockets.get_mut(self.index)
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
    /// `send` calls, such as space becoming available in the transmit buffer, or
    /// the socket closing.
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

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<Duration> {
        self.inner().timeout
    }

    /// Return the ACK delay duration.
    ///
    /// See also the [set_ack_delay](#method.set_ack_delay) method.
    pub fn ack_delay(&self) -> Option<Duration> {
        self.inner().ack_delay
    }

    /// Return whether Nagle's Algorithm is enabled.
    ///
    /// See also the [set_nagle_enabled](#method.set_nagle_enabled) method.
    pub fn nagle_enabled(&self) -> bool {
        self.inner().nagle
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<Duration>) {
        self.inner_mut().timeout = duration
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        self.inner_mut().ack_delay = duration
    }

    /// Enable or disable Nagle's Algorithm.
    ///
    /// Also known as "tinygram prevention". By default, it is enabled.
    /// Disabling it is equivalent to Linux's TCP_NODELAY flag.
    ///
    /// When enabled, Nagle's Algorithm prevents sending segments smaller than MSS if
    /// there is data in flight (sent but not acknowledged). In other words, it ensures
    /// at most only one segment smaller than MSS is in flight at a time.
    ///
    /// It ensures better network utilization by preventing sending many very small packets,
    /// at the cost of increased latency in some situations, particularly when the remote peer
    /// has ACK delay enabled.
    pub fn set_nagle_enabled(&mut self, enabled: bool) {
        self.inner_mut().nagle = enabled
    }

    /// Return the keep-alive interval.
    ///
    /// See also the [set_keep_alive](#method.set_keep_alive) method.
    pub fn keep_alive(&self) -> Option<Duration> {
        self.inner().keep_alive
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "keep-alive ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<Duration>) {
        self.inner_mut().keep_alive = interval;
        if self.inner_mut().keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.inner_mut().timer.set_keep_alive();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.inner().hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.inner_mut().hop_limit = hop_limit
    }

    /// Bind the socket to an interface, or unbind it with `None`.
    ///
    /// A socket bound to an interface only sends and receives packets on it:
    /// - Destinations must be on-link on that iface, or have a route through it.
    /// - Broadcast and multicast destinations go out on that iface only
    /// - Local addresses will be picked from that iface only.
    ///
    /// The socket must be closed (see [`is_open`](Self::is_open)). The binding
    /// is kept across connections, so a reused socket stays bound to its interface.
    /// Accepting a connection into the socket overwrites it with the listener's binding.
    ///
    /// Two sockets with otherwise identical tuples may coexist if they are
    /// bound to different interfaces.
    ///
    /// Returns `Err(ConnectError::InvalidState)` if the socket is open.
    #[cfg(feature = "iface-bind")]
    pub fn bind_to_iface(&mut self, iface: Option<IfaceHandle>) -> Result<(), ConnectError> {
        if self.is_open() {
            return Err(ConnectError::InvalidState);
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

    /// Return the local endpoint, or None if not connected.
    #[inline]
    pub fn local_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.inner().tuple?.local)
    }

    /// Return the remote endpoint, or None if not connected.
    #[inline]
    pub fn remote_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.inner().tuple?.remote)
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.inner().state
    }

    /// Connect to a given endpoint.
    ///
    /// The local endpoint may be left mostly unspecified: a local port of zero
    /// means "allocate an ephemeral port" (a free port in the 49152..=65535
    /// range, picked at a random starting point), and the local address, if not
    /// provided, is selected by the stack from the remote address. So the
    /// common case is simply `connect(remote, 0)`. An unspecified local address
    /// (`0.0.0.0` / `::`) is selected the same way, but asserts the IP version
    /// the connection must be.
    ///
    /// Only the full 4-tuple must be unique, not the local port: two sockets
    /// may connect from the same local port as long as the remote (or the
    /// local address) differs. Ingress matches connected sockets by exact
    /// tuple, so distinct tuples are never ambiguous. Sharing a port with a
    /// listener is fine too, since connected sockets are matched before
    /// listeners. Ephemeral allocation applies the same rule, and an explicit
    /// local endpoint that would duplicate another socket's tuple is rejected
    /// with `Err(ConnectError::InUse)`.
    ///
    /// This function returns an error if the socket was open (see
    /// [is_open](#method.is_open)). It also returns an error if the remote port
    /// is zero, or if the remote address is unspecified.
    pub fn connect<T, U>(&mut self, remote_endpoint: T, local_endpoint: U) -> Result<(), ConnectError>
    where
        T: Into<IpEndpoint>,
        U: Into<IpListenEndpoint>,
    {
        let remote_endpoint: IpEndpoint = remote_endpoint.into();
        let local: IpListenEndpoint = local_endpoint.into();

        if self.is_open() {
            return Err(ConnectError::InvalidState);
        }
        if remote_endpoint.port == 0 || remote_endpoint.addr.is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }

        let binding = self.inner().binding;

        // Resolve the local address up front: conflicts are decided on the full,
        // concrete 4-tuple. An unspecified local address is selected from the
        // remote like a missing one, but restricts the IP version first.
        let local_addr = match local.concrete_addr() {
            Some(addr) => addr,
            None => {
                if let Some(version) = local.version()
                    && version != remote_endpoint.addr.version()
                {
                    return Err(ConnectError::Unaddressable);
                }
                self.tx
                    .get_source_address(binding, &remote_endpoint.addr)
                    .ok_or(ConnectError::Unaddressable)?
            }
        };
        let mut local_endpoint = IpEndpoint::new(local_addr, local.port);

        // The interface binding is part of the identity: same-tuple sockets
        // bound to different interfaces coexist, and a segment arrives on
        // exactly one interface.
        let (sockets, index) = (&self.sockets, self.index);
        let tuple_in_use = |local: IpEndpoint| {
            sockets.iter().any(|(i, s)| {
                i != index
                    && s.binding == binding
                    && s.tuple
                        == Some(Tuple {
                            local,
                            remote: remote_endpoint,
                        })
            })
        };

        if local_endpoint.port == 0 {
            local_endpoint.port = alloc_ephemeral_port(self.tx.rand(), |port| {
                tuple_in_use(IpEndpoint::new(local_endpoint.addr, port))
            })
            .ok_or(ConnectError::NoFreePorts)?;
        } else if tuple_in_use(local_endpoint) {
            return Err(ConnectError::InUse);
        }
        let seq = TcpSocketState::random_seq_no(self.tx.rand());
        #[cfg(feature = "tcp-timestamps")]
        let tsval_offset = TcpSocketState::random_tsval_offset(self.tx.rand());

        let s = self.inner_mut();
        s.reset();
        s.tuple = Some(Tuple {
            local: local_endpoint,
            remote: remote_endpoint,
        });
        s.set_state(State::SynSent);
        s.local_seq_no = seq;
        s.remote_last_seq = seq;
        // Every connection we open offers timestamps; the SYN|ACK decides
        // whether they stay on.
        #[cfg(feature = "tcp-timestamps")]
        {
            s.timestamps = true;
            s.last_remote_tsval = 0;
            s.tsval_offset = tsval_offset;
        }
        Ok(())
    }

    /// Close the transmit half of the full-duplex connection.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.inner_mut().state {
            // In the SYN-SENT state the remote endpoint is not yet synchronized and, upon
            // receiving an RST, will abort the connection.
            State::SynSent => self.inner_mut().set_state(State::Closed),
            // In the SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            State::SynReceived | State::Established => self.inner_mut().set_state(State::FinWait1),
            State::CloseWait => self.inner_mut().set_state(State::LastAck),
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1 | State::FinWait2 | State::Closing | State::TimeWait | State::LastAck | State::Closed => (),
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.inner_mut().set_state(State::Closed);
    }

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` states.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().is_open()
    }

    /// Return whether a connection is active.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` state.
    #[inline]
    pub fn is_active(&self) -> bool {
        match self.inner().state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true,
        }
    }

    /// Return whether the transmit half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to send data and have it arrive
    /// to the remote endpoint. However, it does not make any guarantees about the state
    /// of the transmit buffer, and even if it returns true, [send](#method.send) may
    /// not be able to enqueue any octets.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED` or
    /// `CLOSE-WAIT` state.
    #[inline]
    pub fn may_send(&self) -> bool {
        match self.inner().state {
            State::Established => true,
            // In CLOSE-WAIT, the remote endpoint has closed our receive half of the connection
            // but we still can transmit indefinitely.
            State::CloseWait => true,
            _ => false,
        }
    }

    /// Return whether the receive half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to receive data from the remote endpoint.
    /// It will return true while there is data in the receive buffer, and if there isn't,
    /// as long as the remote endpoint has not closed the connection.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED`,
    /// `FIN-WAIT-1`, or `FIN-WAIT-2` state, or have data in the receive buffer instead.
    #[inline]
    pub fn may_recv(&self) -> bool {
        match self.inner().state {
            State::Established => true,
            // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
            // we still can receive indefinitely.
            State::FinWait1 | State::FinWait2 => true,
            // If we have something in the receive buffer, we can receive that.
            _ if self.can_recv() => true,
            _ => false,
        }
    }

    /// Check whether the transmit half of the full-duplex connection is open
    /// (see [may_send](#method.may_send)), and the transmit buffer is not full.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.may_send() {
            return false;
        }

        !self.inner().tx_buffer.is_full()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn recv_capacity(&self) -> usize {
        self.inner().rx_buffer.capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn send_capacity(&self) -> usize {
        self.inner().tx_buffer.capacity()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.inner().rx_buffer.is_empty()
    }

    fn send_impl<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut SocketBuffer<'d>) -> (usize, R),
    {
        if !self.may_send() {
            return Err(SendError::InvalidState);
        }

        let s = self.inner_mut();
        let old_length = s.tx_buffer.len();
        let (size, result) = f(&mut s.tx_buffer);
        if size > 0 {
            // The connection might have been idle for a long time, and so remote_last_ts
            // would be far in the past. Unless we clear it here, we'll abort the connection
            // down over in dispatch() by erroneously detecting it as timed out.
            if old_length == 0 {
                s.remote_last_ts = None
            }

            // if remote win is zero and we go from having no data to some data pending to
            // send, start the zero window probe timer.
            if s.remote_win_len == 0 && s.timer.is_idle() {
                let delay = s.rtte.retransmission_timeout();
                trace!("starting zero-window-probe timer for t+{}", delay);

                // We don't have access to the current time here, so use Instant::ZERO instead.
                // this will cause the first ZWP to be sent immediately, but that's okay.
                s.timer.set_for_zero_window_probe(Instant::ZERO, delay);
            }

            trace!("tx buffer: enqueueing {} octets (now {})", size, old_length + size);
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the transmit buffer,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(Error::Illegal)` if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.send_impl(|tx_buffer| tx_buffer.enqueue_many_with(f))
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of octets actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, SendError> {
        self.send_impl(|tx_buffer| {
            let size = tx_buffer.enqueue_slice(data);
            (size, size)
        })
    }

    fn recv_error_check(&mut self) -> Result<(), RecvError> {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN. (We do not support TCP Fast Open.)
        if !self.may_recv() {
            if self.inner_mut().rx_fin_received {
                return Err(RecvError::Finished);
            }
            return Err(RecvError::InvalidState);
        }

        Ok(())
    }

    fn recv_impl<'b, F, R>(&'b mut self, f: F) -> Result<R, RecvError>
    where
        F: FnOnce(&'b mut SocketBuffer<'d>) -> (usize, R),
    {
        self.recv_error_check()?;

        let s = self.inner_mut();
        let _old_length = s.rx_buffer.len();
        let (size, result) = f(&mut s.rx_buffer);
        s.remote_seq_no += size;
        if size > 0 {
            trace!("rx buffer: dequeueing {} octets (now {})", size, _old_length - size);
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the receive buffer,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// This function errors if the receive half of the connection is not open.
    ///
    /// If the receive half has been gracefully closed (with a FIN packet), `Err(Error::Finished)`
    /// is returned. In this case, the previously received data is guaranteed to be complete.
    ///
    /// In all other cases, `Err(Error::Illegal)` is returned and previously received data (if any)
    /// may be incomplete (truncated).
    pub fn recv<'b, F, R>(&'b mut self, f: F) -> Result<R, RecvError>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.recv_impl(|rx_buffer| rx_buffer.dequeue_many_with(f))
    }

    /// Dequeue a sequence of received octets, and fill a slice from it.
    ///
    /// This function returns the amount of octets actually dequeued, which is limited
    /// by the amount of occupied space in the receive buffer; down to zero.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        self.recv_impl(|rx_buffer| {
            let size = rx_buffer.dequeue_slice(data);
            (size, size)
        })
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and return a pointer to it.
    ///
    /// This function otherwise behaves identically to [recv](#method.recv).
    pub fn peek(&mut self, size: usize) -> Result<&[u8], RecvError> {
        self.recv_error_check()?;

        let buffer = self.inner_mut().rx_buffer.get_allocated(0, size);
        if !buffer.is_empty() {
            trace!("rx buffer: peeking at {} octets", buffer.len());
        }
        Ok(buffer)
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and fill a slice from it.
    ///
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        Ok(self.inner_mut().rx_buffer.read_allocated(0, data))
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.inner().tx_buffer.len()
    }

    /// Return the amount of octets queued in the receive buffer. This value can be larger than
    /// the slice read by the next `recv` or `peek` call because it includes all queued octets,
    /// and not only the octets that may be returned as a contiguous slice.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.inner().rx_buffer.len()
    }

    /// Take the pending ICMP error, if one has been reported against this
    /// connection.
    #[cfg(feature = "icmp-errors")]
    pub fn take_icmp_error(&mut self) -> Option<IcmpError> {
        self.inner_mut().icmp_error.take()
    }
}

impl fmt::Write for TcpSocket<'_, '_> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}
/// Iterator over the TCP sockets of a [`Stack`], returned by [`Stack::tcp_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.tcp_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.state());
/// }
/// # }
/// ```
pub struct TcpSocketIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> TcpSocketIter<'_, 'd> {
    /// Get the next TCP socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(TcpHandle, TcpSocket<'_, 'd>)> {
        let index = self.stack.sockets.tcp.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = TcpHandle::new(index);
        Some((handle, self.stack.tcp_socket(handle)))
    }
}

#[cfg(all(test, feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
mod test {
    use super::*;
    use crate::iface::Medium;
    use crate::stack::Stack;
    use crate::test_device::TestDevice;
    use crate::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address};
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const TUPLE: Tuple = Tuple {
        local: LOCAL_END,
        remote: REMOTE_END,
    };
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    use crate::wire::Ipv4Address as IpvXAddress;

    const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
    const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
    const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);
    /// The unspecified address of the *other* IP version than the one under test.
    const OTHER_VERSION_ANY: IpAddress = IpAddress::Ipv6(Ipv6Address::UNSPECIFIED);

    const BASE_MSS: u16 = 1460;

    const LOCAL_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(LOCAL_ADDR),
        port: LOCAL_PORT,
    };
    const REMOTE_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(REMOTE_ADDR),
        port: REMOTE_PORT,
    };

    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        #[cfg(feature = "tcp-sack")]
        sack_permitted: false,
        #[cfg(feature = "tcp-sack")]
        sack_ranges: [None, None, None],
        #[cfg(feature = "tcp-timestamps")]
        timestamp: None,
        payload: &[],
        payload2: &[],
    };
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        #[cfg(feature = "tcp-sack")]
        sack_permitted: false,
        #[cfg(feature = "tcp-sack")]
        sack_ranges: [None, None, None],
        #[cfg(feature = "tcp-timestamps")]
        timestamp: None,
        payload: &[],
        payload2: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        sockets: Slab<TcpSocketState<'static>, TCP_SOCKET_COUNT>,
        stack: Stack<'static>,
    }

    impl TestSocket {
        fn view(&mut self) -> TcpSocket<'_, 'static> {
            TcpSocket {
                sockets: &mut self.sockets,
                index: 0,
                tx: self.stack.tx_context(),
            }
        }
    }

    impl Deref for TestSocket {
        type Target = TcpSocketState<'static>;
        fn deref(&self) -> &Self::Target {
            self.sockets.get(0)
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.sockets.get_mut(0)
        }
    }

    #[track_caller]
    fn send(socket: &mut TestSocket, timestamp: Instant, repr: &TcpRepr) -> Option<TcpRepr<'static>> {
        socket.stack.inner.now = timestamp;

        let src_addr = IpAddress::from(REMOTE_ADDR);
        let dst_addr = IpAddress::from(LOCAL_ADDR);
        trace!("send: {}", repr);

        assert!(socket.sockets.get_mut(0).accepts(&src_addr, &dst_addr, repr));

        match socket.sockets.get_mut(0).process(timestamp, &src_addr, &dst_addr, repr) {
            Some(repr) => {
                trace!("recv: {}", repr);
                Some(repr)
            }
            None => None,
        }
    }

    #[track_caller]
    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr, ()>),
    {
        socket.stack.inner.now = timestamp;

        let mut sent = 0;
        let result = socket.sockets.get_mut(0).dispatch(
            &mut socket.stack.tx_context(),
            |_, (_route, src_addr, dst_addr, _hop_limit, tcp_repr)| {
                assert_eq!(src_addr, LOCAL_ADDR.into());
                assert_eq!(dst_addr, REMOTE_ADDR.into());

                trace!("recv: {}", tcp_repr);
                sent += 1;
                f(Ok(tcp_repr));
                Ok(())
            },
        );
        match result {
            Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
            Err(e) => f(Err(e)),
        }
    }

    #[track_caller]
    fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
        socket.stack.inner.now = timestamp;

        let mut fail = false;
        let result: Result<(), ()> = socket
            .sockets
            .get_mut(0)
            .dispatch(&mut socket.stack.tx_context(), |_, _| {
                fail = true;
                Ok(())
            });
        if fail {
            panic!("Should not send a packet")
        }

        assert_eq!(result, Ok(()))
    }

    #[collapse_debuginfo(yes)]
    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, None));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv_nothing!($socket)
        });
        ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
            $( recv!($socket, time $time, Ok($repr)); )*
            recv_nothing!($socket, time $time)
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv_nothing {
        ($socket:ident) => (recv_nothing!($socket, time 0));
        ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.tuple, s2.tuple, "tuple");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win, s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    /// A stack with one interface owning `LOCAL_ADDR`.
    fn test_stack() -> Stack<'static> {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = TestDevice::new(Medium::Ip).install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(handle)
            .set_ip_addrs([
                IpCidr::new(LOCAL_ADDR.into(), 24),
                IpCidr::new(Ipv4Address::new(127, 0, 0, 1).into(), 8),
            ])
            .unwrap();
        stack
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let stack = test_stack();

        let rx_buffer = SocketBuffer::new(vec![0; rx_len].leak());
        let tx_buffer = SocketBuffer::new(vec![0; tx_len].leak());
        let mut socket = TcpSocketState::new(rx_buffer, tx_buffer);
        socket.ack_delay = None;
        let mut sockets = Slab::new();
        sockets.add_with(|_| socket).unwrap();
        TestSocket { sockets, stack }
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynReceived;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynSent;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = s.scaled_window();
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.timer = Timer::Retransmit {
            expires_at: Instant::from_millis_const(1000),
        };
        s
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(
            !s.sockets
                .get(0)
                .accepts(&REMOTE_ADDR.into(), &LOCAL_ADDR.into(), &tcp_repr)
        );
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.view().close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for listeners.
    // =========================================================================================//

    /// A stack with a listener on `LOCAL_PORT` (any address).
    #[cfg(feature = "tcp-listener")]
    fn listener_stack() -> (Stack<'static>, TcpListenerHandle) {
        let mut stack = test_stack();
        let h = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h).listen(LOCAL_PORT).unwrap();
        (stack, h)
    }

    /// Offer a segment from `REMOTE_END` to `LOCAL_END` to the stack's
    /// listeners the way `process_tcp` does, returning whether it was consumed.
    #[cfg(feature = "tcp-listener")]
    fn listener_deliver(stack: &mut Stack, repr: &TcpRepr) -> bool {
        listener_deliver_to(stack, LOCAL_ADDR, repr)
    }

    /// Like [`listener_deliver`], with an explicit destination address.
    #[cfg(feature = "tcp-listener")]
    fn listener_deliver_to(stack: &mut Stack, dst_addr: Ipv4Address, repr: &TcpRepr) -> bool {
        process_listeners(
            &mut stack.sockets.tcp_listeners,
            IfaceHandle::new(0),
            &IpAddress::from(REMOTE_ADDR),
            &IpAddress::from(dst_addr),
            repr,
        )
    }

    #[cfg(feature = "tcp-listener")]
    fn syn_repr() -> TcpRepr<'static> {
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_listen_validation() {
        let mut stack = test_stack();
        let h1 = stack.add_tcp_listener().unwrap();
        let h2 = stack.add_tcp_listener().unwrap();

        assert_eq!(stack.tcp_listener(h1).listen(0), Err(ListenError::Unaddressable));
        assert_eq!(stack.tcp_listener(h1).listen(80), Ok(()));
        assert!(stack.tcp_listener(h1).is_open());
        // Re-listening on the same endpoint is a no-op...
        assert_eq!(stack.tcp_listener(h1).listen(80), Ok(()));
        // ...but a different one is an error.
        assert_eq!(stack.tcp_listener(h1).listen(81), Err(ListenError::InvalidState));

        // An identical sibling bind is rejected. The same port with a
        // different (more specific) address is fine, the most specific match
        // wins.
        assert_eq!(stack.tcp_listener(h2).listen(80), Err(ListenError::InUse));
        assert_eq!(stack.tcp_listener(h2).listen((LOCAL_ADDR, 80)), Ok(()));

        // Free a slot first: without `alloc` the listener slab is small.
        stack.remove_tcp_listener(h1);
        let h3 = stack.add_tcp_listener().unwrap();
        assert_eq!(stack.tcp_listener(h3).listen((LOCAL_ADDR, 80)), Err(ListenError::InUse));
        assert_eq!(stack.tcp_listener(h3).listen(81), Ok(()));
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_syn_and_accept() {
        let (mut stack, h) = listener_stack();

        // A SYN is recorded in the accept queue, nothing is transmitted.
        assert!(!stack.tcp_listener(h).can_accept());
        assert!(listener_deliver(&mut stack, &syn_repr()));
        assert!(stack.tcp_listener(h).can_accept());

        // Accept allocates the actual socket, in SYN-RECEIVED.
        let sh = stack
            .tcp_listener(h)
            .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        assert!(!stack.tcp_listener(h).can_accept());
        assert!(
            stack
                .tcp_listener(h)
                .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
                .is_none()
        );
        assert_eq!(stack.tcp_socket(sh).state(), State::SynReceived);
        assert_eq!(stack.tcp_socket(sh).local_endpoint(), Some(LOCAL_END));
        assert_eq!(stack.tcp_socket(sh).remote_endpoint(), Some(REMOTE_END));

        // The accepted socket is exactly a SYN-RECEIVED socket: it sends the
        // SYN|ACK, advertising its actual receive window, and completes the
        // handshake like any other socket.
        let mut s = TestSocket {
            sockets: {
                let mut sockets = Slab::new();
                sockets.add_with(|_| stack.sockets.tcp.take(sh.index())).unwrap();
                sockets
            },
            stack,
        };
        sanity!(&s, &socket_syn_received());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_established());
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_accept_with_socket() {
        let (mut stack, h) = listener_stack();
        let sh = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();

        // Nothing queued yet.
        assert_eq!(
            stack.tcp_listener(h).accept_with_socket(sh),
            Err(AcceptError::Exhausted)
        );

        // The queued SYN is accepted into the existing socket, which keeps its
        // handle.
        assert!(listener_deliver(&mut stack, &syn_repr()));
        assert_eq!(stack.tcp_listener(h).accept_with_socket(sh), Ok(()));
        assert!(!stack.tcp_listener(h).can_accept());
        assert_eq!(stack.tcp_socket(sh).state(), State::SynReceived);
        assert_eq!(stack.tcp_socket(sh).local_endpoint(), Some(LOCAL_END));
        assert_eq!(stack.tcp_socket(sh).remote_endpoint(), Some(REMOTE_END));

        // The socket is in use now: the next attempt is rejected and stays queued.
        assert!(listener_deliver(
            &mut stack,
            &TcpRepr {
                src_port: REMOTE_PORT + 1,
                ..syn_repr()
            }
        ));
        assert_eq!(
            stack.tcp_listener(h).accept_with_socket(sh),
            Err(AcceptError::InvalidState)
        );
        assert!(stack.tcp_listener(h).can_accept());

        // Once the connection is over, the same socket serves the next one,
        // with the previous connection's state gone.
        assert_eq!(
            stack.sockets.tcp.get_mut(sh.index()).tx_buffer.enqueue_slice(b"stale"),
            5
        );
        stack.tcp_socket(sh).abort();
        assert_eq!(stack.tcp_listener(h).accept_with_socket(sh), Ok(()));
        assert_eq!(stack.tcp_socket(sh).state(), State::SynReceived);
        assert_eq!(
            stack.tcp_socket(sh).remote_endpoint(),
            Some(IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT + 1))
        );
        assert!(stack.sockets.tcp.get(sh.index()).tx_buffer.is_empty());
    }

    // =========================================================================================//
    // Tests for interface binding.
    // =========================================================================================//

    #[cfg(feature = "iface-bind")]
    const LOCAL2_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 2, 1);
    #[cfg(feature = "iface-bind")]
    const REMOTE2_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 2, 2);

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
        let (mut stack, if0, if1, tx0, tx1) = stack_with_two_ifaces();
        let h = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        assert_eq!(stack.tcp_socket(h).bound_iface(), None);
        stack.tcp_socket(h).bind_to_iface(Some(if1)).unwrap();
        assert_eq!(stack.tcp_socket(h).bound_iface(), Some(if1));

        // The remote is on-link for interface 0 only: a socket bound to
        // interface 1 has no route to it.
        assert_eq!(
            stack.tcp_socket(h).connect((REMOTE_ADDR, REMOTE_PORT), 0),
            Err(ConnectError::Unaddressable)
        );

        // A remote on the bound interface's subnet connects, with the local
        // address resolved from the bound interface.
        stack.tcp_socket(h).connect((REMOTE2_ADDR, REMOTE_PORT), 0).unwrap();
        assert_eq!(
            stack.tcp_socket(h).local_endpoint().map(|e| e.addr),
            Some(LOCAL2_ADDR.into())
        );

        // The binding cannot change while the socket is open.
        assert_eq!(stack.tcp_socket(h).bind_to_iface(None), Err(ConnectError::InvalidState));

        // Ingress demux only matches the socket on the bound interface.
        assert!(stack.sockets.tcp.get(h.index()).binding_matches(if1));
        assert!(!stack.sockets.tcp.get(h.index()).binding_matches(if0));

        // The SYN goes out of the bound interface.
        stack.poll(Instant::from_millis(0));
        assert!(tx0.borrow().is_empty());
        assert_eq!(tx1.borrow().len(), 1);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_connect_conflicts_iface_bound() {
        // The binding is part of the socket's identity: the identical 4-tuple
        // bound to different interfaces (or one bound, one not) coexists.
        let (mut stack, _, if1, _, _) = stack_with_two_ifaces();
        let local = (LOCAL2_ADDR, LOCAL_PORT);
        let remote = (REMOTE2_ADDR, REMOTE_PORT);

        let h1 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(h1).bind_to_iface(Some(if1)).unwrap();
        stack.tcp_socket(h1).connect(remote, local).unwrap();

        let h2 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(h2).connect(remote, local).unwrap();

        let h3 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(h3).bind_to_iface(Some(if1)).unwrap();
        assert_eq!(stack.tcp_socket(h3).connect(remote, local), Err(ConnectError::InUse));
    }

    /// Like [`listener_deliver`], with an explicit arrival interface.
    #[cfg(all(feature = "tcp-listener", feature = "iface-bind"))]
    fn listener_deliver_on(stack: &mut Stack, iface: IfaceHandle, repr: &TcpRepr) -> bool {
        process_listeners(
            &mut stack.sockets.tcp_listeners,
            iface,
            &IpAddress::from(REMOTE_ADDR),
            &IpAddress::from(LOCAL_ADDR),
            repr,
        )
    }

    #[cfg(all(feature = "tcp-listener", feature = "iface-bind"))]
    #[test]
    fn test_listener_bind_to_iface() {
        let mut stack = test_stack();
        let if0 = IfaceHandle::new(0);
        let if1 = IfaceHandle::new(1);

        let h = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h).bind_to_iface(Some(if0)).unwrap();
        assert_eq!(stack.tcp_listener(h).bound_iface(), Some(if0));
        stack.tcp_listener(h).listen(LOCAL_PORT).unwrap();
        assert_eq!(
            stack.tcp_listener(h).bind_to_iface(None),
            Err(ListenError::InvalidState)
        );

        // A SYN arriving on another interface is not recorded.
        assert!(!listener_deliver_on(&mut stack, if1, &syn_repr()));
        assert!(!stack.tcp_listener(h).can_accept());

        // On the bound interface it is, and the accepted socket inherits the
        // binding, overwriting the socket's own.
        assert!(listener_deliver_on(&mut stack, if0, &syn_repr()));
        let sh = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(sh).bind_to_iface(Some(if1)).unwrap();
        stack.tcp_listener(h).accept_with_socket(sh).unwrap();
        assert_eq!(stack.tcp_socket(sh).bound_iface(), Some(if0));

        // The binding survives close, and is part of the listen identity: an
        // identical endpoint bound to another interface (or unbound) coexists,
        // the identical binding conflicts.
        stack.tcp_listener(h).close();
        assert_eq!(stack.tcp_listener(h).bound_iface(), Some(if0));
        stack.tcp_listener(h).listen(LOCAL_PORT).unwrap();
        let h2 = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h2).listen(LOCAL_PORT).unwrap();
        stack.tcp_listener(h2).close();
        stack.tcp_listener(h2).bind_to_iface(Some(if0)).unwrap();
        assert_eq!(stack.tcp_listener(h2).listen(LOCAL_PORT), Err(ListenError::InUse));
        stack.tcp_listener(h2).bind_to_iface(Some(if1)).unwrap();
        stack.tcp_listener(h2).listen(LOCAL_PORT).unwrap();
    }

    #[cfg(all(feature = "tcp-listener", feature = "iface-bind"))]
    #[test]
    fn test_listener_bind_to_iface_scoring() {
        // A listener bound to the arrival interface wins the SYN over an
        // unbound one with an equal endpoint.
        let mut stack = test_stack();
        let if0 = IfaceHandle::new(0);
        let if1 = IfaceHandle::new(1);

        let h_any = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h_any).listen(LOCAL_PORT).unwrap();
        let h_bound = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h_bound).bind_to_iface(Some(if0)).unwrap();
        stack.tcp_listener(h_bound).listen(LOCAL_PORT).unwrap();

        assert!(listener_deliver_on(&mut stack, if0, &syn_repr()));
        assert!(stack.tcp_listener(h_bound).can_accept());
        assert!(!stack.tcp_listener(h_any).can_accept());

        assert!(listener_deliver_on(&mut stack, if1, &syn_repr()));
        assert!(stack.tcp_listener(h_any).can_accept());
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_backlog_full_drops_syn() {
        let (mut stack, h) = listener_stack();

        // One more connection attempt than the backlog holds: the last SYN is
        // dropped, the others can all be accepted.
        for i in 0..TCP_LISTENER_BACKLOG + 1 {
            assert!(listener_deliver(
                &mut stack,
                &TcpRepr {
                    src_port: REMOTE_PORT + i as u16,
                    ..syn_repr()
                }
            ));
        }
        for _ in 0..TCP_LISTENER_BACKLOG {
            assert!(
                stack
                    .tcp_listener(h)
                    .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
                    .is_some()
            );
        }
        assert!(
            stack
                .tcp_listener(h)
                .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
                .is_none()
        );
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_syn_dedup() {
        let (mut stack, h) = listener_stack();

        // A retransmitted SYN updates the queue entry in place rather than
        // queueing a duplicate...
        assert!(listener_deliver(&mut stack, &syn_repr()));
        assert!(listener_deliver(&mut stack, &syn_repr()));
        // ...and a new connection attempt reusing the same ports (a new ISN)
        // replaces the stale entry: the newest SYN wins.
        assert!(listener_deliver(
            &mut stack,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 100,
                ..syn_repr()
            }
        ));

        let sh = stack
            .tcp_listener(h)
            .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        assert!(
            stack
                .tcp_listener(h)
                .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
                .is_none()
        );
        assert_eq!(stack.sockets.tcp.get(sh.index()).remote_seq_no, REMOTE_SEQ + 101);
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_rst_cancels_syn() {
        let (mut stack, h) = listener_stack();
        listener_deliver(&mut stack, &syn_repr());

        // An RST with the wrong sequence number is ignored (the only
        // acceptable one is exactly RCV.NXT)...
        assert!(!listener_deliver(
            &mut stack,
            &TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        ));
        assert!(stack.tcp_listener(h).can_accept());

        // ...an exact RST removes the queued SYN.
        assert!(listener_deliver(
            &mut stack,
            &TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        ));
        assert!(!stack.tcp_listener(h).can_accept());
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_addr_filter() {
        // A listener bound to a specific address ignores SYNs to other
        // addresses.
        let mut stack = test_stack();
        let h = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h).listen((OTHER_ADDR, LOCAL_PORT)).unwrap();
        assert!(!listener_deliver(&mut stack, &syn_repr()));

        // Bound to the address the SYN targets, it records it.
        stack.tcp_listener(h).close();
        stack.tcp_listener(h).listen((LOCAL_ADDR, LOCAL_PORT)).unwrap();
        assert!(listener_deliver(&mut stack, &syn_repr()));
        assert!(stack.tcp_listener(h).can_accept());
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_priority() {
        // Among listeners on the same port, an exact local-address match beats
        // a wildcard one, regardless of creation order.
        let mut stack = test_stack();
        let h_any = stack.add_tcp_listener().unwrap();
        let h_addr = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(h_any).listen(LOCAL_PORT).unwrap();
        stack.tcp_listener(h_addr).listen((LOCAL_ADDR, LOCAL_PORT)).unwrap();

        // A SYN to the listened address goes to the specific listener...
        assert!(listener_deliver(&mut stack, &syn_repr()));
        assert!(stack.tcp_listener(h_addr).can_accept());
        assert!(!stack.tcp_listener(h_any).can_accept());

        // ...a SYN to any other address to the wildcard one.
        assert!(listener_deliver_to(&mut stack, OTHER_ADDR, &syn_repr()));
        assert!(stack.tcp_listener(h_any).can_accept());
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_syn_mss() {
        // A tiny MSS is clamped, and a zero MSS is treated as absent.
        for (sent, effective) in [
            (Some(10), MIN_REMOTE_MSS),
            (Some(0), DEFAULT_MSS),
            (None, DEFAULT_MSS),
            (Some(1000), 1000),
        ] {
            let (mut stack, h) = listener_stack();
            assert!(listener_deliver(
                &mut stack,
                &TcpRepr {
                    max_seg_size: sent,
                    ..syn_repr()
                }
            ));
            let sh = stack
                .tcp_listener(h)
                .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
                .unwrap();
            assert_eq!(stack.sockets.tcp.get(sh.index()).remote_mss, effective);
        }
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_window_scaling() {
        // When the remote offers window scaling, the accepted socket's shift
        // comes from its actual rx buffer capacity, and the SYN|ACK advertises
        // it (with the unscaled real window).
        for (buffer_size, shift) in [(64, 0), (65535, 0), (65536, 1), (1048576, 5)] {
            let (mut stack, h) = listener_stack();
            assert!(listener_deliver(
                &mut stack,
                &TcpRepr {
                    window_scale: Some(7),
                    ..syn_repr()
                }
            ));
            let sh = stack
                .tcp_listener(h)
                .accept_with_bufs(vec![0; buffer_size].leak(), vec![0; 64].leak())
                .unwrap();
            assert_eq!(stack.sockets.tcp.get(sh.index()).remote_win_scale, Some(7));
            assert_eq!(stack.sockets.tcp.get(sh.index()).remote_win_shift, shift);

            let mut s = TestSocket {
                sockets: {
                    let mut sockets = Slab::new();
                    sockets.add_with(|_| stack.sockets.tcp.take(sh.index())).unwrap();
                    sockets
                },
                stack,
            };
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(shift),
                    window_len: u16::try_from(buffer_size).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }

        // Without an offer from the remote, scaling is off entirely.
        let (mut stack, h) = listener_stack();
        assert!(listener_deliver(&mut stack, &syn_repr()));
        let sh = stack
            .tcp_listener(h)
            .accept_with_bufs(vec![0; 65536].leak(), vec![0; 64].leak())
            .unwrap();
        assert_eq!(stack.sockets.tcp.get(sh.index()).remote_win_scale, None);
        assert_eq!(stack.sockets.tcp.get(sh.index()).remote_win_shift, 0);
        let mut s = TestSocket {
            sockets: {
                let mut sockets = Slab::new();
                sockets.add_with(|_| stack.sockets.tcp.take(sh.index())).unwrap();
                sockets
            },
            stack,
        };
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                window_len: u16::MAX,
                ..RECV_TEMPL
            }]
        );
    }

    #[cfg(feature = "tcp-listener")]
    #[test]
    fn test_listener_close_drops_syns() {
        let (mut stack, h) = listener_stack();
        listener_deliver(&mut stack, &syn_repr());
        assert!(stack.tcp_listener(h).can_accept());

        stack.tcp_listener(h).close();
        assert!(!stack.tcp_listener(h).is_open());
        assert!(!stack.tcp_listener(h).can_accept());
        assert!(!listener_deliver(&mut stack, &syn_repr()));
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.view().connect((IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        // An unspecified local address of the other IP version is not a wildcard,
        // it is a contradiction.
        assert_eq!(
            s.view().connect(REMOTE_END, (OTHER_VERSION_ANY, LOCAL_PORT)),
            Err(ConnectError::Unaddressable)
        );
        s.view()
            .connect(REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));

        // An unspecified local address of the connection's own version means
        // "select it automatically", like leaving it out entirely.
        let mut s = socket();
        s.view()
            .connect(REMOTE_END, (IpvXAddress::UNSPECIFIED, LOCAL_PORT))
            .expect("Connect failed with auto-selected local address");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                #[cfg(feature = "tcp-timestamps")]
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_synack_tiny_mss_is_clamped() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                #[cfg(feature = "tcp-timestamps")]
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, MIN_REMOTE_MSS);
    }

    #[test]
    fn test_connect_synack_zero_mss_is_ignored() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                #[cfg(feature = "tcp-timestamps")]
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(0),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, DEFAULT_MSS);
    }

    /// RFC 2018: If the data receiver has not received a SACK-Permitted option
    /// for a given connection, it MUST NOT send SACK options on that connection.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_connect_sack_not_offered_by_remote() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // Ensure the remote rejecting SACK results in SACK options not being sent.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );

        assert!(!s.remote_has_sack);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );

        assert_eq!(s.state, State::Established);
        sack_ranges_are_never_emitted(&mut s);
    }

    /// RFC 2018: If the data receiver has not received a SACK-Permitted option
    /// for a given connection, it MUST NOT send SACK options on that connection.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_syn_received_sack_not_offered_by_remote() {
        let mut s = socket_syn_received();

        // Ensure the remote not sending SACK results in SACK options not being sent.
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: false,
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sack_ranges_are_never_emitted(&mut s);
    }

    // Ensure that SACK ranges are not attached to ACKs after receiving out of
    // order segments. These segment should exist within the assembler however.
    #[cfg(feature = "tcp-sack")]
    fn sack_ranges_are_never_emitted(mut s: &mut TestSocket) {
        for offset in [6, 18] {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"abcdef",
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    sack_ranges: [None, None, None],
                    ..RECV_TEMPL
                })
            );
        }

        // No option space is reserved, so the MSS is not reduced.
        assert_eq!(s.sack_range_count(), 0);

        // The dispatch path is gated by the same conjunction.
        s.view().send_slice(b"x").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        assert_eq!(s.assembler.iter_data().count(), 2);
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.view().connect(REMOTE_END, 80), Ok(()));
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(s.view().connect(REMOTE_END, (REMOTE_ADDR, 80)), Ok(()));
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.view().connect(REMOTE_END, 80), Ok(()));
        assert_eq!(s.view().connect(REMOTE_END, 80), Err(ConnectError::InvalidState));
    }

    #[test]
    fn test_connect_ephemeral_port() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h1 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        let h2 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();

        // Local port 0 allocates an ephemeral port. (The explicit local address
        // avoids needing an interface for source address selection.)
        stack.tcp_socket(h1).connect(REMOTE_END, (LOCAL_ADDR, 0)).unwrap();
        let p1 = stack.tcp_socket(h1).local_endpoint().unwrap().port;
        assert!(p1 >= EPHEMERAL_PORT_MIN);

        // A second connection to the same remote would duplicate the 4-tuple,
        // so the allocation skips the port the first socket claimed.
        stack.tcp_socket(h2).connect(REMOTE_END, (LOCAL_ADDR, 0)).unwrap();
        let p2 = stack.tcp_socket(h2).local_endpoint().unwrap().port;
        assert!(p2 >= EPHEMERAL_PORT_MIN);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_connect_tuple_conflicts() {
        const OTHER_REMOTE_END: IpEndpoint = IpEndpoint {
            addr: IpAddress::Ipv4(OTHER_ADDR),
            port: REMOTE_PORT,
        };

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h1 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        let h2 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        let h3 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        let h4 = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();

        stack
            .tcp_socket(h1)
            .connect(REMOTE_END, (LOCAL_ADDR, LOCAL_PORT))
            .unwrap();

        // Only the full 4-tuple must be unique: the same local endpoint may
        // connect to a different remote...
        stack
            .tcp_socket(h2)
            .connect(OTHER_REMOTE_END, (LOCAL_ADDR, LOCAL_PORT))
            .unwrap();
        // ...and a different local address may connect to the same remote.
        stack
            .tcp_socket(h3)
            .connect(REMOTE_END, (OTHER_ADDR, LOCAL_PORT))
            .unwrap();

        // The identical 4-tuple is rejected.
        assert_eq!(
            stack.tcp_socket(h4).connect(REMOTE_END, (LOCAL_ADDR, LOCAL_PORT)),
            Err(ConnectError::InUse)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 1001,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.view().close();
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.view().connect(REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    #[cfg(feature = "tcp-sack")]
                    sack_permitted: true,
                    #[cfg(feature = "tcp-timestamps")]
                    timestamp: Some(TcpTimestampRepr::new(0, 0)),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    #[test]
    fn test_peek_slice() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        // Populate the recv buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &send_buf[..],
                ..SEND_TEMPL
            }
        );

        // Peek into the recv buffer
        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.view().peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.view().recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(&mut peeked_buf[..actually_peeked], &mut recv_buf[..actually_recvd]);
    }

    #[test]
    fn test_peek_slice_buffer_wrap() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456789";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        let _ = s.rx_buffer.enqueue_slice(&send_buf[..8]);
        let _ = s.rx_buffer.dequeue_many(6);
        let _ = s.rx_buffer.enqueue_slice(&send_buf[..5]);

        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.view().peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.view().recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(&mut peeked_buf[..actually_peeked], &mut recv_buf[..actually_recvd]);
    }

    /// Case:
    /// The remote sequence space straddles the u32 wrap and two islands
    /// are created. One straddling the boundary and another past it.
    ///
    /// Outcome:
    /// The SACK ranges are reported correctly with no overflow.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_established_sack_no_overflow_on_near_max_seqnumber() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.remote_seq_no = TcpSeqNumber(-4);
        s.remote_last_ack = Some(TcpSeqNumber(-4));

        // Create first island - [-2..2) - and SACK reports it
        send!(
            s,
            TcpRepr {
                seq_number: TcpSeqNumber(-2),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"AAAA"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(-4)),
                window_len: 64,
                sack_ranges: [Some((u32::MAX - 1, 2)), None, None],
                ..RECV_TEMPL
            })
        );

        // Create second island - [6..10) - and SACK reports both
        send!(
            s,
            TcpRepr {
                seq_number: TcpSeqNumber(6),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"BBBB"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(-4)),
                window_len: 64,
                sack_ranges: [Some((6, 10)), Some((u32::MAX - 1, 2)), None],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.len(), 0);
        s.rx_buffer = SocketBuffer::new(vec![0; 262143].leak());
        s.assembler = Assembler::new();
        s.remote_win_scale = Some(0);
        s.remote_last_win = 65535;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.view().send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.view().set_nagle_enabled(false);
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.view().send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.view().send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.view().send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.view()
            .recv(|data| {
                assert_eq!(data, b"def");
                (3, ())
            })
            .unwrap();
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.view()
            .recv(|data| {
                assert_eq!(data, b"def");
                (3, ())
            })
            .unwrap();

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after adding its data to the assembler.
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.view().send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_old_data_ack_not_rate_limited() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abcdef");
                (6, ())
            })
            .unwrap();
        // The remote retransmits data we already acknowledged, e.g. because
        // the ACK above was lost. Each retransmission must elicit a duplicate
        // ACK, even within the challenge ACK rate limit window: withholding it
        // strands the remote in retransmission backoff.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            time 200,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_bad_seq_rst_dropped_silently() {
        let mut s = socket_established();
        // Out-of-window RSTs are silently dropped, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2): no challenge ACK, no state change.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);

        // A payload doesn't make it eligible for the data segment exemption
        // from challenge ACK rate limiting either: still no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_bad_seq_syn_with_data_rate_limited() {
        let mut s = socket_established();
        // An out-of-window SYN carrying data must not be exempt from challenge
        // ACK rate limiting: RFC 5961 (4.2) says challenge ACKs sent in
        // response to SYNs should be throttled.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        // The second one within the rate limit window gets no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_established_options_reduce_payload_when_local_mss_limited() {
        const EFFECTIVE_MSS: usize = 64;

        // construct socket where remote MSS is less than local MSS
        let mut s = socket_established();
        s.timestamps = true;
        s.remote_mss = EFFECTIVE_MSS;

        // Payload should contain 12 bytes less due to timestamp
        s.view().send_slice(&[0; EFFECTIVE_MSS]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_established_options_reduce_payload_when_remote_mss_limited() {
        const EFFECTIVE_MSS: usize = BASE_MSS as usize;

        // construct socket where remote MSS is more than local MSS
        let mut s = socket_established_with_buffer_sizes(EFFECTIVE_MSS, 64);
        s.timestamps = true;
        s.remote_mss = 9999;
        s.remote_win_len = 9999;

        // Payload should contain 12 bytes less due to timestamp
        s.view().send_slice(&[0; EFFECTIVE_MSS]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_mss_derived_from_iface_mtu() {
        // A device with an MTU smaller than a packet buffer.
        const MTU: usize = 576;
        const MTU_MSS: usize = MTU - IPV4_HEADER_LEN - TCP_HEADER_LEN;

        let mut s = socket_with_buffer_sizes(2048, 64);
        s.stack = Stack::new(0x1234_5678_dead_beef);
        let handle = TestDevice::new(Medium::Ip)
            .with_mtu(MTU)
            .install(&mut s.stack, HardwareAddress::Ip);
        s.stack
            .iface(handle)
            .add_ip_addr(IpCidr::new(LOCAL_ADDR.into(), 24))
            .unwrap();
        s.state = State::SynSent;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;

        // The SYN advertises the MSS derived from the egress interface's MTU.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(MTU_MSS as u16),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // Complete the handshake. The remote's MSS and window are no constraint.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(2000),
                window_scale: Some(0),
                window_len: 4096,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Established);

        // Data is segmented at the MTU-derived MSS, not the remote's 2000.
        s.view().send_slice(&[0; MTU_MSS * 2]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MTU_MSS],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + MTU_MSS,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MTU_MSS],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_established_tiny_mss_with_options_makes_progress() {
        // Connect with timestamps enabled to a remote advertising an absurdly
        // small MSS. Without the MIN_SND_MSS clamp, an MSS smaller than the
        // options length would result in an effective MSS of zero, sending
        // empty segments in a loop without ever making progress.
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, MIN_REMOTE_MSS);

        s.view().send_slice(&[0; 64]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; MIN_REMOTE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(0, 500)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
                window_len: 52,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.view().abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        // Out-of-window RSTs are dropped silently, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2).
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Established);

        // An in-window RST still resets the connection.
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1, // Correct seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_bad_seq_challenge_ack_updated() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send the wrong seq again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/xarxa-rs/xarxa/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.view().send_slice(b"abcdef123456").unwrap();
        s.view().close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.view().close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.view().close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.view().close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.view().close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // A duplicate ACK (ack_number == SND.UNA, not the FIN ACK) must elicit a
        // challenge ACK per RFC 9293 §3.10.7.4 and must keep the state in LAST-ACK.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // RFC 9293 §3.10.7.4: duplicate ACK in LAST-ACK must elicit a challenge ACK,
    // not be silently dropped.
    #[test]
    fn test_last_ack_duplicate_ack_challenge_ack() {
        let mut s = socket_last_ack();
        // Trigger dispatch so our FIN is sent and remote_last_seq advances.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // Remote re-sends an ACK for SND.UNA (not the FIN).  RFC 9293 requires a
        // challenge ACK in response so the remote can learn the current state.
        let challenge = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
        );
        assert_eq!(
            challenge,
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }),
            "expected challenge ACK in response to duplicate ACK in LAST-ACK"
        );
        // State must remain LAST-ACK: we have not received the FIN ACK.
        assert_eq!(s.state, State::LastAck);

        // A second duplicate in the same second is rate-limited; the FIN ACK
        // must still be correctly accepted regardless.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // A partial ACK in LAST-ACK (ack_len > 0 but not FIN ACK) advances SND.UNA
    // without a challenge ACK; the FIN will be retransmitted by the timer.
    #[test]
    fn test_last_ack_partial_ack_no_challenge_ack() {
        // Build a LAST-ACK socket that has one byte of data still unacknowledged
        // before the FIN.  We manually wire the state so we can send a partial ACK.
        let mut s = socket_last_ack();
        // Push one byte into the tx buffer to simulate data that preceded the FIN.
        let _ = s.tx_buffer.enqueue_slice(b"x");
        // Mark it as already sent (remote_last_seq is past the data byte and the FIN).
        s.remote_last_seq = LOCAL_SEQ + 1 + 1 + 1; // data(1) + FIN(1)

        // Remote ACKs just the data byte, not the FIN (partial ACK).
        // ack_number = local_seq_no + 1  =>  ack_len = 1, ack_of_fin = false.
        // Per RFC 9293, a valid partial ACK should advance SND.UNA normally;
        // no challenge ACK should be emitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1), // acks the data byte, not FIN
                ..SEND_TEMPL
            }
        );
        // State remains LAST-ACK; FIN retransmission is handled by the timer.
        assert_eq!(s.state, State::LastAck);
        // SND.UNA has advanced to the partial ACK number.
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1 + 1);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.view().close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.view().close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        s.view().close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        s.view().close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_reset_clears_connection_state() {
        let mut s = socket_established();
        #[cfg(feature = "tcp-sack")]
        {
            s.remote_has_sack = true;
            s.local_rx_last_seq = Some(TcpSeqNumber(42));
        }
        s.local_rx_last_ack = Some(TcpSeqNumber(42));
        s.local_rx_dup_acks = 2;
        s.pending_fast_retransmit = true;
        #[cfg(feature = "tcp-timestamps")]
        {
            s.last_remote_tsval = 7;
        }

        s.reset();

        #[cfg(feature = "tcp-sack")]
        {
            assert!(!s.remote_has_sack);
            assert_eq!(s.local_rx_last_seq, None);
        }
        assert_eq!(s.local_rx_last_ack, None);
        assert_eq!(s.local_rx_dup_acks, 0);
        assert!(!s.pending_fast_retransmit);
        #[cfg(feature = "tcp-timestamps")]
        {
            assert_eq!(s.last_remote_tsval, 0);
        }
    }

    #[cfg(feature = "tcp-reno")]
    #[test]
    fn test_congestion_window_limits_data_in_flight() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        let data = [b'x'; 8192];
        s.view().send_slice(&data[..]).unwrap();

        // Reno's initial congestion window is 2048 bytes: only two
        // 1024-byte segments may be in flight, the rest must wait for ACKs.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // ACKing one segment frees congestion window space and grows
        // cwnd (slow start), allowing further segments out.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1024),
            window_len: 65535,
            ..SEND_TEMPL
        });
        recv!(s, time 10, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[cfg(feature = "tcp-reno")]
    #[test]
    fn test_congestion_window_doesnt_limit_fast_retransmit() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        let data = [b'x'; 8192];
        s.view().send_slice(&data[..]).unwrap();

        // Reno's initial congestion window is 2048 bytes, allowing 2 segments
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // Send three duplicate ACKS, treating the first segment as lost
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        // A fast retrnasmit should be sent and not be blocked by congestion control
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 2399);
        // The second packet should be re-sent.
        recv!(s, time 2400, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef012345").unwrap();
        s.view().close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.view().state(), State::Established);
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.view().send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.view().send_slice(b"abcdef").unwrap();
        s.view().send_slice(b"123456").unwrap();
        s.view().send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 3000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 3005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 3010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.view().send_slice(b"abcdef").unwrap();
        s.view().send_slice(b"123456").unwrap();
        s.view().send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.view().send_slice(b"abcdef").unwrap();
        s.view().send_slice(b"123456").unwrap();
        s.view().send_slice(b"ABCDEF").unwrap();
        s.view().close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 3;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.view().send_slice(b"aaaBBBcccDDDeeeFFF").unwrap();

        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // These packets arrive
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"BBB"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ccc"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"DDD"[..],
            ..RECV_TEMPL
        }));

        // Duplicate ACKs trigger fast rentramsit after 3rd successive one
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit should have triggered
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // Transmission should continue as normal after re-transitting the first segment
        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 4),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"eee"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 5),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"FFF"[..],
            ..RECV_TEMPL
        }));

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (3 * 5)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.view().send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.view().send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.view().send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.view().send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.view().send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx_buffer.is_empty());
        recv_nothing!(s, time 5000);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.view().close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 999);
        recv!(s, time 1000, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_established_with_buffer_sizes(32767, 64);
        // The remote advertised MSS 1000 in its SYN, and a 32767-byte window in
        // its handshake ACK: segments are capped at 1000 bytes.
        s.remote_mss = 1000;
        s.remote_win_len = 32767;
        s.view().send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_recv_out_of_recv_win() {
        let mut s = socket_established();
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        s.remote_mss = 32;

        // No ACKs are sent due to the ACK delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv_nothing!(s);

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 33,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 34),
                window_len: 31,
                ..RECV_TEMPL
            })
        );

        // This frees up a byte in the receive buffer. However, the remote shouldn't be aware of
        // this since no ACKs are sent.
        s.view().recv_slice(&mut [0; 1]).unwrap();
        recv_nothing!(s);

        // Now, if the remote wants to send one byte outside of the receive window that we
        // previously advertised, it should not succeed.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 34,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 65),
                window_len: 1, // The last byte isn't accepted.
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.view().recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.view().recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef").unwrap();
        s.view().send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_ack_not_rate_limited() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        // The remote retransmits into the zero window again within a second,
        // e.g. because the ACK above was lost. The ACK must not be withheld by
        // challenge ACK rate limiting: it is the remote's only way to learn
        // the window state, and a data segment cannot cause an ACK loop.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        s.ack_delay = None;

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // Even though the sequence space for the FIN itself is outside the window,
        // it is not data, so FIN must be accepted when window full.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 0);
        s.view()
            .recv(|buffer| {
                assert_eq!(&buffer[..3], b"abc");
                (3, ())
            })
            .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);
        s.view()
            .recv(|buffer| {
                assert_eq!(buffer, b"def");
                (buffer.len(), ())
            })
            .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_window_update_with_delay_ack() {
        let mut s = socket_established_with_buffer_sizes(6, 6);
        s.ack_delay = Some(Duration::from_millis(10));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 5);

        s.view()
            .recv(|buffer| {
                assert_eq!(&buffer[..2], b"ab");
                (2, ())
            })
            .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 2,
                ..RECV_TEMPL
            })
        );

        s.view()
            .recv(|buffer| {
                assert_eq!(&buffer[..1], b"c");
                (1, ())
            })
            .unwrap();
        recv_nothing!(s, time 5);

        s.view()
            .recv(|buffer| {
                assert_eq!(&buffer[..1], b"d");
                (1, ())
            })
            .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 4,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        // Test that `dispatch` updates `remote_last_win`
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.view().recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        // Provoke immediate ACK to test that `process` updates `remote_last_win`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.view().recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
    }

    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            time 1010,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1010,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[cfg(feature = "tcp-reno")]
    #[test]
    fn test_zero_window_probe_not_capped_by_cwnd() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        let data = [b'x'; 4096];
        s.view().send_slice(&data[..]).unwrap();

        // Reno's initial cwnd is 2048: two segments fill the congestion window
        // exactly, leaving cwnd_remaining() == 0.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // The remote closes its window without acknowledging anything new, so
        // no congestion window space is freed either.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });

        // Arm the probe timer. (Set directly because the ACK above carries no
        // new data; in real traffic this state is reached e.g. when the
        // controller shrinks cwnd below the flight size while probing.)
        s.timer
            .set_for_zero_window_probe(Instant::from_millis(10), Duration::from_millis(100));

        // The probe must carry 1 byte of data past the window edge even though
        // the congestion window is exhausted: an empty probe occupies no
        // sequence space and elicits no reply, so the connection would stall
        // if the remote's window update got lost.
        recv!(s, time 110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 1100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 6999);
        recv!(
            s,
            time 7000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.view().send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 3100+1000 = 4100
        recv_nothing!(s, time 4099);
        recv!(
            s,
            time 4100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        s.view().set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            #[cfg(feature = "tcp-sack")]
            sack_permitted: true,
            #[cfg(feature = "tcp-timestamps")]
            timestamp: Some(TcpTimestampRepr::new(150, 0)),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(250));
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            #[cfg(feature = "tcp-timestamps")]
            timestamp: Some(TcpTimestampRepr::new(250, 0)),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.view().set_timeout(Some(Duration::from_millis(2000)));
        recv_nothing!(s, time 250);
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(2250));
        s.view().send_slice(b"abcdef").unwrap();
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::MIN);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(1255));
        recv!(s, time 1255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(2255));
        recv!(s, time 2255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.view().set_keep_alive(Some(Duration::from_millis(50)));
        s.view().set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 100);
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(150));
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(155));
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 155);
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(205));
        recv_nothing!(s, time 200);
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 205);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.view().set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.view().set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.view().set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.view().abort();
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::MIN);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::MAX);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.view().set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::MIN);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(100));
        recv_nothing!(s, time 95);
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(200));
        recv_nothing!(s, time 195);
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.sockets.get_mut(0).poll_at(), Instant::from_millis(350));
        recv_nothing!(s, time 345);
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.view().set_hop_limit(Some(0x2a));
        assert_eq!(
            s.sockets
                .get_mut(0)
                .dispatch(&mut s.stack.tx_context(), |_, (_, _, _, hop_limit, _)| {
                    assert_eq!(hop_limit, 0x2a);
                    Ok::<_, ()>(())
                }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/xarxa-rs/xarxa/issues/601.
        s.reset();
        assert_eq!(s.view().hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.view().set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        s.view()
            .recv(|buffer| {
                assert_eq!(buffer, b"");
                (buffer.len(), ())
            })
            .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
        s.view()
            .recv(|buffer| {
                assert_eq!(buffer, b"abcdef");
                (buffer.len(), ())
            })
            .unwrap();
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.view()
            .recv(|buffer| {
                assert_eq!(buffer, b"abc");
                (buffer.len(), ())
            })
            .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 6];
        assert_eq!(s.view().recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();
        s.view().set_nagle_enabled(false);

        s.tx_buffer = SocketBuffer::new(vec![b'.'; 9].leak());
        assert_eq!(s.view().send_slice(b"xxxyyy"), Ok(6));
        assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
        assert_eq!(s.tx_buffer.len(), 3);

        // "abcdef" not contiguous in tx buffer. The segment straddles the ring's
        // wrap point, but is still sent as a single segment, in two chunks.
        assert_eq!(s.view().send_slice(b"abcdef"), Ok(6));
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"yyyabc"[..],
                payload2: &b"def"[..],
                ..RECV_TEMPL
            })
        );
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        s.view()
            .recv(|data| {
                assert_eq!(data, b"");
                (0, ())
            })
            .unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Error must be `Illegal` even if we've received a FIN,
        // because we are missing data.
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();
        assert_eq!(s.view().recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.view()
            .recv(|data| {
                assert_eq!(data, b"abc");
                (3, ())
            })
            .unwrap();

        s.view().send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS - 1) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.view().set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+2 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS - 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.view().send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.view().send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_nagle_works_with_reduced_payload_from_options() {
        const EFFECTIVE_MSS: usize = 64;

        let mut s = socket_established_with_buffer_sizes(256, 64);
        s.view().set_nagle_enabled(true);
        s.timestamps = true;
        s.remote_mss = EFFECTIVE_MSS;

        // Send small segment to "arm" Nagle's
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );

        // A full segment (once options are accounted for) should not be delayed and contain 12 bytes less due to timestamp
        s.view().send_slice(&[0; EFFECTIVE_MSS - 12]).unwrap();
        recv!(
            s,
            time 0,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.view().send_slice(b"abcdef0").unwrap();
        s.view().close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6].leak());
        s.assembler = Assembler::new();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(
            !s.sockets
                .get(0)
                .accepts(&REMOTE_ADDR.into(), &LOCAL_ADDR.into(), &tcp_repr)
        );

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(
            !s.sockets
                .get(0)
                .accepts(&REMOTE_ADDR.into(), &LOCAL_ADDR.into(), &tcp_repr)
        );
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        assert!(
            s.sockets
                .get(0)
                .accepts(&REMOTE_ADDR.into(), &LOCAL_ADDR.into(), &tcp_repr)
        );

        // Wrong source address.
        assert!(
            !s.sockets
                .get(0)
                .accepts(&OTHER_ADDR.into(), &LOCAL_ADDR.into(), &tcp_repr)
        );

        // Wrong destination address.
        assert!(
            !s.sockets
                .get(0)
                .accepts(&REMOTE_ADDR.into(), &OTHER_ADDR.into(), &tcp_repr)
        );
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle(Instant::from_millis(1301), None);
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        let rtos = &[
            6000, 5000, 4252, 3692, 3272, 2956, 2720, 2540, 2408, 2308, 2232, 2176, 2132, 2100, 2076, 2060, 2048, 2036,
            2028, 2024, 2020, 2016, 2012, 2012,
        ];

        for &rto in rtos {
            r.sample(2000);
            assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
        }
    }

    // =========================================================================================//
    // Timestamp tests
    // =========================================================================================//

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_tsval_established_connection() {
        let mut s = socket_established();
        s.timestamps = true;

        // First roundtrip after establishing.
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.view().send_slice(b"foobar").unwrap();
        recv!(
            s,
            time 100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                timestamp: Some(TcpTimestampRepr::new(100, 500)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_tsval_offset() {
        // The tsval is the clock plus the connection's random offset, so it
        // does not leak the time since boot. The sum wraps.
        let mut s = socket_established();
        s.timestamps = true;
        s.tsval_offset = 0xffff_ff00;

        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            time 500,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(0xffff_ff00u32.wrapping_add(500), 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[cfg(feature = "tcp-timestamps")]
    fn accepted_socket(syn: &TcpRepr) -> TestSocket {
        let (mut stack, h) = listener_stack();
        assert!(listener_deliver(&mut stack, syn));
        let sh = stack
            .tcp_listener(h)
            .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        TestSocket {
            sockets: {
                let mut sockets = Slab::new();
                sockets.add_with(|_| stack.sockets.tcp.take(sh.index())).unwrap();
                sockets
            },
            stack,
        }
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_tsval_in_accepted_socket() {
        // A SYN carrying a timestamp gets a SYN|ACK echoing its tsval.
        let mut s = accepted_socket(&TcpRepr {
            timestamp: Some(TcpTimestampRepr::new(500, 0)),
            ..syn_repr()
        });
        assert!(s.timestamps);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                timestamp: Some(TcpTimestampRepr::new(0, 500)),
                ..RECV_TEMPL
            }]
        );

        // A SYN without one gets a SYN|ACK without one: we only answer with
        // timestamps if the remote offered them.
        let mut s = accepted_socket(&syn_repr());
        assert!(!s.timestamps);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_tsval_enabled_by_handshake() {
        // Every connection we open offers timestamps, and a remote that answers
        // with one keeps them on for the rest of the connection.
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        assert!(s.timestamps);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(s.timestamps);
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(0, 500)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    #[cfg(feature = "tcp-timestamps")]
    fn test_tsval_disabled_in_remote_server() {
        // A remote that answers our SYN without a timestamp turns them off.
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
        assert!(s.timestamps);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                #[cfg(feature = "tcp-sack")]
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(0, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamps);
        s.view().send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for Selective Acknowledgements
    // =========================================================================================//

    /// Creates a SACK range from segment's left and right edges.
    #[cfg(feature = "tcp-sack")]
    fn block(left: usize, right: usize) -> Option<(u32, u32)> {
        Some(((REMOTE_SEQ + 1 + left).0 as u32, (REMOTE_SEQ + 1 + right).0 as u32))
    }

    /// Sets up a socket to the initial conditions used in the RFC 2018 test cases.
    ///
    /// RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
    /// segments, each containing 500 data bytes.
    #[cfg(feature = "tcp-sack")]
    fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
        setup_rfc2018_cases_with_rx_buffer(4000)
    }

    /// As `setup_rfc2018_cases()`, with the receive buffer size chosen by the caller.
    #[cfg(feature = "tcp-sack")]
    fn setup_rfc2018_cases_with_rx_buffer(rx_len: usize) -> (TestSocket, Vec<u8>) {
        let mut s = socket_established_with_buffer_sizes(4000, rx_len);
        s.remote_has_sack = true;

        // The window advertised while one 500 byte segment sits undrained.
        let win = (rx_len - 500) as u16;

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: win,
                    ..RECV_TEMPL
                }]
            );
            s.view()
                .recv(|data| {
                    assert_eq!(data.len(), 500);
                    assert_eq!(data, segment.as_slice());
                    (500, ())
                })
                .unwrap();
        }
        assert_eq!(s.remote_last_win, win);
        (s, segment)
    }

    /// Case:
    /// Following RFC 2018 setup, the first segment is dropped but the
    /// remaining 7 are received.
    ///
    /// Outcome:
    /// Upon receiving each of the last seven packets, the data receiver will
    /// return a TCP ACK segment that acknowledges sequence number 5000 and
    /// contains a SACK option specifying one block of queued data.
    ///
    ///                             +---------------+----------------+
    ///                             |          First Block           |
    /// +-------------+-------------+---------------+----------------+
    /// |    Segment  |     ACK     |   Left Edge   |   Right Edge   |
    /// +-------------+-------------+---------------+----------------|
    /// |    5000     |    (lost)   |               |                |
    /// |    5500     |    5000     |     5500      |      6000      |
    /// |    6000     |    5000     |     5500      |      6500      |
    /// |    6500     |    5000     |     5500      |      7000      |
    /// |    7000     |    5000     |     5500      |      7500      |
    /// |    7500     |    5000     |     5500      |      8000      |
    /// |    8000     |    5000     |     5500      |      8500      |
    /// |    8500     |    5000     |     5500      |      9000      |
    /// +-------------+-------------+---------------+----------------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_rfc2018_case_2() {
        let (mut s, segment) = setup_rfc2018_cases();

        for offset in (500..3500).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 4000,
                    sack_ranges: [block(5500, 5500 + offset), None, None],
                    ..RECV_TEMPL
                })
            );
        }
    }

    /// Case:
    /// Following RFC 2018 setup, the 2nd, 4th, 6th, and 8th (last) segments
    /// are dropped.
    ///
    /// Outcome:
    /// The data receiver ACKs the first packet normally.  The third, fifth, and
    /// seventh packets trigger SACK options.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |    5000    |   5500   |        |        |        |        |        |        |
    /// |    5500    |   (lost) |        |        |        |        |        |        |
    /// |    6000    |   5500   |  6000  |  6500  |        |        |        |        |
    /// |    6500    |   (lost) |        |        |        |        |        |        |
    /// |    7000    |   5500   |  7000  |  7500  |  6000  |  6500  |        |        |
    /// |    7500    |   (lost) |        |        |        |        |        |        |
    /// |    8000    |   5500   |  8000  |  8500  |  7000  |  7500  |  6000  |  6500  |
    /// |    8500    |   (lost) |        |        |        |        |        |        |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    ///
    /// Now, the 4th, 2nd and 6th (not specified in RFC test case) segments are
    /// received:
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |    6500    |   5500   |  6000  |  7500  |  8000  |  8500  |        |        |
    /// |    5500    |   7500   |  8000  |  8500  |        |        |        |        |
    /// |    7500    |   8500   |        |        |        |        |        |        |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_rfc2018_case_3() {
        let (mut s, segment) = setup_rfc2018_cases();

        // Segment 5000 advances the left edge.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 3500,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        // 5500 is lost. Segment 6000 opens an island. One SACK block should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 3500,
                sack_ranges: [block(6000, 6500), None, None],
                ..RECV_TEMPL
            })
        );

        // 6500 is lost. Segment 7000 opens a second island. Two SACK blocks should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 7000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 3500,
                sack_ranges: [block(7000, 7500), block(6000, 6500), None],
                ..RECV_TEMPL
            })
        );

        // 7500 is lost. Segment 8000 opens a third island. Three SACK blocks should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 3500,
                sack_ranges: [block(8000, 8500), block(7000, 7500), block(6000, 6500)],
                ..RECV_TEMPL
            })
        );

        // 6500 is received out of order. SACK ranges merge. Two SACK blocks should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 3500,
                sack_ranges: [block(6000, 7500), block(8000, 8500), None],
                ..RECV_TEMPL
            })
        );

        // 5500 is received out of order. Window advances. One SACK block should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7500),
                window_len: 1500,
                sack_ranges: [block(8000, 8500), None, None],
                ..RECV_TEMPL
            })
        );

        // 7500 is received. Window advances. No SACK blocks should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 7500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 8500),
                window_len: 500,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.local_sack_history, [None, None, None]);
    }

    /// Case:
    /// Following RFC 2018 setup, the 2nd, 4th and 6th segments are dropped. The
    ///  network reorders the survivors and then the remote transmits a pure ACK.
    ///
    /// Outcome:
    /// The data receiver ACKs the first segment normally. Each later segment
    /// triggers a SACK option and leads with its own block.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |    5000    |   5500   |        |        |        |        |        |        |
    /// |    5500    |   (lost) |        |        |        |        |        |        |
    /// |    8000    |   5500   |  8000  |  8500  |        |        |        |        |
    /// |    8500    |   5500   |  8000  |  9000  |        |        |        |        |
    /// |    7000    |   5500   |  7000  |  7500  |  8000  |  9000  |        |        |
    /// |    6000    |   5500   |  6000  |  6500  |  7000  |  7500  |  8000  |  9000  |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    ///
    /// A pure ACK from the transmitter now arrives. It carries no data and has a
    /// sequence number of 9000, right on the edge of the data held by the assembler.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// | (pure ACK) |   5500   |  6000  |  6500  |  7000  |  7500  |  8000  |  9000  |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_not_affected_by_pure_ack() {
        let (mut s, segment) = setup_rfc2018_cases_with_rx_buffer(5000);

        // Segment 5000 advances the left edge.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        // Segment 8000 arrives early and opens an island.
        // One SACK block should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(8000, 8500), None, None],
                ..RECV_TEMPL
            })
        );

        // Segment 8500 arrives early and increases the island width.
        // One SACK block should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(8000, 9000), None, None],
                ..RECV_TEMPL
            })
        );

        // Segment 7000 opens a second island.
        // Two SACK blocks should be reported.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 7000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(7000, 7500), block(8000, 9000), None],
                ..RECV_TEMPL
            })
        );

        // Segment 6000 arrives and opens an island.
        // Three SACK blocks should be reported, with [6000, 6500) being first.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(6000, 6500), block(7000, 7500), block(8000, 9000)],
                ..RECV_TEMPL
            })
        );

        // A pure ACK carrying the transmitter's snd_nxt of 9000. No payload.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 9000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                ..SEND_TEMPL
            }
        );

        // Transmitted data will contain the SACK ranges.
        // SACK ordering should remain the same as before, unaffected by the pure ACK.
        s.view().send_slice(b"x").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                payload: b"x",
                sack_ranges: [block(6000, 6500), block(7000, 7500), block(8000, 9000)],
                ..RECV_TEMPL
            }]
        );
    }

    /// Case:
    /// Following RFC 2018 setup, the 2nd, 4th and 6th segments are dropped. The
    /// network reorders the survivors and then a reordered pure ACK (SEQ < 9000) is
    /// delivered.
    ///
    ///
    /// Outcome:
    /// The data receiver ACKs the first segment normally. Each later segment
    /// triggers a SACK option and leads with its own block.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |    5000    |   5500   |        |        |        |        |        |        |
    /// |    5500    |   (lost) |        |        |        |        |        |        |
    /// |    8000    |   5500   |  8000  |  8500  |        |        |        |        |
    /// |    8500    |   5500   |  8000  |  9000  |        |        |        |        |
    /// |    7000    |   5500   |  7000  |  7500  |  8000  |  9000  |        |        |
    /// |    6000    |   5500   |  6000  |  6500  |  7000  |  7500  |  8000  |  9000  |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    ///
    /// A reordered pure ACK arrives, with a sequence number inside one of the ranges
    /// held by the assembler.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// | (pure ACK) |   5500   |  6000  |  6500  |  7000  |  7500  |  8000  |  9000  |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_not_affected_by_reordered_pure_ack() {
        let (mut s, segment) = setup_rfc2018_cases_with_rx_buffer(5000);

        // Segment 5000 advances the left edge.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        // Segment 8000 arrives early and opens an island.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(8000, 8500), None, None],
                ..RECV_TEMPL
            })
        );

        // Segment 8500 arrives early and increases the island width.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(8000, 9000), None, None],
                ..RECV_TEMPL
            })
        );

        // Segment 7000 opens a second island.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 7000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(7000, 7500), block(8000, 9000), None],
                ..RECV_TEMPL
            })
        );

        // Segment 6000 opens a third island and becomes the last data segment.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                sack_ranges: [block(6000, 6500), block(7000, 7500), block(8000, 9000)],
                ..RECV_TEMPL
            })
        );

        // The reordered pure ACK, carrying the snd_nxt of 8500 it was sent with.
        // No payload.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                ..SEND_TEMPL
            }
        );

        // Transmitted data will contain the SACK ranges.
        // SACK ordering should remain the same as before, unaffected by the pure ACK.
        s.view().send_slice(b"x").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 4500,
                payload: b"x",
                sack_ranges: [block(6000, 6500), block(7000, 7500), block(8000, 9000)],
                ..RECV_TEMPL
            }]
        );
    }

    /// Case:
    /// One island is held, so every outgoing ACK carries one SACK block. The socket
    /// then gets one MSS of data to send.
    ///
    /// Outcome:
    /// The data should be split into two segments, due to the length of the options.
    /// One full segment should be sent, and another carrying the remainder. One SACK
    /// block is 10 option bytes, padded to 12 on the wire. This test does not
    /// negotiate timestamps, so the option length is 12 and the remainder is also 12.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_emitted_on_data_segments() {
        const REMOTE_MSS: usize = 128;
        const ONE_BLOCK_OPTS: usize = 12;
        const SEG: usize = REMOTE_MSS - ONE_BLOCK_OPTS;

        let mut s = socket_established_with_buffer_sizes(SEG * 2, 1024);
        s.remote_has_sack = true;
        s.remote_mss = REMOTE_MSS;
        s.remote_win_len = 9999;
        s.view().set_nagle_enabled(false);

        //  Open an island 100 bytes past the left edge
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 100,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'a'; 100],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 1024,
                sack_ranges: [block(100, 200), None, None],
                ..RECV_TEMPL
            })
        );

        // One MSS of data should take two segments, due to effective MSS shrinkage from option length.
        s.view().send_slice(&[b'z'; REMOTE_MSS]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    window_len: 1024,
                    payload: &[b'z'; REMOTE_MSS - ONE_BLOCK_OPTS],
                    sack_ranges: [block(100, 200), None, None],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + (REMOTE_MSS - ONE_BLOCK_OPTS),
                    ack_number: Some(REMOTE_SEQ + 1),
                    window_len: 1024,
                    payload: &[b'z'; ONE_BLOCK_OPTS],
                    sack_ranges: [block(100, 200), None, None],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    /// Case:
    /// One island is held when the remote then closes its window. Data queues at the
    /// socket and a zero window probe is sent.
    ///
    /// Outcome:
    /// The zero window probe carries the previously announced SACK range.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_emitted_on_zero_window_probe() {
        let mut s = socket_established_with_buffer_sizes(64, 128);
        s.remote_has_sack = true;

        // A segment 20 bytes past the left edge opens one island
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 20,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'a'; 10],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 128,
                sack_ranges: [block(20, 30), None, None],
                ..RECV_TEMPL
            })
        );

        // Queued data plus a closed remote window arms the probe timer
        s.view().send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );
        assert!(s.timer.is_zero_window_probe());

        // Timer triggers and ZWP triggers containing the SACK ranges
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 128,
                payload: &b"a"[..],
                sack_ranges: [block(20, 30), None, None],
                ..RECV_TEMPL
            }]
        );
    }

    /// Case:
    /// Fill a 128 byte window with 96 contiguous bytes and a 10 byte out-of-order
    /// segment. Then, the application drains the buffer.
    ///
    /// Outcome:
    /// The buffer drain should cause a window update to be sent. This update should
    /// contain a SACK block and the window advertised should not include the bytes
    /// from the out-of-order segment.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_emitted_on_window_update() {
        let mut s = socket_established_with_buffer_sizes(64, 128);
        s.remote_has_sack = true;

        // Contiguous data to advance left edge and fill the buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'a'; 96],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 96),
                window_len: 32,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        // 10 bytes, out-of-order, to create an island in the assembler
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 106,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'b'; 10],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 96),
                window_len: 32,
                sack_ranges: [block(106, 116), None, None],
                ..RECV_TEMPL
            })
        );

        // Receiving the data should trigger a window update
        s.view().recv(|data| (data.len(), ())).unwrap();

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 96),
                window_len: 128,
                sack_ranges: [block(106, 116), None, None],
                ..RECV_TEMPL
            }]
        );
    }

    /// Case:
    /// Four islands arrive in reverse order: 8th, 6th, 4th then 2nd. Then, segment 1 is
    /// received.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +--------------+--------+--------+--------+--------+--------+--------+--------+
    /// |    Segment   |   ACK  |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +--------------+--------+--------+--------+--------+--------+--------+--------+
    /// |     8500     |  5000  |  8500  |  9000  |        |        |        |        |
    /// |     7500     |  5000  |  7500  |  8000  |  8500  |  9000  |        |        |
    /// |     6500     |  5000  |  6500  |  7000  |  7500  |  8000  |  8500  |  9000  |
    /// |     5500     |  5000  |  5500  |  6000  |  6500  |  7000  |  7500  |  8000  |
    /// |     5000     |  6000  |  6500  |  7000  |  7500  |  8000  |  8500  |  9000  |
    /// +--------------+--------+--------+--------+--------+--------+--------+--------+
    ///
    /// Outcome:
    /// Four islands should be held within the assembler, but only three blocks reported
    /// in the order that they were received. When segment 1 is received and advances
    /// the left edge, SACK ranges should now contain that fourth island.
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_reports_three_of_four_islands() {
        let (mut s, segment) = setup_rfc2018_cases_with_rx_buffer(5000);

        // Four islands in reverse order
        for (offset, expected) in [
            (8500, [block(8500, 9000), None, None]),
            (7500, [block(7500, 8000), block(8500, 9000), None]),
            (6500, [block(6500, 7000), block(7500, 8000), block(8500, 9000)]),
            (5500, [block(5500, 6000), block(6500, 7000), block(7500, 8000)]),
        ] {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 5000,
                    sack_ranges: expected,
                    ..RECV_TEMPL
                })
            );
        }

        assert_eq!(s.assembler.iter_data().count(), 4);

        // Advancing the left edge should remove one island and let another be reported
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6000),
                window_len: 4000,
                sack_ranges: [block(6500, 7000), block(7500, 8000), block(8500, 9000)],
                ..RECV_TEMPL
            })
        );
    }

    /// RFC 2018 defines the block edges as a half-open range:
    ///
    /// - Left Edge of Block: the first sequence number of this block.
    /// - Right Edge of Block: the sequence number immediately following the last
    ///   sequence number of this block.
    ///
    /// So the right edge names the first byte the receiver does NOT hold.
    ///
    /// Case:
    /// Two segments arrive with a gap of exactly one byte between them, at 6500.
    /// The one byte then arrives and closes the gap.
    ///
    /// Outcome:
    /// The first two arrivals must stay two separate blocks. A right edge of 6500
    /// that meant "6500 is held" would leave no gap, and the two would report as
    /// one block. The single byte at 6500 then merges them into one.
    ///
    ///                          +-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |
    /// +--------------+--------+--------+--------+--------+--------+
    /// |    Segment   |   ACK  |  Left  |  Right |  Left  |  Right |
    /// +--------------+--------+--------+--------+--------+--------+
    /// |  6000..6500  |  5000  |  6000  |  6500  |        |        |
    /// |  6501..7001  |  5000  |  6501  |  7001  |  6000  |  6500  |
    /// |  6500..6501  |  5000  |  6000  |  7001  |        |        |
    /// +--------------+--------+--------+--------+--------+--------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_is_an_exclusive_range() {
        let (mut s, segment) = setup_rfc2018_cases();

        // 500 bytes at 6000. The right edge is 6500, one past the last byte held.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5000),
                window_len: 4000,
                sack_ranges: [block(6000, 6500), None, None],
                ..RECV_TEMPL
            })
        );

        // 500 bytes at 6501, leaving exactly one byte missing at 6500. Two blocks,
        // so 6500 is confirmed absent from the first one.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6501,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5000),
                window_len: 4000,
                sack_ranges: [block(6501, 7001), block(6000, 6500), None],
                ..RECV_TEMPL
            })
        );

        // The one missing byte. Both islands become one, which is only possible if
        // 6500 was the gap and not part of either block.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6500,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment[..1],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5000),
                window_len: 4000,
                sack_ranges: [block(6000, 7001), None, None],
                ..RECV_TEMPL
            })
        );
    }

    /// Case:
    /// Following from RFC 2018 setup, every second segment is dropped, so each
    ///  arrival opens a new island. The assembler holds at most  `ASSEMBLER_MAX_SEGMENT_COUNT`
    /// islands, which `src/lib.rs` pins to 4 for test builds.
    ///
    /// Outcome:
    /// The data receiver ACKs the first segment normally. Each later arrival opens
    /// an island and leads with its own block. Only three blocks fit, so the
    /// island at 6000 stops being reported once a fourth one opens.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |    5000    |   5500   |        |        |        |        |        |        |
    /// |    5500    |   (lost) |        |        |        |        |        |        |
    /// |    6000    |   5500   |  6000  |  6500  |        |        |        |        |
    /// |    6500    |   (lost) |        |        |        |        |        |        |
    /// |    7000    |   5500   |  7000  |  7500  |  6000  |  6500  |        |        |
    /// |    7500    |   (lost) |        |        |        |        |        |        |
    /// |    8000    |   5500   |  8000  |  8500  |  7000  |  7500  |  6000  |  6500  |
    /// |    8500    |   (lost) |        |        |        |        |        |        |
    /// |    9000    |   5500   |  9000  |  9500  |  8000  |  8500  |  7000  |  7500  |
    /// |    9500    |   (lost) |        |        |        |        |        |        |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    ///
    /// The assembler now holds 4 islands and is full. Segment 10000 would open a
    /// fifth, so the assembler rejects it with `TooManyHolesError` and the payload
    /// is discarded. The segment still arrived out of order, so the immediate
    /// duplicate ACK of RFC 5681 goes out anyway, restating the held ranges.
    ///
    ///                          +-----------------+-----------------+-----------------+
    ///                          |   First Block   |  Second Block   |   Third Block   |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   Segment  |    ACK   |  Left  |  Right |  Left  |  Right |  Left  |  Right |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    /// |   10000    |   5500   |  9000  |  9500  |  8000  |  8500  |  7000  |  7500  |
    /// |  transmit  |   5500   |  9000  |  9500  |  8000  |  8500  |  7000  |  7500  |
    /// +------------+----------+--------+--------+--------+--------+--------+--------+
    #[test]
    #[cfg(feature = "tcp-sack")]
    fn test_sack_works_when_assembler_rejects_segment() {
        // The window must stay wide enough that segment 10000 is still inside it,
        // so the assembler turns it away rather than the window check.
        let (mut s, segment) = setup_rfc2018_cases_with_rx_buffer(6000);

        // Segment 5000 advances the left edge.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 5500,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            }]
        );

        // Every second segment is lost, so each arrival opens a fresh island.
        // The assembler is filled to capacity.
        for i in 0..4 {
            let offset = 6000 + i * 1000;
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5500),
                    window_len: 5500,
                    sack_ranges: [
                        block(offset, offset + 500),
                        (i >= 1).then(|| block(offset - 1000, offset - 500)).flatten(),
                        (i >= 2).then(|| block(offset - 2000, offset - 1500)).flatten(),
                    ],
                    ..RECV_TEMPL
                })
            );
        }

        let islands_before = s.assembler.iter_data().count();
        assert_eq!(islands_before, 4);

        let blocks_before = s.local_sack_history;

        // The assembler should reject this segment with `TooManyHolesError`.
        // The payload is dropped, but the out-of-order arrival still triggers
        // an immediate duplicate ACK restating the held ranges.
        let rejected = 10000;
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + rejected,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 5500,
                sack_ranges: [block(9000, 9500), block(8000, 8500), block(7000, 7500)],
                ..RECV_TEMPL
            })
        );

        // Assembler must not hold the segment
        assert_eq!(s.assembler.iter_data().count(), islands_before);
        assert!(!s.assembler.iter_data().any(|(l, _)| l == rejected - 5500));

        // The SACK history should not have changed
        assert_eq!(s.local_sack_history, blocks_before);

        // Transmitted data will contain the SACK ranges.
        // SACK ordering on the wire should remain as before, unaffected by the rejected segment.
        s.view().send_slice(b"x").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5500),
                window_len: 5500,
                payload: b"x",
                sack_ranges: blocks_before.map(|b| b.map(|(l, r)| (l.0 as u32, r.0 as u32))),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for source IP address change.
    // =========================================================================================//

    #[test]
    fn test_established_src_ip_change_drops_segments() {
        let mut s = socket_established();

        // Verify socket is working normally
        s.view().send_slice(b"abc").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abc"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 3),
                ..SEND_TEMPL
            }
        );

        // Simulate interface IP change - remove the socket's source IP
        // and add a different one.
        s.stack.ifaces.get_mut(0).ip_addrs.clear();
        s.stack
            .ifaces
            .get_mut(0)
            .ip_addrs
            .push(crate::iface::IfaceAddr::manual(IpCidr::new(OTHER_ADDR.into(), 24)))
            .unwrap();

        // The socket's source IP is no longer ours: dispatch treats it like a
        // routing failure. The segment is still built, but with no route, so
        // emit drops it. The socket stays open, and the retransmit timer owns
        // recovery in case the address comes back.
        s.view().send_slice(b"def").unwrap();
        let mut routes = vec![];
        let result: Result<(), ()> = s.sockets.get_mut(0).dispatch(
            &mut s.stack.tx_context(),
            |_, (route, _src_addr, _dst_addr, _hop_limit, _repr)| {
                routes.push(route.is_some());
                Ok(())
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(routes, [false], "segment should be emitted with no route");
        assert_eq!(s.state, State::Established);

        // Restoring the address makes egress work again, and the retransmission
        // carries the dropped data.
        s.stack.ifaces.get_mut(0).ip_addrs.clear();
        s.stack
            .ifaces
            .get_mut(0)
            .ip_addrs
            .push(crate::iface::IfaceAddr::manual(IpCidr::new(LOCAL_ADDR.into(), 24)))
            .unwrap();
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"def"[..],
            ..RECV_TEMPL
        }));
    }
}

#[cfg(all(test, feature = "medium-ip", feature = "ipv4"))]
mod stack_test {
    //! Stack-level tests: TCP segments travelling through the full ingress
    //! (`Stack::poll`) and egress paths, IP headers and checksums
    //! included.

    use super::*;
    use crate::iface::Medium;
    use crate::stack::Stack;
    use crate::test_device::TestDevice;
    use crate::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv4Packet};

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;

    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(100);
    /// The fixed initial sequence number `random_seq_no` returns in test builds.
    #[cfg_attr(not(feature = "tcp-listener"), allow(dead_code))]
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);

    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        #[cfg(feature = "tcp-sack")]
        sack_permitted: false,
        #[cfg(feature = "tcp-sack")]
        sack_ranges: [None, None, None],
        #[cfg(feature = "tcp-timestamps")]
        timestamp: None,
        payload: &[],
        payload2: &[],
    };

    fn stack() -> (Stack<'static>, TestDevice) {
        let driver = TestDevice::new(Medium::Ip);
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(handle)
            .add_ip_addr(IpCidr::new(LOCAL_ADDR.into(), 24))
            .unwrap();
        (stack, driver)
    }

    /// Build a full IPv4+TCP packet from the remote to the local endpoint,
    /// checksums filled, ready for injection into the device RX queue.
    fn tcp_packet(repr: &TcpRepr) -> Vec<u8> {
        let mut buf = build_tcp_packet(
            repr,
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        crate::stack::push_ipv4_header(
            &mut buf,
            REMOTE_ADDR,
            LOCAL_ADDR,
            IpProtocol::Tcp,
            64,
            &ChecksumCapabilities::default(),
        );
        buf.to_vec()
    }

    /// Parse a transmitted frame: verify the IP header, the TCP checksum, and the
    /// addressing, then run `f` on the TCP packet.
    #[track_caller]
    fn parse_tx(frame: &mut [u8], f: impl FnOnce(&TcpPacket<'_>)) {
        let header_len = {
            let ip = Ipv4Packet::new_checked(&mut frame[..]).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.next_header(), IpProtocol::Tcp);
            assert_eq!(ip.src_addr(), LOCAL_ADDR);
            assert_eq!(ip.dst_addr(), REMOTE_ADDR);
            ip.header_len() as usize
        };
        let tcp = TcpPacket::new_checked(&mut frame[header_len..]).unwrap();
        assert!(tcp.verify_checksum(&LOCAL_ADDR.into(), &REMOTE_ADDR.into()));
        assert_eq!(tcp.src_port(), LOCAL_PORT);
        assert_eq!(tcp.dst_port(), REMOTE_PORT);
        f(&tcp);
    }

    #[test]
    #[cfg(feature = "tcp-listener")]
    fn test_stack_handshake_data_and_close() {
        let (mut stack, driver) = stack();
        let lh = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(lh).listen(LOCAL_PORT).unwrap();

        // A SYN is recorded in the accept queue, nothing is transmitted until
        // the connection is accepted.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(0));
        assert!(driver.tx.borrow().is_empty());
        assert!(stack.tcp_listener(lh).can_accept());

        // Accept allocates the actual socket, and the next poll sends the
        // SYN|ACK, advertising the socket's actual receive window.
        let h = stack
            .tcp_listener(lh)
            .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(h).set_ack_delay(None);
        assert_eq!(stack.tcp_socket(h).state(), State::SynReceived);
        stack.poll(Instant::from_millis(0));
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.syn() && tcp.ack());
            assert_eq!(tcp.seq_number(), LOCAL_SEQ);
            assert_eq!(tcp.ack_number(), REMOTE_SEQ + 1);
            assert_eq!(tcp.window_len(), 64);
        });
        assert!(driver.tx.borrow().is_empty());

        // ACK of the SYN|ACK in: established.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(1));
        assert_eq!(stack.tcp_socket(h).state(), State::Established);
        assert!(driver.tx.borrow().is_empty());

        // Data in, ACK out, and the data is readable from the socket.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"hello",
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(2));
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert_eq!(tcp.ack_number(), REMOTE_SEQ + 1 + 5);
        });
        let mut data = [0; 8];
        assert_eq!(stack.tcp_socket(h).recv_slice(&mut data), Ok(5));
        assert_eq!(&data[..5], b"hello");

        // Data out: enqueued by send, transmitted by the next poll.
        assert_eq!(stack.tcp_socket(h).send_slice(b"world"), Ok(5));
        stack.poll(Instant::from_millis(3));
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.psh());
            assert_eq!(tcp.seq_number(), LOCAL_SEQ + 1);
            assert_eq!(tcp.payload(), b"world");
        });

        // ACK of the data in.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 5,
            ack_number: Some(LOCAL_SEQ + 1 + 5),
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(3));
        assert!(driver.tx.borrow().is_empty());

        // Close: the FIN is transmitted by the next poll.
        stack.tcp_socket(h).close();
        assert_eq!(stack.tcp_socket(h).state(), State::FinWait1);
        stack.poll(Instant::from_millis(4));
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.fin());
            assert_eq!(tcp.seq_number(), LOCAL_SEQ + 1 + 5);
        });
    }

    #[test]
    fn test_stack_rst_on_closed_port() {
        let (mut stack, driver) = stack();

        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(0));

        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.rst());
            assert_eq!(tcp.ack_number(), REMOTE_SEQ + 1);
        });

        // An incoming RST to a closed port is not answered.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(1));
        assert!(driver.tx.borrow().is_empty());
    }

    #[test]
    #[cfg(feature = "tcp-listener")]
    fn test_stack_established_socket_beats_listener() {
        // Set up an established connection through the listener.
        let (mut stack, driver) = stack();
        let lh = stack.add_tcp_listener().unwrap();
        stack.tcp_listener(lh).listen(LOCAL_PORT).unwrap();
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(0));
        let h = stack
            .tcp_listener(lh)
            .accept_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.poll(Instant::from_millis(0));
        driver.tx.borrow_mut().remove(0); // the SYN|ACK
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(1));
        assert_eq!(stack.tcp_socket(h).state(), State::Established);

        // A SYN matching the established connection's exact 4-tuple goes to
        // the connected socket (which discards it: it carries no ACK) and
        // never reaches the listener, so no new connection attempt is queued.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 100,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(2));
        assert!(!stack.tcp_listener(lh).can_accept());
        assert!(driver.tx.borrow().is_empty());

        // A SYN from a different source port reaches the listener.
        driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        }));
        stack.poll(Instant::from_millis(3));
        assert!(stack.tcp_listener(lh).can_accept());
    }

    #[test]
    fn test_stack_retransmission_timer() {
        let (mut stack, driver) = stack();
        let h = stack
            .add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak())
            .unwrap();
        stack.tcp_socket(h).set_ack_delay(None);
        stack
            .tcp_socket(h)
            .connect((REMOTE_ADDR, REMOTE_PORT), LOCAL_PORT)
            .unwrap();

        // The SYN is transmitted by the next poll, which returns the
        // retransmission deadline.
        let deadline = stack.poll(Instant::from_millis(0));
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.syn() && !tcp.ack());
        });
        assert!(driver.tx.borrow().is_empty());

        // No answer: polling past the deadline retransmits the SYN.
        stack.poll(deadline);
        let mut frame = driver.tx.borrow_mut().remove(0);
        parse_tx(&mut frame, |tcp| {
            assert!(tcp.syn() && !tcp.ack());
        });
    }
}
