/*! Time structures.

The `time` module contains structures used to represent both
absolute and relative time.

 - [Instant] is used to represent absolute time.
 - [Duration] is used to represent relative time.

Both count milliseconds in a `u32`. Their accessors are named and behave like the
ones on [`core::time::Duration`]: `as_*` returns the whole value, `subsec_*`
returns only the part below one second.

[Instant]: struct.Instant.html
[Duration]: struct.Duration.html
*/

use core::{cmp, fmt, ops};

/// A point in time.
///
/// An `Instant` counts milliseconds from an arbitrary starting point, such as
/// system startup. It wraps around to zero every 2<sup>32</sup> ms, about 49.7
/// days. To make one from a wider timestamp, keep its low 32 bits.
///
/// Comparisons take the wraparound into account. Of two instants less than
/// 2<sup>31</sup> ms (about 24.8 days) apart, the earlier one is the smaller one,
/// even if the counter wrapped around in between. Instants further apart than
/// that compare the wrong way around. This is why `Instant` implements
/// `PartialOrd` but not `Ord`.
///
/// The stack keeps every instant it holds close enough to the current time to
/// compare correctly, as long as [`Stack::poll`](crate::Stack::poll) is called
/// by the deadline it returns.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Instant {
    millis: u32,
}

impl Instant {
    /// The starting point.
    pub const ZERO: Instant = Instant::from_millis(0);

    /// Create a new `Instant` from a number of milliseconds.
    pub const fn from_millis(millis: u32) -> Instant {
        Instant { millis }
    }

    /// Create a new `Instant` from a number of seconds.
    ///
    /// Wraps around like the instant itself.
    pub const fn from_secs(secs: u32) -> Instant {
        Instant {
            millis: secs.wrapping_mul(1000),
        }
    }

    /// Create a new `Instant` from the current [std::time::SystemTime].
    ///
    /// Requires the `std` feature.
    ///
    /// See [std::time::SystemTime::now]
    ///
    /// [std::time::SystemTime]: https://doc.rust-lang.org/std/time/struct.SystemTime.html
    /// [std::time::SystemTime::now]: https://doc.rust-lang.org/std/time/struct.SystemTime.html#method.now
    #[cfg(feature = "std")]
    pub fn now() -> Instant {
        Self::from(::std::time::SystemTime::now())
    }

    /// The number of milliseconds since the starting point, wrapped around.
    pub const fn as_millis(&self) -> u32 {
        self.millis
    }

    /// The number of whole seconds in [`as_millis`](Self::as_millis).
    pub const fn as_secs(&self) -> u32 {
        self.millis / 1000
    }

    /// The number of milliseconds past [`as_secs`](Self::as_secs).
    ///
    /// Always less than 1000.
    pub const fn subsec_millis(&self) -> u32 {
        self.millis % 1000
    }

    /// The amount of time elapsed from `earlier` to this instant.
    ///
    /// Returns [`Duration::ZERO`] if `earlier` is later than this instant.
    /// Saturates at [`Duration::MAX`].
    pub const fn duration_since(&self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }

    /// The amount of time elapsed from `earlier` to this instant.
    ///
    /// Returns `None` if `earlier` is later than this instant. Saturates at
    /// [`Duration::MAX`].
    pub const fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        let elapsed = self.millis.wrapping_sub(earlier.millis);
        if (elapsed as i32) < 0 {
            None
        } else {
            Some(Duration::from_millis(elapsed))
        }
    }

    /// The amount of time elapsed from `earlier` to this instant.
    ///
    /// Returns [`Duration::ZERO`] if `earlier` is later than this instant.
    /// Saturates at [`Duration::MAX`].
    pub const fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        match self.checked_duration_since(earlier) {
            Some(elapsed) => elapsed,
            None => Duration::ZERO,
        }
    }

    /// The earlier of two instants.
    pub fn min(self, other: Instant) -> Instant {
        if other < self { other } else { self }
    }

    /// The later of two instants.
    pub fn max(self, other: Instant) -> Instant {
        if other > self { other } else { self }
    }

    /// The amount of time elapsed since this instant.
    ///
    /// Requires the `std` feature. Returns [`Duration::ZERO`] if this instant
    /// is in the future.
    #[cfg(feature = "std")]
    pub fn elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(*self)
    }
}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Instant) -> Option<cmp::Ordering> {
        // The sign of the difference, like TCP sequence numbers and lwIP's
        // TIME_LESS_THAN. Correct while the two are less than 2^31 ms apart.
        Some((self.millis.wrapping_sub(other.millis) as i32).cmp(&0))
    }
}

/// How far ahead the deadline a poll returns can be, when no timer is due sooner.
///
/// Polling at least this often keeps every instant the stack holds comparable
/// with the current time. Pending deadlines are at most [`Duration::MAX`] ahead,
/// and an instant that has passed is dropped or replaced at the next poll, long
/// before it is old enough to look like it is in the future again.
pub(crate) const MAX_POLL_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The deadline a poll at `now` returns when no timer is due within
/// [`MAX_POLL_DELAY`].
#[cfg(test)]
#[allow(dead_code)] // Not every feature set has a test that uses it.
pub(crate) fn idle_deadline(now: Instant) -> Instant {
    now + MAX_POLL_DELAY
}

/// One poll's view of time: when the poll runs, and the earliest timer due after that.
///
/// [`Stack::poll`](crate::Stack::poll) makes one and passes it to everything that
/// has timers. Checking a timer with [`expired`](Self::expired) also counts it
/// toward the next deadline when it hasn't fired, so the check and the deadline
/// can't disagree. Nothing counts a deadline that is already due, so the one a
/// poll returns is always later than the poll. It is never later than
/// [`MAX_POLL_DELAY`] from the poll.
pub(crate) struct Clock {
    now: Instant,
    next: Instant,
}

// Some builds have no timers at all, and use only `new` and `next`.
#[allow(dead_code)]
impl Clock {
    /// A clock for a poll at `now`, with no timers counted yet.
    pub(crate) const fn new(now: Instant) -> Self {
        Self {
            now,
            next: Instant {
                millis: now.millis.wrapping_add(MAX_POLL_DELAY.millis),
            },
        }
    }

    /// The time of the poll.
    pub(crate) const fn now(&self) -> Instant {
        self.now
    }

    /// The earliest deadline counted, or [`MAX_POLL_DELAY`] from now if there is
    /// none sooner than that.
    pub(crate) const fn next(&self) -> Instant {
        self.next
    }

    /// Whether a timer set for `deadline` has fired. If it hasn't, `deadline`
    /// counts toward the next deadline.
    ///
    /// A timer fires at its deadline. With `<` instead of `<=` it would stay due
    /// at the deadline it reported, and the stack would ask to be polled right
    /// away, forever.
    pub(crate) fn expired(&mut self, deadline: Instant) -> bool {
        if deadline <= self.now {
            return true;
        }
        self.next = self.next.min(deadline);
        false
    }

    /// Count a timer set for `deadline` toward the next deadline, for a timer
    /// that isn't checked with [`expired`](Self::expired) in this poll.
    ///
    /// The deadline must be later than now: a timer that is due must have fired.
    #[track_caller]
    pub(crate) fn schedule(&mut self, deadline: Instant) {
        debug_assert!(
            deadline > self.now,
            "timer due at {} left for a poll at {}",
            deadline,
            self.now
        );
        self.next = self.next.min(deadline);
    }

    /// Ask to be polled again right away, for work queued for the next poll.
    #[cfg(feature = "loopback")]
    pub(crate) fn poll_again(&mut self) {
        self.next = self.now;
    }

    /// Set a timer `delay` from now. Returns its deadline, which counts toward
    /// the next one.
    #[track_caller]
    pub(crate) fn after(&mut self, delay: Duration) -> Instant {
        let deadline = self.now + delay;
        self.schedule(deadline);
        deadline
    }
}

#[cfg(feature = "std")]
impl From<::std::time::Instant> for Instant {
    /// Counts from the first `std::time::Instant` converted, and wraps around
    /// like any other `Instant`.
    fn from(other: ::std::time::Instant) -> Instant {
        static REFERENTIAL: ::std::sync::LazyLock<::std::time::Instant> =
            ::std::sync::LazyLock::new(::std::time::Instant::now);

        let n = other.saturating_duration_since(*REFERENTIAL);
        Self::from_millis(n.as_millis() as u32)
    }
}

#[cfg(feature = "std")]
impl From<::std::time::SystemTime> for Instant {
    /// Counts from the unix epoch, and wraps around like any other `Instant`.
    fn from(other: ::std::time::SystemTime) -> Instant {
        let n = other
            .duration_since(::std::time::UNIX_EPOCH)
            .expect("start time must not be before the unix epoch");
        Self::from_millis(n.as_millis() as u32)
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{:03}s", self.as_secs(), self.subsec_millis())
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant {
            millis: self.millis.wrapping_add(rhs.millis),
        }
    }
}

impl ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant {
            millis: self.millis.wrapping_sub(rhs.millis),
        }
    }
}

impl ops::SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl ops::Sub<Instant> for Instant {
    type Output = Duration;

    /// Saturates to [`Duration::ZERO`] if `rhs` is later than `self`, like
    /// [`Instant::duration_since`].
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

/// A relative amount of time, in milliseconds.
///
/// A duration is at most [`Duration::MAX`], about 12.4 days. Constructors and
/// arithmetic saturate at it. This keeps every timer the stack sets well within
/// the range where an [`Instant`] compares correctly.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    millis: u32,
}

impl Duration {
    /// A duration of zero time.
    pub const ZERO: Duration = Duration { millis: 0 };

    /// The longest duration: 2<sup>30</sup> ms, about 12.4 days.
    pub const MAX: Duration = Duration { millis: 1 << 30 };

    /// Create a new `Duration` from a number of milliseconds.
    ///
    /// Saturates at [`Duration::MAX`].
    pub const fn from_millis(millis: u32) -> Duration {
        if millis < Self::MAX.millis {
            Duration { millis }
        } else {
            Self::MAX
        }
    }

    /// Create a new `Duration` from a number of seconds.
    ///
    /// Saturates at [`Duration::MAX`].
    pub const fn from_secs(secs: u32) -> Duration {
        Self::from_millis(secs.saturating_mul(1000))
    }

    /// Create a new `Duration` from a number of seconds, as an `f64`.
    ///
    /// The fraction below one millisecond is truncated. Saturates at
    /// [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if `secs` is negative or NaN.
    pub fn from_secs_f64(secs: f64) -> Duration {
        let millis = secs * 1000.0;
        if millis.is_nan() || millis < 0.0 {
            panic!("can not convert float seconds to Duration: value is either negative or NaN");
        }
        // `as` saturates at u32::MAX, and `from_millis` at `MAX`.
        Duration::from_millis(millis as u32)
    }

    /// Create a new `Duration` from a number of seconds, as an `f32`.
    ///
    /// The fraction below one millisecond is truncated. Saturates at
    /// [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if `secs` is negative or NaN.
    pub fn from_secs_f32(secs: f32) -> Duration {
        Self::from_secs_f64(secs as f64)
    }

    /// Whether this is [`Duration::ZERO`].
    pub const fn is_zero(&self) -> bool {
        self.millis == 0
    }

    /// The number of whole seconds in this `Duration`.
    pub const fn as_secs(&self) -> u32 {
        self.millis / 1000
    }

    /// The number of milliseconds in this `Duration`.
    pub const fn as_millis(&self) -> u32 {
        self.millis
    }

    /// The number of milliseconds past [`as_secs`](Self::as_secs).
    ///
    /// Always less than 1000.
    pub const fn subsec_millis(&self) -> u32 {
        self.millis % 1000
    }

    /// This `Duration` as a number of seconds, as an `f64`.
    pub fn as_secs_f64(&self) -> f64 {
        self.millis as f64 / 1000.0
    }

    /// This `Duration` as a number of seconds, as an `f32`.
    pub fn as_secs_f32(&self) -> f32 {
        self.millis as f32 / 1000.0
    }

    /// `self + rhs`, or `None` if it is longer than [`Duration::MAX`].
    pub const fn checked_add(&self, rhs: Duration) -> Option<Duration> {
        // Both are at most 2^30, so the sum fits.
        let millis = self.millis + rhs.millis;
        if millis <= Self::MAX.millis {
            Some(Duration { millis })
        } else {
            None
        }
    }

    /// `self - rhs`, or `None` if `rhs` is longer than `self`.
    pub const fn checked_sub(&self, rhs: Duration) -> Option<Duration> {
        match self.millis.checked_sub(rhs.millis) {
            Some(millis) => Some(Duration { millis }),
            None => None,
        }
    }

    /// `self * rhs`, or `None` if it is longer than [`Duration::MAX`].
    pub const fn checked_mul(&self, rhs: u32) -> Option<Duration> {
        match self.millis.checked_mul(rhs) {
            Some(millis) if millis <= Self::MAX.millis => Some(Duration { millis }),
            _ => None,
        }
    }

    /// `self / rhs`, or `None` if `rhs` is zero.
    pub const fn checked_div(&self, rhs: u32) -> Option<Duration> {
        match self.millis.checked_div(rhs) {
            Some(millis) => Some(Duration { millis }),
            None => None,
        }
    }

    /// `self / rhs`, rounded up to the next millisecond.
    ///
    /// Panics if `rhs` is zero.
    pub const fn div_ceil(&self, rhs: u32) -> Duration {
        Duration {
            millis: self.millis.div_ceil(rhs),
        }
    }

    /// `self + rhs`, saturating at [`Duration::MAX`].
    pub const fn saturating_add(&self, rhs: Duration) -> Duration {
        // Both are at most 2^30, so the sum fits.
        Duration::from_millis(self.millis + rhs.millis)
    }

    /// `self - rhs`, saturating at [`Duration::ZERO`].
    pub const fn saturating_sub(&self, rhs: Duration) -> Duration {
        Duration {
            millis: self.millis.saturating_sub(rhs.millis),
        }
    }

    /// `self * rhs`, saturating at [`Duration::MAX`].
    pub const fn saturating_mul(&self, rhs: u32) -> Duration {
        Duration::from_millis(self.millis.saturating_mul(rhs))
    }

    /// The absolute difference between `self` and `other`.
    pub const fn abs_diff(&self, other: Duration) -> Duration {
        Duration {
            millis: self.millis.abs_diff(other.millis),
        }
    }

    /// `self` multiplied by `rhs`.
    ///
    /// Saturates at [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if the result is negative or NaN.
    pub fn mul_f64(&self, rhs: f64) -> Duration {
        Self::from_secs_f64(rhs * self.as_secs_f64())
    }

    /// `self` multiplied by `rhs`.
    ///
    /// Saturates at [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if the result is negative or NaN.
    pub fn mul_f32(&self, rhs: f32) -> Duration {
        Self::from_secs_f64(rhs as f64 * self.as_secs_f64())
    }

    /// `self` divided by `rhs`.
    ///
    /// Saturates at [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if the result is negative or NaN.
    pub fn div_f64(&self, rhs: f64) -> Duration {
        Self::from_secs_f64(self.as_secs_f64() / rhs)
    }

    /// `self` divided by `rhs`.
    ///
    /// Saturates at [`Duration::MAX`].
    ///
    /// # Panics
    /// Panics if the result is negative or NaN.
    pub fn div_f32(&self, rhs: f32) -> Duration {
        Self::from_secs_f64(self.as_secs_f64() / rhs as f64)
    }

    /// The ratio of `self` to `rhs`.
    pub fn div_duration_f64(&self, rhs: Duration) -> f64 {
        self.as_secs_f64() / rhs.as_secs_f64()
    }

    /// The ratio of `self` to `rhs`.
    pub fn div_duration_f32(&self, rhs: Duration) -> f32 {
        self.as_secs_f32() / rhs.as_secs_f32()
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{:03}s", self.as_secs(), self.subsec_millis())
    }
}

impl ops::Add<Duration> for Duration {
    type Output = Duration;

    /// Saturates at [`Duration::MAX`].
    fn add(self, rhs: Duration) -> Duration {
        self.saturating_add(rhs)
    }
}

impl ops::AddAssign<Duration> for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl ops::Sub<Duration> for Duration {
    type Output = Duration;

    fn sub(self, rhs: Duration) -> Duration {
        self.checked_sub(rhs).expect("overflow when subtracting durations")
    }
}

impl ops::SubAssign<Duration> for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl ops::Mul<u32> for Duration {
    type Output = Duration;

    /// Saturates at [`Duration::MAX`].
    fn mul(self, rhs: u32) -> Duration {
        self.saturating_mul(rhs)
    }
}

impl ops::Mul<Duration> for u32 {
    type Output = Duration;

    /// Saturates at [`Duration::MAX`].
    fn mul(self, rhs: Duration) -> Duration {
        rhs * self
    }
}

impl ops::MulAssign<u32> for Duration {
    fn mul_assign(&mut self, rhs: u32) {
        *self = *self * rhs;
    }
}

impl ops::Div<u32> for Duration {
    type Output = Duration;

    fn div(self, rhs: u32) -> Duration {
        Duration {
            millis: self.millis / rhs,
        }
    }
}

impl ops::DivAssign<u32> for Duration {
    fn div_assign(&mut self, rhs: u32) {
        *self = *self / rhs;
    }
}

impl From<::core::time::Duration> for Duration {
    /// Truncates below one millisecond, and saturates at [`Duration::MAX`].
    fn from(other: ::core::time::Duration) -> Duration {
        Duration::from_millis(u32::try_from(other.as_millis()).unwrap_or(u32::MAX))
    }
}

impl From<Duration> for ::core::time::Duration {
    fn from(val: Duration) -> Self {
        ::core::time::Duration::from_millis(val.millis as u64)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_instant_ops() {
        // std::ops::Add
        assert_eq!(
            Instant::from_millis(4) + Duration::from_millis(6),
            Instant::from_millis(10)
        );
        // std::ops::Sub
        assert_eq!(
            Instant::from_millis(7) - Duration::from_millis(5),
            Instant::from_millis(2)
        );
    }

    #[test]
    fn test_instant_wraps_around() {
        let before = Instant::from_millis(u32::MAX - 1);
        let after = before + Duration::from_millis(5);
        assert_eq!(after, Instant::from_millis(3));
        assert_eq!(after - Duration::from_millis(5), before);
        assert!(before < after);
        assert!(after > before);
        assert_eq!(after - before, Duration::from_millis(5));
        assert_eq!(before - after, Duration::ZERO);
        assert_eq!(before.min(after), before);
        assert_eq!(before.max(after), after);
        assert_eq!(after.min(before), before);
        assert_eq!(after.max(before), after);
    }

    #[test]
    fn test_instant_compare_range() {
        let a = Instant::from_millis(1000);
        // Up to 2^31 - 1 ms apart, the earlier instant is the smaller one.
        let b = Instant::from_millis(1000 + i32::MAX as u32);
        assert!(a < b);
        assert!(b > a);
        // One more, and they compare the other way around.
        let c = b + Duration::from_millis(2);
        assert!(c < a);
    }

    #[test]
    fn test_instant_getters() {
        let instant = Instant::from_millis(5674);
        assert_eq!(instant.as_secs(), 5);
        assert_eq!(instant.as_millis(), 5674);
        assert_eq!(instant.subsec_millis(), 674);
        assert_eq!(Instant::from_secs(5), Instant::from_millis(5000));
        // Seconds wrap around like the instant.
        assert_eq!(Instant::from_secs(4_294_968), Instant::from_millis(704));
    }

    #[test]
    fn test_instant_duration_since() {
        let a = Instant::from_millis(100);
        let b = Instant::from_millis(250);
        assert_eq!(b.duration_since(a), Duration::from_millis(150));
        assert_eq!(b - a, Duration::from_millis(150));
        // Saturates instead of returning the absolute difference.
        assert_eq!(a.duration_since(b), Duration::ZERO);
        assert_eq!(a - b, Duration::ZERO);
        assert_eq!(a.saturating_duration_since(b), Duration::ZERO);
        assert_eq!(a.checked_duration_since(b), None);
        assert_eq!(b.checked_duration_since(a), Some(Duration::from_millis(150)));
        // Saturates at the longest duration.
        let c = a + Duration::MAX + Duration::from_secs(1000);
        assert_eq!(c - a, Duration::MAX);
    }

    #[test]
    fn test_instant_display() {
        assert_eq!(format!("{}", Instant::from_millis(74)), "0.074s");
        assert_eq!(format!("{}", Instant::from_millis(5674)), "5.674s");
        assert_eq!(format!("{}", Instant::from_millis(5000)), "5.000s");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_conversions() {
        assert_eq!(Instant::from(::std::time::UNIX_EPOCH), Instant::from_millis(0));
        assert_eq!(
            Instant::from(::std::time::UNIX_EPOCH + ::std::time::Duration::from_millis(5674)),
            Instant::from_millis(5674)
        );
        // Wraps around.
        assert_eq!(
            Instant::from(::std::time::UNIX_EPOCH + ::std::time::Duration::from_millis((1 << 32) + 42)),
            Instant::from_millis(42)
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_conversions_from_std_instant() {
        let std_now = ::std::time::Instant::now();

        let before = Instant::from(std_now);
        ::std::thread::sleep(::std::time::Duration::from_millis(5));
        let after = Instant::from(std_now);

        assert_eq!(
            before, after,
            "converting the same std Instant twice should yield the same result"
        );
    }

    #[test]
    fn test_clock_default_deadline() {
        let now = Instant::from_millis(u32::MAX - 10);
        let mut clock = Clock::new(now);
        assert_eq!(clock.next(), now + MAX_POLL_DELAY);
        // A timer further out than that doesn't push the deadline back.
        assert!(!clock.expired(now + Duration::MAX));
        assert_eq!(clock.next(), now + MAX_POLL_DELAY);
        // One sooner does, across the wraparound too.
        assert!(!clock.expired(now + Duration::from_millis(20)));
        assert_eq!(clock.next(), Instant::from_millis(9));
        assert!(clock.expired(now));
        assert!(clock.expired(now - Duration::from_millis(20)));
        assert_eq!(clock.next(), Instant::from_millis(9));
    }

    #[test]
    fn test_duration_ops() {
        // std::ops::Add
        assert_eq!(
            Duration::from_millis(40) + Duration::from_millis(2),
            Duration::from_millis(42)
        );
        // std::ops::Sub
        assert_eq!(
            Duration::from_millis(555) - Duration::from_millis(42),
            Duration::from_millis(513)
        );
        // std::ops::Mul
        assert_eq!(Duration::from_millis(13) * 22, Duration::from_millis(286));
        assert_eq!(22 * Duration::from_millis(13), Duration::from_millis(286));
        // std::ops::Div
        assert_eq!(Duration::from_millis(53) / 4, Duration::from_millis(13));
    }

    #[test]
    fn test_duration_assign_ops() {
        let mut duration = Duration::from_millis(4735);
        duration += Duration::from_millis(1733);
        assert_eq!(duration, Duration::from_millis(6468));
        duration -= Duration::from_millis(1234);
        assert_eq!(duration, Duration::from_millis(5234));
        duration *= 4;
        assert_eq!(duration, Duration::from_millis(20936));
        duration /= 5;
        assert_eq!(duration, Duration::from_millis(4187));
    }

    #[test]
    #[should_panic(expected = "overflow when subtracting durations")]
    fn test_sub_from_zero_overflow() {
        let _ = Duration::from_millis(0) - Duration::from_millis(1);
    }

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_div_by_zero() {
        let _ = Duration::from_millis(4) / 0;
    }

    #[test]
    fn test_duration_getters() {
        let duration = Duration::from_millis(4934);
        assert_eq!(duration.as_secs(), 4);
        assert_eq!(duration.as_millis(), 4934);
        assert_eq!(duration.subsec_millis(), 934);
        assert!(!duration.is_zero());
        assert!(Duration::ZERO.is_zero());
    }

    #[test]
    fn test_duration_saturates_at_max() {
        assert_eq!(Duration::MAX.as_millis(), 1 << 30);
        assert_eq!(Duration::from_millis(u32::MAX), Duration::MAX);
        assert_eq!(Duration::from_secs(u32::MAX), Duration::MAX);
        assert_eq!(Duration::from_secs(1_073_741), Duration::from_millis(1_073_741_000));
        assert_eq!(Duration::from_secs(1_073_742), Duration::MAX);
        assert_eq!(Duration::MAX + Duration::MAX, Duration::MAX);
        assert_eq!(Duration::MAX * 7, Duration::MAX);
        assert_eq!(Duration::from_secs_f64(1e12), Duration::MAX);
        assert_eq!(
            Duration::from(::core::time::Duration::from_secs(1 << 40)),
            Duration::MAX
        );
    }

    #[test]
    fn test_duration_floats() {
        let duration = Duration::from_millis(4934);
        assert_eq!(duration.as_secs_f64(), 4.934);
        assert_eq!(duration.as_secs_f32(), 4.934);
        assert_eq!(Duration::from_secs_f64(4.934), duration);
        assert_eq!(Duration::from_secs_f32(0.5), Duration::from_millis(500));
        assert_eq!(Duration::from_secs(1).mul_f64(2.5), Duration::from_millis(2500));
        assert_eq!(Duration::from_secs(1).div_f64(4.0), Duration::from_millis(250));
        assert_eq!(Duration::from_secs(1).mul_f32(2.5), Duration::from_millis(2500));
        assert_eq!(Duration::from_secs(1).div_f32(4.0), Duration::from_millis(250));
        assert_eq!(Duration::from_secs(3).div_duration_f64(Duration::from_secs(2)), 1.5);
        assert_eq!(Duration::from_secs(3).div_duration_f32(Duration::from_secs(2)), 1.5);
    }

    #[test]
    #[should_panic(expected = "can not convert float seconds to Duration")]
    fn test_duration_from_secs_f64_negative() {
        let _ = Duration::from_secs_f64(-1.0);
    }

    #[test]
    fn test_duration_checked() {
        let a = Duration::from_millis(100);
        let b = Duration::from_millis(40);
        assert_eq!(a.checked_add(b), Some(Duration::from_millis(140)));
        assert_eq!(a.checked_sub(b), Some(Duration::from_millis(60)));
        assert_eq!(b.checked_sub(a), None);
        assert_eq!(Duration::MAX.checked_add(Duration::from_millis(1)), None);
        assert_eq!(a.checked_mul(3), Some(Duration::from_millis(300)));
        assert_eq!(Duration::MAX.checked_mul(2), None);
        assert_eq!(a.checked_div(4), Some(Duration::from_millis(25)));
        assert_eq!(a.checked_div(0), None);
    }

    #[test]
    fn test_duration_saturating() {
        let a = Duration::from_millis(100);
        let b = Duration::from_millis(40);
        assert_eq!(a.saturating_add(b), Duration::from_millis(140));
        assert_eq!(Duration::MAX.saturating_add(a), Duration::MAX);
        assert_eq!(a.saturating_sub(b), Duration::from_millis(60));
        assert_eq!(b.saturating_sub(a), Duration::ZERO);
        assert_eq!(a.saturating_mul(2), Duration::from_millis(200));
        assert_eq!(Duration::MAX.saturating_mul(2), Duration::MAX);
        assert_eq!(a.abs_diff(b), Duration::from_millis(60));
        assert_eq!(b.abs_diff(a), Duration::from_millis(60));
    }

    #[test]
    fn test_duration_conversions() {
        let mut std_duration = ::core::time::Duration::from_millis(4934);
        let duration: Duration = std_duration.into();
        assert_eq!(duration, Duration::from_millis(4934));
        assert_eq!(Duration::from(std_duration), Duration::from_millis(4934));

        std_duration = duration.into();
        assert_eq!(std_duration, ::core::time::Duration::from_millis(4934));
    }
}
