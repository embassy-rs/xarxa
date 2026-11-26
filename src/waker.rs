//! Waker registration, for the `async` feature.
//!
//! Every socket keeps one waker per operation kind (receive, send, accept). The
//! stack wakes them whenever something happens that may change what the
//! corresponding operations return: a packet arriving, a TCP state transition,
//! room freeing up in a ring buffer. A future built on top can then poll the
//! socket, register, and go to sleep.

#![cfg_attr(not(any(feature = "tcp", feature = "udp", feature = "_raw")), allow(unused))]

use core::task::Waker;

/// Utility struct to register and wake a waker.
#[derive(Debug, Default)]
pub(crate) struct WakerRegistration {
    waker: Option<Waker>,
}

impl WakerRegistration {
    pub const fn new() -> Self {
        Self { waker: None }
    }

    /// Register a waker. Overwrites the previous waker, if any.
    ///
    /// If a different task's waker was already registered, that task is woken so
    /// it can poll again and re-register if it is still waiting. Without that,
    /// a second waiter on the same registration (for example two tasks in
    /// `Iface::register_waker`) would silently drop the first, and a later
    /// `wake` would never reach it. Matches `embassy_sync::waitqueue::WakerRegistration`.
    pub fn register(&mut self, w: &Waker) {
        match self.waker {
            // Optimization: If both the old and new Wakers wake the same task, we can simply
            // keep the old waker, skipping the clone. (In most executor implementations,
            // cloning a waker is somewhat expensive, comparable to cloning an Arc).
            Some(ref w2) if (w2.will_wake(w)) => {}
            // Different task (or none): store the new waker, and wake the old one if any
            // so that task can make progress and re-register.
            _ => {
                if let Some(old) = self.waker.take() {
                    old.wake();
                }
                self.waker = Some(w.clone());
            }
        }
    }

    /// Wake the registered waker, if any.
    pub fn wake(&mut self) {
        if let Some(w) = self.waker.take() {
            w.wake()
        }
    }
}

#[cfg(all(test, feature = "async"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn register_wakes_previous_task() {
        let mut reg = WakerRegistration::new();
        let first = Arc::new(Count(AtomicUsize::new(0)));
        let second = Arc::new(Count(AtomicUsize::new(0)));

        reg.register(&Waker::from(first.clone()));
        reg.register(&Waker::from(second.clone()));

        assert_eq!(first.0.load(Ordering::SeqCst), 1, "replaced waiter must be woken");
        assert_eq!(
            second.0.load(Ordering::SeqCst),
            0,
            "current waiter stays asleep until wake()"
        );

        reg.wake();
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn register_same_task_does_not_wake() {
        let mut reg = WakerRegistration::new();
        let first = Arc::new(Count(AtomicUsize::new(0)));
        let w = Waker::from(first.clone());

        reg.register(&w);
        reg.register(&w);
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
    }
}
