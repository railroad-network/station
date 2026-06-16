//! An injectable clock.
//!
//! Ledger and settlement code never read the system clock — they take `now:
//! i64` (Unix seconds). The daemon is what *supplies* that `now`, and in a test
//! we need to fast-forward it across a 48-hour settlement window without
//! actually waiting. [`Clock`] is that seam: a real one reads wall-clock time, a
//! manual one returns whatever the test last set, and both are cheaply
//! cloneable so the settlement timer, the core, and the test can share one.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of "now" in Unix seconds, shared across the station's tasks.
#[derive(Clone)]
pub struct Clock(Inner);

#[derive(Clone)]
enum Inner {
    /// Reads the host clock.
    System,
    /// Returns a value the holder can advance at will (tests, demos).
    Manual(Arc<AtomicI64>),
}

impl Clock {
    /// A clock backed by the real system time.
    pub fn system() -> Self {
        Clock(Inner::System)
    }

    /// A manually-controlled clock starting at `start` Unix seconds. Clones
    /// share the same underlying value, so advancing one advances all.
    pub fn manual(start: i64) -> Self {
        Clock(Inner::Manual(Arc::new(AtomicI64::new(start))))
    }

    /// The current time, in Unix seconds.
    pub fn now(&self) -> i64 {
        match &self.0 {
            Inner::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Inner::Manual(v) => v.load(Ordering::SeqCst),
        }
    }

    /// Advances a manual clock by `secs` seconds and returns the new value.
    ///
    /// On a [`Clock::system`] clock this is a no-op (you cannot move wall-clock
    /// time); it returns the current time. Manual control is a test/demo affordance.
    pub fn advance(&self, secs: i64) -> i64 {
        match &self.0 {
            Inner::System => self.now(),
            Inner::Manual(v) => v.fetch_add(secs, Ordering::SeqCst) + secs,
        }
    }

    /// Sets a manual clock to an absolute `value`. No-op on a system clock.
    pub fn set(&self, value: i64) {
        if let Inner::Manual(v) = &self.0 {
            v.store(value, Ordering::SeqCst);
        }
    }
}

impl Default for Clock {
    fn default() -> Self {
        Clock::system()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_and_shares() {
        let a = Clock::manual(1_000);
        let b = a.clone();
        assert_eq!(a.now(), 1_000);
        assert_eq!(b.advance(500), 1_500);
        // The clone sees the same advance.
        assert_eq!(a.now(), 1_500);
        a.set(42);
        assert_eq!(b.now(), 42);
    }

    #[test]
    fn system_clock_is_nonzero_and_unmovable() {
        let c = Clock::system();
        assert!(c.now() > 1_600_000_000); // sometime after 2020
        let before = c.now();
        let after = c.advance(10_000); // no-op
        assert!(after - before < 5); // advancing did nothing
    }
}
