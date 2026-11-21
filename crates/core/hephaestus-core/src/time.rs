//! Deterministic monotonic timestamp injected from the I/O boundary.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Deterministic monotonic timestamp in milliseconds since an arbitrary origin.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct MonoTime(pub u64);

impl MonoTime {
    /// Returns a timestamp advanced by `delta_ms`, saturating at `u64::MAX`.
    #[must_use]
    pub const fn add_ms(self, delta_ms: u64) -> Self {
        Self(self.0.saturating_add(delta_ms))
    }

    /// Returns elapsed milliseconds between `self` and `earlier`, saturating at zero.
    #[must_use]
    pub const fn saturating_sub(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// Returns the raw millisecond counter.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MonoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}
