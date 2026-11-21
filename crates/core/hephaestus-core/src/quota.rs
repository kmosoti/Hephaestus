//! Deterministic Sans-I/O token-bucket quota and rate-limit governor.

use crate::time::MonoTime;
use alloc::collections::VecDeque;

/// Safety margin under Google Drive's 325,000 API units/minute project limit.
pub const MAX_UNITS_PER_MINUTE: u64 = 300_000;
/// Maximum instantaneous write burst tokens.
pub const WRITE_BURST_CAPACITY: u64 = 30;
/// Sustained write token refill rate (3 writes/second).
pub const WRITE_REFILL_PER_SEC: u64 = 3;
/// Daily upload transfer ceiling (750 GiB/day).
pub const DAILY_TRANSFER_CAP_BYTES: u64 = 750 * 1024 * 1024 * 1024;

const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;
const BASE_BACKOFF_MS: u64 = 500;
const MAX_BACKOFF_MS: u64 = 60_000;

/// Operation classes weighted by API quota cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveOpKind {
    /// Metadata lookup by `fileId` (`5` quota units).
    FilesGet,
    /// Resumable bundle creation (`50` quota units, consumes write token).
    FilesCreate,
    /// Media download by `fileId` (`200` quota units).
    FilesDownload,
}

impl DriveOpKind {
    /// Returns the quota unit cost for this operation.
    #[must_use]
    pub const fn quota_units(self) -> u64 {
        match self {
            Self::FilesGet => 5,
            Self::FilesCreate => 50,
            Self::FilesDownload => 200,
        }
    }

    /// Returns `true` for write operations governed by the 3 writes/s token bucket.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::FilesCreate)
    }
}

/// Admission decision returned by [`DriveQuotaGovernor::check_and_consume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Operation may proceed immediately.
    Allow,
    /// Caller must wait until the specified monotonic timestamp before retrying.
    WaitUntil(MonoTime),
    /// Daily 750 GiB upload transfer cap would be exceeded.
    DailyCapExceeded,
}

/// Pure Sans-I/O deterministic Drive quota & rate-limit governor driven by [`MonoTime`].
#[derive(Debug, Clone)]
pub struct DriveQuotaGovernor {
    write_tokens_milli: u64,
    last_refill: MonoTime,
    minute_events: VecDeque<(MonoTime, u64)>,
    minute_units_used: u64,
    daily_uploads: VecDeque<(MonoTime, u64)>,
    daily_bytes_uploaded: u64,
    backoff_until: Option<MonoTime>,
    consecutive_429: u32,
    jitter_seed: u64,
}

impl DriveQuotaGovernor {
    /// Initializes a fresh governor at `start` with deterministic `jitter_seed`.
    #[must_use]
    pub fn new(start: MonoTime, jitter_seed: u64) -> Self {
        Self {
            write_tokens_milli: WRITE_BURST_CAPACITY * 1000,
            last_refill: start,
            minute_events: VecDeque::new(),
            minute_units_used: 0,
            daily_uploads: VecDeque::new(),
            daily_bytes_uploaded: 0,
            backoff_until: None,
            consecutive_429: 0,
            jitter_seed,
        }
    }

    /// Evaluates quota limits and consumes tokens when returning [`QuotaDecision::Allow`].
    pub fn check_and_consume(
        &mut self,
        op: DriveOpKind,
        upload_bytes: u64,
        now: MonoTime,
    ) -> QuotaDecision {
        self.evict_expired(now);
        self.refill_write_tokens(now);

        if let Some(until) = self.backoff_until {
            if now < until {
                return QuotaDecision::WaitUntil(until);
            }
            self.backoff_until = None;
        }

        if upload_bytes > 0
            && self.daily_bytes_uploaded.saturating_add(upload_bytes) > DAILY_TRANSFER_CAP_BYTES
        {
            return QuotaDecision::DailyCapExceeded;
        }

        let units = op.quota_units();
        if self.minute_units_used.saturating_add(units) > MAX_UNITS_PER_MINUTE {
            let wake = self
                .minute_events
                .front()
                .map(|(ts, _)| ts.add_ms(MINUTE_MS))
                .unwrap_or_else(|| now.add_ms(1_000));
            return QuotaDecision::WaitUntil(wake);
        }

        if op.is_write() && self.write_tokens_milli < 1000 {
            let deficit = 1000 - self.write_tokens_milli;
            let wait_ms = deficit.div_ceil(WRITE_REFILL_PER_SEC);
            return QuotaDecision::WaitUntil(now.add_ms(wait_ms.max(1)));
        }

        if op.is_write() {
            self.write_tokens_milli -= 1000;
        }
        self.minute_events.push_back((now, units));
        self.minute_units_used += units;
        if upload_bytes > 0 {
            self.daily_uploads.push_back((now, upload_bytes));
            self.daily_bytes_uploaded += upload_bytes;
        }
        QuotaDecision::Allow
    }

    /// Resets exponential backoff state after a successful remote call.
    pub fn on_success(&mut self) {
        self.consecutive_429 = 0;
        self.backoff_until = None;
    }

    /// Records an HTTP 403/429 rate-limit response and returns the deterministic wake time.
    pub fn on_rate_limited(&mut self, now: MonoTime, retry_after_ms: Option<u64>) -> MonoTime {
        let shift = self.consecutive_429.min(8);
        self.consecutive_429 = self.consecutive_429.saturating_add(1);
        let exp_ms = BASE_BACKOFF_MS
            .saturating_mul(1u64 << shift)
            .min(MAX_BACKOFF_MS);
        let jitter = self.next_jitter_ms(exp_ms / 4 + 1);
        let delay = retry_after_ms
            .unwrap_or(0)
            .max(exp_ms.saturating_add(jitter));
        let until = now.add_ms(delay);
        self.backoff_until = Some(until);
        until
    }

    /// Total quota units consumed inside the active 60-second sliding window.
    #[must_use]
    pub const fn minute_units_used(&self) -> u64 {
        self.minute_units_used
    }

    /// Total bytes uploaded inside the active 24-hour sliding window.
    #[must_use]
    pub const fn daily_bytes_uploaded(&self) -> u64 {
        self.daily_bytes_uploaded
    }

    fn refill_write_tokens(&mut self, now: MonoTime) {
        let elapsed_ms = now.saturating_sub(self.last_refill);
        if elapsed_ms > 0 {
            let added = elapsed_ms.saturating_mul(WRITE_REFILL_PER_SEC);
            self.write_tokens_milli = self
                .write_tokens_milli
                .saturating_add(added)
                .min(WRITE_BURST_CAPACITY * 1000);
            self.last_refill = now;
        }
    }

    fn evict_expired(&mut self, now: MonoTime) {
        while let Some(&(ts, units)) = self.minute_events.front() {
            if now.saturating_sub(ts) >= MINUTE_MS {
                self.minute_events.pop_front();
                self.minute_units_used = self.minute_units_used.saturating_sub(units);
            } else {
                break;
            }
        }
        while let Some(&(ts, bytes)) = self.daily_uploads.front() {
            if now.saturating_sub(ts) >= DAY_MS {
                self.daily_uploads.pop_front();
                self.daily_bytes_uploaded = self.daily_bytes_uploaded.saturating_sub(bytes);
            } else {
                break;
            }
        }
    }

    fn next_jitter_ms(&mut self, bound: u64) -> u64 {
        let mut x = self.jitter_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.jitter_seed = x;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (x ^ (x >> 31)) % bound.max(1)
    }
}
