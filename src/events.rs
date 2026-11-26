//! Event bus and rolling request-rate tracker for broadcasting attack events

use crate::db::AttackEvent;
use chrono::Utc;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

const WINDOW_SECS: usize = 300; // 5-minute rolling window

/// Tracks incoming request timestamps in a fixed 300-second ring buffer.
pub struct RateTracker {
    buckets: Mutex<[(i64, u64); WINDOW_SECS]>,
    started_at: i64,
}

impl RateTracker {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new([(0, 0); WINDOW_SECS]),
            started_at: Utc::now().timestamp(),
        }
    }

    pub fn record(&self) {
        self.record_at(Utc::now().timestamp());
    }

    fn record_at(&self, now_sec: i64) {
        let idx = (now_sec.rem_euclid(WINDOW_SECS as i64)) as usize;
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets[idx].0 == now_sec {
            buckets[idx].1 += 1;
        } else {
            buckets[idx] = (now_sec, 1);
        }
    }

    /// Compute rolling requests per minute over the active window (up to 5 minutes).
    pub fn requests_per_minute(&self) -> f64 {
        self.requests_per_minute_at(Utc::now().timestamp())
    }

    fn requests_per_minute_at(&self, now_sec: i64) -> f64 {
        let cutoff = now_sec - WINDOW_SECS as i64;
        let sum: u64 = {
            let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            buckets
                .iter()
                .filter(|&&(ts, _)| ts > cutoff && ts <= now_sec)
                .map(|&(_, c)| c)
                .sum()
        };

        let elapsed = (now_sec - self.started_at)
            .clamp(1, WINDOW_SECS as i64) as f64;
        let rpm = (sum as f64) * 60.0 / elapsed;
        (rpm * 10.0).round() / 10.0
    }
}

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<AttackEvent>>,
    rate_tracker: Arc<RateTracker>,
}

impl EventBus {
    pub fn new(sender: broadcast::Sender<Arc<AttackEvent>>) -> Self {
        Self {
            sender,
            rate_tracker: Arc::new(RateTracker::new()),
        }
    }

    pub fn publish(&self, event: AttackEvent) {
        self.rate_tracker.record();
        let _ = self.sender.send(Arc::new(event));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<AttackEvent>> {
        self.sender.subscribe()
    }

    pub fn requests_per_minute(&self) -> f64 {
        self.rate_tracker.requests_per_minute()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_tracker_computes_rolling_rpm() {
        let base = 1_700_000_000;
        let tracker = RateTracker {
            buckets: Mutex::new([(0, 0); WINDOW_SECS]),
            started_at: base - 60,
        };

        for offset in 0..30 {
            tracker.record_at(base - offset);
        }
        // 30 requests in last 60s of uptime -> 30.0 req/min
        assert_eq!(tracker.requests_per_minute_at(base), 30.0);

        // Advance past the 5-minute window: old buckets expire
        assert_eq!(tracker.requests_per_minute_at(base + 305), 0.0);
    }
}
