//! Connection concurrency limits for DoS resilience

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Enforces global and per-IP concurrent connection caps across protocol handlers.
#[derive(Debug)]
pub struct ConnectionLimiter {
    max_per_ip: usize,
    max_total: usize,
    total: AtomicUsize,
    per_ip: Mutex<HashMap<String, usize>>,
}

/// RAII permit that releases connection slots when dropped.
#[derive(Debug)]
pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    ip: String,
}

impl ConnectionLimiter {
    /// Create a new limiter. A limit of 0 disables that specific cap.
    pub fn new(max_per_ip: usize, max_total: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_ip,
            max_total,
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Attempt to acquire a connection permit for `ip`. Returns `None` if at capacity.
    pub fn try_acquire(self: &Arc<Self>, ip: &str) -> Option<ConnectionPermit> {
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());

        let current_total = self.total.load(Ordering::Relaxed);
        if self.max_total > 0 && current_total >= self.max_total {
            return None;
        }

        let ip_count = map.get(ip).copied().unwrap_or(0);
        if self.max_per_ip > 0 && ip_count >= self.max_per_ip {
            return None;
        }

        self.total.fetch_add(1, Ordering::Relaxed);
        map.insert(ip.to_string(), ip_count + 1);

        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            ip: ip.to_string(),
        })
    }

    #[allow(dead_code)]
    pub fn active_total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn active_for_ip(&self, ip: &str) -> usize {
        self.per_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(ip)
            .copied()
            .unwrap_or(0)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut map = self.limiter.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            if *count <= 1 {
                map.remove(&self.ip);
            } else {
                *count -= 1;
            }
        }
        self.limiter.total.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_ip_and_global_limits_and_releases_on_drop() {
        let limiter = ConnectionLimiter::new(2, 3);

        let p1 = limiter.try_acquire("1.1.1.1").expect("first permit");
        let p2 = limiter.try_acquire("1.1.1.1").expect("second permit");
        assert!(limiter.try_acquire("1.1.1.1").is_none(), "per-IP cap should block 3rd");
        assert_eq!(limiter.active_for_ip("1.1.1.1"), 2);
        assert_eq!(limiter.active_total(), 2);

        let p3 = limiter.try_acquire("2.2.2.2").expect("different IP allowed up to global cap");
        assert!(limiter.try_acquire("3.3.3.3").is_none(), "global cap should block 4th");
        assert_eq!(limiter.active_total(), 3);

        drop(p1);
        assert_eq!(limiter.active_for_ip("1.1.1.1"), 1);
        assert_eq!(limiter.active_total(), 2);

        let p4 = limiter.try_acquire("1.1.1.1").expect("slot freed on drop");
        assert_eq!(limiter.active_total(), 3);

        drop(p2);
        drop(p3);
        drop(p4);
        assert_eq!(limiter.active_total(), 0);
        assert_eq!(limiter.active_for_ip("1.1.1.1"), 0);
    }
}
