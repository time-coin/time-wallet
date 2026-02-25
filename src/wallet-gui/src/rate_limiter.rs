/// Rate limiting module for peer connections
/// Prevents DoS attacks by limiting message frequency per peer
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Maximum requests per minute per peer
const MAX_REQUESTS_PER_MINUTE: u32 = 60;

/// Maximum requests per 10 seconds burst
const MAX_BURST_REQUESTS: u32 = 20;

/// Violation threshold before peer is banned
const MAX_VIOLATIONS: u32 = 10;

/// Ban duration in seconds
const BAN_DURATION_SECS: u64 = 600; // 10 minutes

/// Rate limit tracking for a single peer
#[derive(Debug, Clone)]
struct PeerRateLimit {
    /// Total requests in current minute window
    minute_count: u32,
    /// Start of current minute window
    minute_start: Instant,

    /// Burst requests in current 10-second window
    burst_count: u32,
    /// Start of current burst window
    burst_start: Instant,

    /// Total violations (rate limit exceeded)
    violations: u32,
    /// Last violation timestamp
    last_violation: Option<Instant>,

    /// Ban timestamp (if banned)
    banned_until: Option<Instant>,
}

impl PeerRateLimit {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            minute_count: 0,
            minute_start: now,
            burst_count: 0,
            burst_start: now,
            violations: 0,
            last_violation: None,
            banned_until: None,
        }
    }

    /// Check if peer is currently banned
    fn is_banned(&self) -> bool {
        if let Some(banned_until) = self.banned_until {
            Instant::now() < banned_until
        } else {
            false
        }
    }

    /// Check and update rate limits
    /// Returns true if request is allowed, false if rate limited
    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();

        // Check if banned
        if self.is_banned() {
            return false;
        }

        // Reset minute window if expired
        if now.duration_since(self.minute_start) >= Duration::from_secs(60) {
            self.minute_count = 0;
            self.minute_start = now;
        }

        // Reset burst window if expired
        if now.duration_since(self.burst_start) >= Duration::from_secs(10) {
            self.burst_count = 0;
            self.burst_start = now;
        }

        // Check minute limit
        if self.minute_count >= MAX_REQUESTS_PER_MINUTE {
            self.record_violation();
            return false;
        }

        // Check burst limit
        if self.burst_count >= MAX_BURST_REQUESTS {
            self.record_violation();
            return false;
        }

        // Allow request and increment counters
        self.minute_count += 1;
        self.burst_count += 1;
        true
    }

    /// Record a rate limit violation
    fn record_violation(&mut self) {
        self.violations += 1;
        self.last_violation = Some(Instant::now());

        // Ban if too many violations
        if self.violations >= MAX_VIOLATIONS {
            self.banned_until = Some(Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
            println!(
                "⛔ Peer banned for {} seconds due to {} violations",
                BAN_DURATION_SECS, self.violations
            );
        }
    }

    /// Reset violation counter (called after successful behavior)
    fn reset_violations(&mut self) {
        self.violations = 0;
        self.last_violation = None;
    }
}

/// Rate limiter for all peers
#[derive(Debug)]
pub struct RateLimiter {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerRateLimit>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a peer is allowed to make a request
    /// Returns true if allowed, false if rate limited
    pub async fn check_rate_limit(&self, peer: SocketAddr) -> bool {
        let mut peers = self.peers.write().await;
        let limiter = peers.entry(peer).or_insert_with(PeerRateLimit::new);
        limiter.check_rate_limit()
    }

    /// Check if peer is banned
    pub async fn is_banned(&self, peer: SocketAddr) -> bool {
        let peers = self.peers.read().await;
        if let Some(limiter) = peers.get(&peer) {
            limiter.is_banned()
        } else {
            false
        }
    }

    /// Record a violation for a peer
    pub async fn record_violation(&self, peer: SocketAddr) {
        let mut peers = self.peers.write().await;
        let limiter = peers.entry(peer).or_insert_with(PeerRateLimit::new);
        limiter.record_violation();
    }

    /// Reset violations for a peer (reward good behavior)
    pub async fn reset_violations(&self, peer: SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(limiter) = peers.get_mut(&peer) {
            limiter.reset_violations();
        }
    }

    /// Get violation count for a peer
    pub async fn get_violations(&self, peer: SocketAddr) -> u32 {
        let peers = self.peers.read().await;
        peers.get(&peer).map(|l| l.violations).unwrap_or(0)
    }

    /// Clean up old peer entries (call periodically)
    pub async fn cleanup_old_entries(&self) {
        let mut peers = self.peers.write().await;
        let now = Instant::now();

        // Remove entries with no recent activity (>1 hour)
        peers.retain(|_addr, limiter| {
            if let Some(last_violation) = limiter.last_violation {
                now.duration_since(last_violation) < Duration::from_secs(3600)
            } else {
                now.duration_since(limiter.minute_start) < Duration::from_secs(3600)
            }
        });
    }

    /// Get statistics for monitoring
    pub async fn get_stats(&self) -> RateLimiterStats {
        let peers = self.peers.read().await;
        let total_peers = peers.len();
        let banned_peers = peers.values().filter(|l| l.is_banned()).count();
        let peers_with_violations = peers.values().filter(|l| l.violations > 0).count();

        RateLimiterStats {
            total_peers,
            banned_peers,
            peers_with_violations,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub total_peers: usize,
    pub banned_peers: usize,
    pub peers_with_violations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_basic() {
        let mut limiter = PeerRateLimit::new();

        // Should allow first request
        assert!(limiter.check_rate_limit());

        // Should allow up to MAX_BURST_REQUESTS
        for _ in 0..MAX_BURST_REQUESTS - 1 {
            assert!(limiter.check_rate_limit());
        }

        // Should deny next request (burst exceeded)
        assert!(!limiter.check_rate_limit());
    }

    #[test]
    fn test_violation_tracking() {
        let mut limiter = PeerRateLimit::new();

        // Exceed burst limit
        for _ in 0..MAX_BURST_REQUESTS {
            limiter.check_rate_limit();
        }

        // Next request should be denied and record violation
        assert!(!limiter.check_rate_limit());
        assert_eq!(limiter.violations, 1);
    }

    #[test]
    fn test_ban_after_violations() {
        let mut limiter = PeerRateLimit::new();

        // Record MAX_VIOLATIONS violations
        for _ in 0..MAX_VIOLATIONS {
            limiter.record_violation();
        }

        // Should be banned
        assert!(limiter.is_banned());
    }

    #[tokio::test]
    async fn test_multi_peer_rate_limiting() {
        let limiter = RateLimiter::new();
        let peer1 = "127.0.0.1:8080".parse().unwrap();
        let peer2 = "127.0.0.1:8081".parse().unwrap();

        // Both peers should be allowed initially
        assert!(limiter.check_rate_limit(peer1).await);
        assert!(limiter.check_rate_limit(peer2).await);

        // Exceed burst for peer1
        for _ in 0..MAX_BURST_REQUESTS {
            limiter.check_rate_limit(peer1).await;
        }

        // peer1 should be rate limited
        assert!(!limiter.check_rate_limit(peer1).await);

        // peer2 should still be allowed
        assert!(limiter.check_rate_limit(peer2).await);
    }
}
