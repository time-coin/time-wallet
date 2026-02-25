use chrono::{DateTime, Utc};
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

const MAX_SAFE_OFFSET_SECS: i64 = 600; // 10 minutes
const TIME_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes
const NTP_SERVERS: &[&str] = &[
    "time.google.com:123",
    "time.cloudflare.com:123",
    "pool.ntp.org:123",
];

#[derive(Debug, Clone)]
pub struct TimeSample {
    pub source: String,
    pub offset_ms: i64,
    pub latency_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TimeCalibration {
    pub offset_ms: i64,
    pub samples: Vec<TimeSample>,
    pub last_update: DateTime<Utc>,
    pub is_healthy: bool,
}

impl Default for TimeCalibration {
    fn default() -> Self {
        Self {
            offset_ms: 0,
            samples: Vec::new(),
            last_update: Utc::now(),
            is_healthy: true,
        }
    }
}

pub struct TimeSyncService {
    calibration: Arc<RwLock<TimeCalibration>>,
}

impl TimeSyncService {
    pub fn new() -> Self {
        Self {
            calibration: Arc::new(RwLock::new(TimeCalibration::default())),
        }
    }

    pub fn calibration(&self) -> Arc<RwLock<TimeCalibration>> {
        self.calibration.clone()
    }

    /// Get current calibrated time
    pub async fn get_calibrated_time(&self) -> DateTime<Utc> {
        let cal = self.calibration.read().await;
        let now = Utc::now();
        now + chrono::Duration::milliseconds(cal.offset_ms)
    }

    /// Start periodic time synchronization
    pub fn start_sync_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("⏰ Starting time synchronization service");

            // Initial sync
            if let Err(e) = self.sync_time().await {
                error!("❌ Initial time sync failed: {}", e);
            }

            // Periodic sync
            let mut interval = tokio::time::interval(Duration::from_secs(TIME_SYNC_INTERVAL_SECS));
            loop {
                interval.tick().await;

                if let Err(e) = self.sync_time().await {
                    error!("❌ Time sync failed: {}", e);
                }
            }
        });
    }

    /// Synchronize time with NTP servers and network peers
    async fn sync_time(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🔄 Synchronizing time with authorities...");

        let mut samples = Vec::new();

        // Query NTP servers
        for server in NTP_SERVERS {
            match Self::query_ntp_with_latency(server).await {
                Ok(sample) => {
                    debug!(
                        "   ✓ {} offset: {}ms, latency: {}ms",
                        sample.source, sample.offset_ms, sample.latency_ms
                    );
                    samples.push(sample);
                }
                Err(e) => {
                    debug!("   ✗ {}: {}", server, e);
                }
            }
        }

        // TODO: Query network peers once PeerManager integration is complete
        // Peer time queries will provide additional time samples for consensus

        if samples.is_empty() {
            return Err("No time sources available".into());
        }

        // Calculate median offset
        samples.sort_by_key(|s| s.offset_ms);
        let median_offset = if samples.len() % 2 == 0 {
            (samples[samples.len() / 2 - 1].offset_ms + samples[samples.len() / 2].offset_ms) / 2
        } else {
            samples[samples.len() / 2].offset_ms
        };

        // Check if offset is within safe bounds
        let is_healthy = median_offset.abs() <= MAX_SAFE_OFFSET_SECS * 1000;

        if !is_healthy {
            error!(
                "⚠️  CRITICAL: System clock offset too large: {}s",
                median_offset / 1000
            );
            error!("   Node will refuse to produce blocks until clock is fixed!");
        } else if median_offset.abs() > 1000 {
            warn!(
                "⚠️  System clock offset: {}ms (will be calibrated)",
                median_offset
            );
        } else {
            info!("✅ System clock synchronized (offset: {}ms)", median_offset);
        }

        // Update calibration
        let mut cal = self.calibration.write().await;
        cal.offset_ms = median_offset;
        cal.samples = samples;
        cal.last_update = Utc::now();
        cal.is_healthy = is_healthy;

        Ok(())
    }

    // TODO: Peer time queries - will be enabled once PeerManager integration is complete
    /*
    /// Query peer time with latency compensation
    async fn query_peer_time_with_latency(
        manager: Arc<PeerManager>,
        peer: &str,
    ) -> Result<TimeSample, Box<dyn std::error::Error + Send + Sync>> {
        use crate::protocol::NetworkMessage;

        let t1 = Instant::now();
        let local_before = SystemTime::now();
        let request_time_ms = local_before.duration_since(UNIX_EPOCH)?.as_millis() as i64;

        // Send TimeRequest
        let request = NetworkMessage::TimeRequest { request_time_ms };
        let response = manager
            .send_message_and_wait_response(peer, request, Duration::from_secs(5))
            .await?;

        let t3 = Instant::now();
        let local_after = SystemTime::now();

        // Extract peer time from response
        let peer_time_ms = match response {
            NetworkMessage::TimeResponse { peer_time_ms, .. } => peer_time_ms,
            _ => return Err("Invalid response type".into()),
        };

        // Calculate round-trip time
        let rtt = t3.duration_since(t1);
        let one_way_delay_ms = (rtt.as_millis() / 2) as i64;

        // Local time at midpoint of request
        let local_mid = local_before + (local_after.duration_since(local_before)? / 2);
        let local_mid_ms = local_mid.duration_since(UNIX_EPOCH)?.as_millis() as i64;

        // Adjust peer time for one-way delay
        let adjusted_peer_time_ms = peer_time_ms + one_way_delay_ms;

        // Calculate offset
        let offset_ms = adjusted_peer_time_ms - local_mid_ms;

        Ok(TimeSample {
            source: format!("peer:{}", peer),
            offset_ms,
            latency_ms: rtt.as_millis() as u64,
            timestamp: Utc::now(),
        })
    }
    */

    /// Query NTP server with latency compensation
    async fn query_ntp_with_latency(
        server: &str,
    ) -> Result<TimeSample, Box<dyn std::error::Error + Send + Sync>> {
        let t1 = Instant::now();
        let local_before = SystemTime::now();

        // Query NTP (simplified - in production use proper NTP client)
        let ntp_time = Self::query_ntp_simple(server).await?;

        let t3 = Instant::now();
        let local_after = SystemTime::now();

        // Calculate round-trip time
        let rtt = t3.duration_since(t1);
        let one_way_delay = rtt / 2;

        // Local time at midpoint of request
        let local_mid = local_before + (local_after.duration_since(local_before)? / 2);
        let local_mid_dt: DateTime<Utc> = local_mid.into();

        // Adjust NTP time for one-way delay
        let adjusted_ntp = ntp_time + chrono::Duration::from_std(one_way_delay)?;

        // Calculate offset
        let offset = adjusted_ntp.signed_duration_since(local_mid_dt);

        Ok(TimeSample {
            source: server.to_string(),
            offset_ms: offset.num_milliseconds(),
            latency_ms: rtt.as_millis() as u64,
            timestamp: Utc::now(),
        })
    }

    /// Simple NTP query using SNTP protocol
    async fn query_ntp_simple(
        server: &str,
    ) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
        // Use tokio spawn_blocking for sync UDP operations
        let server = server.to_string();
        tokio::task::spawn_blocking(move || {
            // NTP packet format (48 bytes)
            let mut packet = [0u8; 48];
            // Set version (4) and mode (3 = client)
            packet[0] = 0x1b; // 00 011 011 = version 3, mode 3

            // Create UDP socket with timeout
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;

            // Send request
            socket.send_to(&packet, &server)?;

            // Receive response
            let mut response = [0u8; 48];
            let (size, _) = socket.recv_from(&mut response)?;

            if size != 48 {
                return Err("Invalid NTP response size".into());
            }

            // Extract transmit timestamp (bytes 40-47)
            let seconds =
                u32::from_be_bytes([response[40], response[41], response[42], response[43]]);
            let fraction =
                u32::from_be_bytes([response[44], response[45], response[46], response[47]]);

            // NTP epoch is 1900-01-01, Unix epoch is 1970-01-01
            // Difference is 2,208,988,800 seconds
            const NTP_TO_UNIX_OFFSET: u64 = 2_208_988_800;

            let unix_seconds = seconds as u64 - NTP_TO_UNIX_OFFSET;
            let nanos = ((fraction as u64 * 1_000_000_000) >> 32) as u32;

            let system_time =
                UNIX_EPOCH + Duration::from_secs(unix_seconds) + Duration::from_nanos(nanos as u64);
            let datetime: DateTime<Utc> = system_time.into();

            Ok(datetime)
        })
        .await?
    }

    /// Query HTTP time endpoint
    #[allow(dead_code)]
    async fn query_http_time(
        url: &str,
    ) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let response = client.get(url).send().await?;

        // Parse Date header
        if let Some(date) = response.headers().get("date") {
            let date_str = date.to_str()?;
            let parsed = DateTime::parse_from_rfc2822(date_str)?;
            return Ok(parsed.with_timezone(&Utc));
        }

        Err("No date header in response".into())
    }

    /// Check if time calibration is healthy
    pub async fn is_healthy(&self) -> bool {
        self.calibration.read().await.is_healthy
    }

    /// Get current offset in milliseconds
    pub async fn get_offset_ms(&self) -> i64 {
        self.calibration.read().await.offset_ms
    }
}

impl Default for TimeSyncService {
    fn default() -> Self {
        Self::new()
    }
}
