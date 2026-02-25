//! UPnP port forwarding support for NAT traversal
//!
//! Automatically configures router port forwarding for P2P and RPC ports
//! to allow incoming connections from the internet.

use std::net::SocketAddrV4;
use std::time::Duration;
use tracing::{debug, info, warn};

/// UPnP port forwarding manager
pub struct UpnpManager {
    gateway: Option<igd_next::Gateway>,
    local_addr: SocketAddrV4,
}

impl UpnpManager {
    /// Create a new UPnP manager and attempt to discover the gateway
    pub async fn new(local_addr: SocketAddrV4) -> Self {
        let gateway = tokio::task::spawn_blocking(move || {
            match igd_next::search_gateway(igd_next::SearchOptions {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            }) {
                Ok(gateway) => {
                    info!("✓ UPnP gateway discovered: {}", gateway.addr);
                    Some(gateway)
                }
                Err(e) => {
                    warn!("⚠️  UPnP gateway discovery failed: {}", e);
                    warn!("   Port forwarding will not be configured automatically");
                    None
                }
            }
        })
        .await
        .unwrap_or(None);

        Self {
            gateway,
            local_addr,
        }
    }

    /// Add a port forwarding rule
    pub async fn add_port_forwarding(
        &self,
        external_port: u16,
        _internal_port: u16,
        protocol: igd_next::PortMappingProtocol,
        description: &str,
    ) -> Result<(), String> {
        let gateway = match &self.gateway {
            Some(g) => g,
            None => return Err("No UPnP gateway available".to_string()),
        };

        let gateway = gateway.clone();
        let local_addr = self.local_addr;
        let description = description.to_string();

        tokio::task::spawn_blocking(move || {
            gateway
                .add_port(
                    protocol,
                    external_port,
                    std::net::SocketAddr::V4(local_addr),
                    3600, // Lease duration: 1 hour
                    &description,
                )
                .map_err(|e| format!("Failed to add port forwarding: {}", e))
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }

    /// Remove a port forwarding rule
    pub async fn remove_port_forwarding(
        &self,
        external_port: u16,
        protocol: igd_next::PortMappingProtocol,
    ) -> Result<(), String> {
        let gateway = match &self.gateway {
            Some(g) => g,
            None => return Err("No UPnP gateway available".to_string()),
        };

        let gateway = gateway.clone();

        tokio::task::spawn_blocking(move || {
            gateway
                .remove_port(protocol, external_port)
                .map_err(|e| format!("Failed to remove port forwarding: {}", e))
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }

    /// Get the external IP address from the gateway
    pub async fn get_external_ip(&self) -> Result<String, String> {
        let gateway = match &self.gateway {
            Some(g) => g,
            None => return Err("No UPnP gateway available".to_string()),
        };

        let gateway = gateway.clone();

        tokio::task::spawn_blocking(move || {
            gateway
                .get_external_ip()
                .map(|ip| ip.to_string())
                .map_err(|e| format!("Failed to get external IP: {}", e))
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }

    /// Renew port forwarding lease (should be called periodically)
    pub async fn renew_port_forwarding(
        &self,
        external_port: u16,
        internal_port: u16,
        protocol: igd_next::PortMappingProtocol,
        description: &str,
    ) -> Result<(), String> {
        // Remove and re-add to renew
        let _ = self.remove_port_forwarding(external_port, protocol).await;
        self.add_port_forwarding(external_port, internal_port, protocol, description)
            .await
    }

    /// Setup common port forwarding for TIME node
    pub async fn setup_time_node_ports(&self, p2p_port: u16, rpc_port: u16) -> Result<(), String> {
        if self.gateway.is_none() {
            return Err("No UPnP gateway available".to_string());
        }

        // Forward P2P port (TCP)
        match self
            .add_port_forwarding(
                p2p_port,
                p2p_port,
                igd_next::PortMappingProtocol::TCP,
                "TIME P2P",
            )
            .await
        {
            Ok(_) => {
                info!("✓ UPnP port forwarding configured: TCP port {}", p2p_port);
            }
            Err(e) => {
                warn!("⚠️  Failed to forward P2P port {}: {}", p2p_port, e);
            }
        }

        // Forward RPC port (TCP)
        match self
            .add_port_forwarding(
                rpc_port,
                rpc_port,
                igd_next::PortMappingProtocol::TCP,
                "TIME RPC",
            )
            .await
        {
            Ok(_) => {
                info!("✓ UPnP port forwarding configured: TCP port {}", rpc_port);
            }
            Err(e) => {
                warn!("⚠️  Failed to forward RPC port {}: {}", rpc_port, e);
            }
        }

        Ok(())
    }

    /// Cleanup port forwarding on shutdown
    pub async fn cleanup(&self, p2p_port: u16, rpc_port: u16) {
        if self.gateway.is_none() {
            return;
        }

        debug!("Cleaning up UPnP port forwarding...");

        let _ = self
            .remove_port_forwarding(p2p_port, igd_next::PortMappingProtocol::TCP)
            .await;
        let _ = self
            .remove_port_forwarding(rpc_port, igd_next::PortMappingProtocol::TCP)
            .await;

        info!("✓ UPnP port forwarding cleaned up");
    }

    /// Spawn a background task to renew port forwarding leases
    pub fn spawn_renewal_task(
        self: std::sync::Arc<Self>,
        p2p_port: u16,
        rpc_port: u16,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1800)); // Renew every 30 minutes

            loop {
                interval.tick().await;

                debug!("Renewing UPnP port forwarding leases...");

                let _ = self
                    .renew_port_forwarding(
                        p2p_port,
                        p2p_port,
                        igd_next::PortMappingProtocol::TCP,
                        "TIME P2P",
                    )
                    .await;

                let _ = self
                    .renew_port_forwarding(
                        rpc_port,
                        rpc_port,
                        igd_next::PortMappingProtocol::TCP,
                        "TIME RPC",
                    )
                    .await;
            }
        })
    }
}
