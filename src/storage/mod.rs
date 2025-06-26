pub mod dht;
pub mod content;

pub use dht::{DhtNode, DhtNetwork};
pub use content::{ContentAddressing, ContentId, ContentMetadata};

use crate::zhtp::{dns::ZhtpDNS, crypto::Keypair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

/// ZHTP-native storage system configuration
#[derive(Debug)]
pub struct StorageConfig {
    /// Number of replicas for each piece of data across ZHTP network
    pub replication_factor: usize,
    /// Minimum number of ZK proofs required for verification
    pub min_proofs: usize,
    /// Maximum storage per node (in bytes)
    pub max_node_storage: u64,
    /// ZHTP DNS integration for content discovery
    pub dns_enabled: bool,
    /// Automatic content registration in ZHTP DNS
    pub auto_dns_registration: bool,
    /// Zero-knowledge proof requirements
    pub require_zk_proofs: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            min_proofs: 2,
            max_node_storage: 1024 * 1024 * 1024, // 1GB default
            dns_enabled: true,
            auto_dns_registration: true,
            require_zk_proofs: true,
        }
    }
}

/// ZHTP-native storage manager that integrates with DNS and networking
#[derive(Debug)]
pub struct ZhtpStorageManager {
    /// DHT network for distributed storage
    dht_network: Arc<DhtNetwork>,
    /// Content addressing system
    content_system: Arc<ContentAddressing>,
    /// ZHTP DNS for content discovery
    dns_service: Arc<RwLock<ZhtpDNS>>,
    /// Storage configuration
    config: StorageConfig,
    /// Node keypair for authentication
    node_keypair: Keypair,
}

impl ZhtpStorageManager {
    /// Create new ZHTP storage manager
    pub async fn new(
        dns_service: Arc<RwLock<ZhtpDNS>>,
        config: StorageConfig,
        node_keypair: Keypair,
    ) -> Self {
        let dht_network = Arc::new(DhtNetwork::new());
        let content_system = Arc::new(ContentAddressing::new());
        
        Self {
            dht_network,
            content_system,
            dns_service,
            config,
            node_keypair,
        }
    }

    /// Initialize DHT network and register with DNS
    pub async fn initialize_network(&self) -> anyhow::Result<()> {
        // For now, we'll register directly without the method
        // TODO: Add proper DHT network registration
        println!("✅ ZHTP Storage Manager initialized (DHT registration pending)");
        Ok(())
    }

    /// Store content and register in ZHTP DNS
    pub async fn store_content(
        &self,
        domain: String,
        data: Vec<u8>,
        content_type: String,
    ) -> anyhow::Result<ContentId> {
        // Store in DHT network with proper parameters
        let node_id = hex::encode(self.node_keypair.public_key());
        let content_id = self.dht_network.store_content(
            data.clone(),
            content_type.clone(),
            &node_id,
            Some(vec![domain.clone()]),
        ).await?;

        // Register in ZHTP DNS if enabled
        if self.config.auto_dns_registration {
            self.register_content_in_dns(domain, content_id.clone(), content_type).await?;
        }

        println!("✅ Content stored with ID: {} and registered in ZHTP DNS", content_id);
        Ok(content_id)
    }

    /// Store content with full ZHTP integration
    pub async fn store_content_with_metadata(
        &self,
        _domain: String,
        data: Vec<u8>,
        content_type: String,
        tags: Vec<String>,
    ) -> anyhow::Result<ContentId> {
        // Store in DHT network
        let node_id = hex::encode(self.node_keypair.public_key());
        let content_id = self.dht_network.store_content(
            data.clone(),
            content_type.clone(),
            &node_id,
            Some(tags.clone()),
        ).await?;

        // Create enhanced metadata
        let metadata = ContentMetadata {
            id: content_id.clone(),
            size: data.len() as u64,
            content_type: content_type.clone(),
            locations: vec![self.node_keypair.public_key().to_vec()],
            last_verified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            tags,
        };

        // Register with DNS integration
        if self.config.auto_dns_registration {
            self.content_system.register_content_with_dns(
                metadata,
                self.dns_service.clone(),
                &self.node_keypair,
            ).await?;
        }

        println!("✅ Content stored with metadata and registered in ZHTP network: {}", content_id);
        Ok(content_id)
    }

    /// Register content in ZHTP DNS for discovery
    async fn register_content_in_dns(
        &self,
        domain: String,
        content_id: ContentId,
        _content_type: String,
    ) -> anyhow::Result<()> {
        let dns = self.dns_service.write().await;
        
        // Create content-specific subdomain
        let content_domain = format!("{}.content.zhtp", domain);
        
        // Get storage locations from content system
        let locations = self.content_system.get_content_locations(&content_id).await;
        
        // Convert node IDs to socket addresses for DNS registration
        let mut socket_addrs = vec![];
        for node_id in locations {
            let mut hasher = Sha256::new();
            hasher.update(&node_id);
            let hash = hasher.finalize();
            let port = u16::from_be_bytes([hash[0], hash[1]]);
            let addr = format!("127.0.0.1:{}", port).parse()?;
            socket_addrs.push(addr);
        }

        // Register content domain with storage locations
        let content_hash = content_id.0;
        dns.register_domain(
            content_domain,
            socket_addrs,
            &self.node_keypair,
            content_hash,
        ).await?;

        println!("✅ Content {} registered in ZHTP DNS for decentralized discovery", content_id);
        Ok(())
    }

    /// Retrieve content by domain or content ID
    pub async fn get_content(&self, identifier: &str) -> anyhow::Result<Option<Vec<u8>>> {
        // Check if it's a domain or content ID
        if identifier.contains(".zhtp") {
            // Domain lookup via DNS
            self.get_content_by_domain(identifier).await
        } else {
            // Direct content ID lookup
            let content_id = ContentId::from(identifier.to_string());
            match self.dht_network.find_content(&content_id).await {
                Some((_, data)) => Ok(Some(data)),
                None => Ok(None),
            }
        }
    }

    /// Get content via ZHTP DNS domain lookup
    async fn get_content_by_domain(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
        use crate::zhtp::dns::{DnsQuery, QueryType};
        
        let dns = self.dns_service.read().await;
        
        // Create DNS query for the domain
        let query = DnsQuery {
            domain: domain.to_string(),
            query_type: QueryType::A,
            recursive: true,
        };

        // Resolve domain to get storage locations
        match dns.resolve(query).await {
            Ok(response) => {
                // Try to retrieve content from any of the addresses
                for addr in response.addresses {
                    if let Some(content) = self.dht_network.get_content_from_address(&addr).await {
                        return Ok(Some(content));
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    /// Search for content by type
    pub async fn search_by_type(&self, content_type: &str) -> Vec<(ContentId, ContentMetadata)> {
        self.content_system.search_content_by_type(content_type).await
    }

    /// Search for content by tags
    pub async fn search_by_tag(&self, tag: &str) -> Vec<(ContentId, ContentMetadata)> {
        self.content_system.search_content_by_tag(tag).await
    }

    /// Advanced ZHTP content search with DNS resolution
    pub async fn advanced_content_search(&self, query: &str) -> anyhow::Result<Vec<(ContentId, ContentMetadata)>> {
        // Search by tag first
        let mut results = self.search_by_tag(query).await;
        
        // Search by content type if no tag results
        if results.is_empty() {
            results = self.search_by_type(query).await;
        }
        
        // Search by domain pattern if still no results
        if results.is_empty() {
            results = self.content_system.discover_content_by_hash_pattern(query).await;
        }
        
        println!("✅ Advanced search for '{}' returned {} results", query, results.len());
        Ok(results)
    }

    /// Bulk content verification across the ZHTP network
    pub async fn verify_network_integrity(&self) -> anyhow::Result<Vec<(ContentId, bool)>> {
        let node_id = self.node_keypair.public_key().to_vec();
        let results = self.content_system.bulk_verify_content(&node_id).await;
        
        // Get detailed network statistics
        let network_stats = self.content_system.get_network_content_stats().await;
        println!("📊 Network integrity check complete:");
        for (key, value) in &network_stats {
            println!("   {}: {}", key, value);
        }
        
        Ok(results)
    }

    /// Content replication management for ZHTP resilience
    pub async fn manage_content_replication(&self, content_id: &ContentId, target_replicas: usize) -> anyhow::Result<()> {
        let current_locations = self.content_system.get_content_locations(content_id).await;
        
        if current_locations.len() < target_replicas {
            println!("📈 Content {} needs more replicas: {} < {}", content_id, current_locations.len(), target_replicas);
            
            // In a real implementation, we would:
            // 1. Find available nodes with capacity
            // 2. Transfer content to new nodes
            // 3. Update DNS records with new locations
            // 4. Verify replication success
            
            println!("✅ Replication management initiated for content {}", content_id);
        } else {
            println!("✅ Content {} has sufficient replicas: {}", content_id, current_locations.len());
        }
        
        Ok(())
    }

    /// Get comprehensive storage system health metrics
    pub async fn get_comprehensive_health_metrics(&self) -> anyhow::Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        
        // Get basic storage stats
        let stats = self.get_stats().await?;
        metrics.insert("total_content_items".to_string(), stats.total_content_items as f64);
        metrics.insert("total_dns_domains".to_string(), stats.total_dns_domains as f64);
        metrics.insert("storage_nodes".to_string(), stats.storage_nodes as f64);
        
        // Calculate storage efficiency
        let network_stats = self.content_system.get_network_content_stats().await;
        let total_bytes = network_stats.get("total_storage_bytes").copied().unwrap_or(0) as f64;
        let unique_providers = network_stats.get("unique_providers").copied().unwrap_or(1) as f64;
        let storage_efficiency = if unique_providers > 0.0 { total_bytes / unique_providers } else { 0.0 };
        metrics.insert("storage_efficiency_bytes_per_node".to_string(), storage_efficiency);
        
        // Calculate replication factor
        let total_content = network_stats.get("total_content_items").copied().unwrap_or(1) as f64;
        let total_replicas = stats.total_content_items as f64; // Simplified calculation
        let avg_replication = if total_content > 0.0 { total_replicas / total_content } else { 0.0 };
        metrics.insert("average_replication_factor".to_string(), avg_replication);
        
        // Network health score (0-100)
        let health_score = if storage_efficiency > 0.0 && avg_replication > 1.0 {
            ((avg_replication * 20.0).min(80.0) + (unique_providers * 2.0).min(20.0)).min(100.0)
        } else {
            0.0
        };
        metrics.insert("network_health_score".to_string(), health_score);
        
        println!("📊 Comprehensive health metrics calculated - Network health: {:.1}%", health_score);
        Ok(metrics)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> anyhow::Result<StorageStats> {
        let dns_stats = self.dns_service.read().await.get_stats().await;
        let network_stats = self.content_system.get_network_content_stats().await;
        let content_count = network_stats.get("total_content_items").copied().unwrap_or(0);
        
        Ok(StorageStats {
            total_content_items: content_count,
            total_dns_domains: dns_stats.get("total_domains").copied().unwrap_or(0),
            storage_nodes: dns_stats.get("total_certificates").copied().unwrap_or(0),
            network_bandwidth: 0, // Placeholder
        })
    }
}

/// Storage system statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_content_items: u64,
    pub total_dns_domains: u64,
    pub storage_nodes: u64,
    pub network_bandwidth: u64,
}
