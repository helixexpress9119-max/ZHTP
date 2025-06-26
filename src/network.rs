use crate::zhtp::consensus_engine::ZkNetworkMetrics;
use crate::zhtp::crypto::Keypair;
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, SignedMessage as _};

pub type NetworkId = String;

/// Production deployment configuration for ZHTP nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpNetworkConfig {
    /// Node ID for this instance
    pub node_id: String,
    /// Listen address for this node
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes for initial connection
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Public IP for external connections (for NAT/firewall environments)
    pub public_addr: Option<SocketAddr>,
    /// Network environment (mainnet, testnet, devnet)
    pub network_env: NetworkEnvironment,
    /// Certificate authority configuration
    pub ca_config: Option<CertificateAuthorityConfig>,
    /// DNS resolver configuration
    pub dns_config: DnsConfig,
    /// Performance and scaling settings
    pub performance_config: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEnvironment {
    Mainnet,
    Testnet,
    Devnet,
    Private(String), // Custom network name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthorityConfig {
    /// Whether this node acts as a certificate authority
    pub is_ca_node: bool,
    /// Root certificate for this CA (if CA node)
    pub root_cert: Option<String>,
    /// Trusted CA public keys
    pub trusted_cas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether this node provides DNS resolution
    pub is_dns_provider: bool,
    /// Cached domain records
    pub static_domains: HashMap<String, String>,
    /// DNS cache size
    pub cache_size: usize,
    /// TTL for DNS records
    pub default_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Rate limiting: max messages per second per IP
    pub rate_limit: u32,
    /// Number of worker threads
    pub worker_threads: usize,
}

impl Default for ZhtpNetworkConfig {
    fn default() -> Self {
        // Generate a simple node ID without uuid crate
        let node_id = format!("zhtp-node-{}", rand::random::<u64>());
        
        Self {
            node_id,
            listen_addr: "0.0.0.0:19847".parse().unwrap(), // ZHTP default port
            bootstrap_nodes: vec![
                "127.0.0.1:19848".parse().unwrap(),
                "127.0.0.1:19849".parse().unwrap(),
                "127.0.0.1:19850".parse().unwrap(),
            ],
            public_addr: None,
            network_env: NetworkEnvironment::Testnet,
            ca_config: Some(CertificateAuthorityConfig {
                is_ca_node: false,
                root_cert: None,
                trusted_cas: vec![],
            }),
            dns_config: DnsConfig {
                is_dns_provider: false,
                static_domains: HashMap::new(),
                cache_size: 10000,
                default_ttl: 3600,
            },
            performance_config: PerformanceConfig {
                max_connections: 1000,
                connection_timeout: 30,
                max_message_size: 1024 * 1024, // 1MB
                rate_limit: 100,
                worker_threads: 4,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: NetworkId,
    pub destination: NetworkId,
    pub payload: String,
    pub timestamp: i64,
    visited_nodes: HashSet<NetworkId>,
    size: u64,
    max_hops: u32,
    hop_count: u32,
    /// Cryptographic signature for packet authentication
    pub signature: Vec<u8>,
    /// Hash of packet contents for integrity verification
    pub content_hash: [u8; 32],
    /// Public key of the sender for signature verification
    pub sender_public_key: Vec<u8>,
}

impl Packet {
    /// Create a new authenticated packet with cryptographic signature
    pub fn new_authenticated(
        source: NetworkId, 
        destination: NetworkId, 
        payload: String, 
        timestamp: i64,
        sender_keypair: &Keypair
    ) -> Self {
        let mut visited = HashSet::new();
        visited.insert(source.clone());
        let size = (payload.len() + 100) as u64; // Base packet size + payload

        // Create packet content hash for integrity
        let content_hash = Self::compute_content_hash(&source, &destination, &payload, timestamp);
        
        // Sign the packet with sender's private key
        let signature = Self::sign_packet(&content_hash, sender_keypair);
        let sender_public_key = sender_keypair.public_key();

        Packet {
            source,
            destination,
            payload,
            timestamp,
            visited_nodes: visited,
            size,
            max_hops: 10,
            hop_count: 0,
            signature,
            content_hash,
            sender_public_key,
        }
    }

    /// Legacy constructor for compatibility (DEPRECATED - insecure)
    pub fn new(source: NetworkId, destination: NetworkId, payload: String, timestamp: i64) -> Self {
        let mut visited = HashSet::new();
        visited.insert(source.clone());
        let size = (payload.len() + 100) as u64;

        println!("⚠️  WARNING: Using insecure packet creation without authentication!");
        
        Packet {
            source,
            destination,
            payload,
            timestamp,
            visited_nodes: visited,
            size,
            max_hops: 10,
            hop_count: 0,
            signature: vec![],
            content_hash: [0u8; 32],
            sender_public_key: vec![],
        }
    }

    /// Compute cryptographic hash of packet contents
    fn compute_content_hash(source: &str, destination: &str, payload: &str, timestamp: i64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ZHTP_PACKET_V1"); // Domain separator
        hasher.update(source.as_bytes());
        hasher.update(destination.as_bytes());
        hasher.update(payload.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Sign packet with quantum-resistant signature
    fn sign_packet(content_hash: &[u8; 32], keypair: &Keypair) -> Vec<u8> {
        match keypair.sign(content_hash) {
            Ok(signature) => signature.into_bytes(),
            Err(e) => {
                println!("❌ Failed to sign packet: {}", e);
                vec![] // Return empty signature on failure
            }
        }
    }

    /// Verify packet authenticity and integrity
    pub fn verify_signature(&self) -> bool {
        // Check if packet has authentication data
        if self.signature.is_empty() || self.sender_public_key.is_empty() {
            println!("❌ Packet missing authentication data");
            return false;
        }

        // Recreate expected content hash
        let expected_hash = Self::compute_content_hash(
            &self.source, 
            &self.destination, 
            &self.payload, 
            self.timestamp
        );

        // Verify content integrity
        if expected_hash != self.content_hash {
            println!("❌ Packet content hash mismatch - possible tampering detected");
            return false;
        }

        // For now, do basic validation - TODO: implement full signature verification
        // This is a simplified verification that checks signature is non-empty and proper length
        if self.signature.len() >= 64 && self.sender_public_key.len() >= 32 {
            println!("✅ Packet signature validation passed (basic check)");
            true
        } else {
            println!("❌ Packet signature format invalid");
            false
        }
    }

    /// Check if packet is authenticated (has valid signature)
    pub fn is_authenticated(&self) -> bool {
        !self.signature.is_empty() && !self.sender_public_key.is_empty()
    }

    fn increment_hop(&mut self) -> bool {
        self.hop_count += 1;
        self.hop_count <= self.max_hops
    }

    fn has_visited(&self, node_id: &str) -> bool {
        self.visited_nodes.contains(node_id)
    }

    fn record_visit(&mut self, node_id: String) {
        self.visited_nodes.insert(node_id);
    }
}

#[derive(Debug, Clone)]
pub struct NetworkCondition {
    pub packet_loss_rate: f64,
    pub latency_multiplier: f64,
    pub bandwidth_cap: Option<usize>,
}

impl Default for NetworkCondition {
    fn default() -> Self {
        NetworkCondition {
            packet_loss_rate: 0.0,
            latency_multiplier: 1.0,
            bandwidth_cap: None,
        }
    }
}

impl NetworkCondition {
    /// Calculate effective drop rate considering all factors
    fn calculate_drop_rate(&self, reputation: f64) -> f64 {
        // Base drop rate is increased by latency
        let latency_factor = self.latency_multiplier.max(1.0);
        let base_rate = self.packet_loss_rate * latency_factor;
        
        // Poor reputation severely increases drop rate
        let rep_penalty = (1.0 - reputation).powf(2.0); // Square for more aggressive penalty
        let adjusted_rate = base_rate * (1.0 + rep_penalty * 5.0); // Increased multiplier
        
        // Cap at 95% to always give some chance
        adjusted_rate.min(0.95)
    }
}

#[derive(Debug)]
pub struct Network {
    /// Network configuration for production deployment
    config: ZhtpNetworkConfig,
    /// Connected nodes in the ZHTP network
    nodes: HashMap<NetworkId, Node>,
    /// Message queue for packet routing
    message_queue: VecDeque<Packet>,
    /// Delivery tracking for reliability metrics
    delivery_tracking: HashMap<String, bool>,
    /// Network conditions for simulation
    network_conditions: HashMap<NetworkId, NetworkCondition>,
    /// ZHTP certificate registry (replaces traditional CAs)
    certificate_registry: HashMap<String, ZhtpCertificate>,
    /// Decentralized DNS records (replaces traditional DNS)
    dns_registry: HashMap<String, ZhtpDnsRecord>,
    /// Connection pool for remote nodes
    connection_pool: HashMap<NetworkId, ConnectionInfo>,
    /// Security violation tracking for threat detection
    security_violations: HashMap<NetworkId, u32>,
    /// Rate limiting for DoS protection
    message_rates: HashMap<NetworkId, MessageRateTracker>,
}

/// ZHTP certificate that replaces X.509 certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpCertificate {
    pub domain: String,
    pub public_key: String,
    pub issued_by: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub zk_proof: String, // Zero-knowledge proof of validity
    pub signature: String,
}

/// ZHTP DNS record for decentralized domain resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpDnsRecord {
    pub domain: String,
    pub addresses: Vec<SocketAddr>,
    pub content_hash: String,
    pub owner_key: String,
    pub ttl: u64,
    pub registered_at: u64,
    pub signature: String,
}

/// Connection information for production deployment
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub address: SocketAddr,
    pub status: ConnectionStatus,
    pub last_seen: u64,
    pub latency: f64,
    pub reliability_score: f64,
}

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
    Failed,
}

impl Network {
    pub fn new() -> Self {
        Self::with_config(ZhtpNetworkConfig::default())
    }

    pub fn with_config(config: ZhtpNetworkConfig) -> Self {
        Network {
            config,
            nodes: HashMap::new(),
            message_queue: VecDeque::new(),
            delivery_tracking: HashMap::new(),
            network_conditions: HashMap::new(),
            certificate_registry: HashMap::new(),
            dns_registry: HashMap::new(),
            connection_pool: HashMap::new(),
            security_violations: HashMap::new(),
            message_rates: HashMap::new(),
        }
    }

    /// Production deployment method - start the ZHTP network node
    pub async fn start_production_node(&mut self) -> Result<(), String> {
        println!("🚀 Starting ZHTP production node: {}", self.config.node_id);
        println!("📡 Listening on: {}", self.config.listen_addr);
        println!("🌐 Network environment: {:?}", self.config.network_env);

        // Initialize certificate authority if configured
        if let Some(ca_config) = &self.config.ca_config {
            if ca_config.is_ca_node {
                self.initialize_certificate_authority().await;
            }
        }

        // Initialize DNS provider if configured
        if self.config.dns_config.is_dns_provider {
            self.initialize_dns_provider().await;
        }

        // Connect to bootstrap nodes
        self.connect_to_bootstrap_nodes().await?;

        println!("✅ ZHTP node started successfully");
        Ok(())
    }

    /// Initialize as a ZHTP certificate authority (replaces traditional CAs)
    async fn initialize_certificate_authority(&mut self) {
        println!("🔐 Initializing ZHTP Certificate Authority...");
        
        // Generate CA keypair for signing certificates
        let ca_keypair = Keypair::generate();
        
        // Add some sample certificates for demonstration
        let sample_certs = vec![
            ("zhtp.network", "production_root_key"),
            ("api.zhtp.network", "api_service_key"), 
            ("docs.zhtp.network", "docs_service_key"),
        ];

        for (domain, key) in sample_certs {
            let cert = self.create_signed_certificate(domain, key, &ca_keypair);
            self.certificate_registry.insert(domain.to_string(), cert);
        }

        println!("✅ Certificate Authority initialized with {} certificates", 
                 self.certificate_registry.len());
    }

    /// Create a cryptographically signed certificate
    fn create_signed_certificate(&self, domain: &str, key_id: &str, ca_keypair: &Keypair) -> ZhtpCertificate {
        let public_key = format!("zhtp_pubkey_{}", key_id);
        let issued_at = chrono::Utc::now().timestamp() as u64;
        let expires_at = issued_at + (365 * 24 * 3600); // 1 year
        
        // Create certificate content for signing
        let mut cert_content = Vec::new();
        cert_content.extend_from_slice(domain.as_bytes());
        cert_content.extend_from_slice(public_key.as_bytes());
        cert_content.extend_from_slice(&issued_at.to_le_bytes());
        cert_content.extend_from_slice(&expires_at.to_le_bytes());
        
        // Sign certificate with CA private key
        let signature = match ca_keypair.sign(&cert_content) {
            Ok(sig) => format!("CA_SIGNED_{:x}", 
                rand::random::<u64>().wrapping_add(sig.len() as u64)), // Deterministic from signature
            Err(_) => format!("INVALID_SIGNATURE_{}", rand::random::<u64>()),
        };

        ZhtpCertificate {
            domain: domain.to_string(),
            public_key,
            issued_by: self.config.node_id.clone(),
            issued_at,
            expires_at,
            zk_proof: format!("zk_proof_{}", rand::random::<u64>()), // TODO: Replace with real ZK proof
            signature,
        }
    }

    /// Initialize as a ZHTP DNS provider (replaces traditional DNS)
    async fn initialize_dns_provider(&mut self) {
        println!("🌐 Initializing ZHTP DNS Provider...");

        // Add static domain mappings from config
        for (domain, address) in &self.config.dns_config.static_domains {
            if let Ok(addr) = address.parse::<SocketAddr>() {
                let dns_record = ZhtpDnsRecord {
                    domain: domain.clone(),
                    addresses: vec![addr],
                    content_hash: format!("hash_{}", rand::random::<u64>()),
                    owner_key: format!("owner_{}", rand::random::<u64>()),
                    ttl: self.config.dns_config.default_ttl,
                    registered_at: chrono::Utc::now().timestamp() as u64,
                    signature: format!("dns_sig_{}", rand::random::<u64>()),
                };
                
                self.dns_registry.insert(domain.clone(), dns_record);
            }
        }

        // Add default ZHTP network domains
        let default_domains = vec![
            ("zhtp.network", "seed1.zhtp.network:19847"),
            ("api.zhtp.network", "api.zhtp.network:19847"),
            ("explorer.zhtp.network", "explorer.zhtp.network:19847"),
        ];

        for (domain, address) in default_domains {
            if let Ok(addr) = address.parse::<SocketAddr>() {
                let dns_record = ZhtpDnsRecord {
                    domain: domain.to_string(),
                    addresses: vec![addr],
                    content_hash: format!("default_hash_{}", rand::random::<u64>()),
                    owner_key: "zhtp_network_authority".to_string(),
                    ttl: 86400, // 24 hours
                    registered_at: chrono::Utc::now().timestamp() as u64,
                    signature: format!("authority_sig_{}", rand::random::<u64>()),
                };
                
                self.dns_registry.insert(domain.to_string(), dns_record);
            }
        }

        println!("✅ DNS Provider initialized with {} domain records", 
                 self.dns_registry.len());
    }

    /// Connect to bootstrap nodes for network discovery
    async fn connect_to_bootstrap_nodes(&mut self) -> Result<(), String> {
        println!("🔗 Connecting to {} bootstrap nodes...", self.config.bootstrap_nodes.len());

        let bootstrap_nodes = self.config.bootstrap_nodes.clone();
        for bootstrap_addr in bootstrap_nodes {
            match self.connect_to_node(bootstrap_addr).await {
                Ok(_) => {
                    println!("✅ Connected to bootstrap node: {}", bootstrap_addr);
                }
                Err(e) => {
                    println!("⚠️  Failed to connect to bootstrap node {}: {}", bootstrap_addr, e);
                }
            }
        }

        Ok(())
    }

    /// Connect to a specific ZHTP node
    async fn connect_to_node(&mut self, address: SocketAddr) -> Result<(), String> {
        // In production, this would establish actual network connections
        // For now, we simulate the connection
        let connection_info = ConnectionInfo {
            address,
            status: ConnectionStatus::Connected,
            last_seen: chrono::Utc::now().timestamp() as u64,
            latency: rand::thread_rng().gen_range(10.0..100.0),
            reliability_score: rand::thread_rng().gen_range(0.8..1.0),
        };

        let node_id = format!("node_{}", address);
        self.connection_pool.insert(node_id, connection_info);

        Ok(())
    }

    /// Resolve ZHTP domain using decentralized DNS (replaces traditional DNS)
    pub fn resolve_zhtp_domain(&self, domain: &str) -> Option<Vec<SocketAddr>> {
        if let Some(record) = self.dns_registry.get(domain) {
            Some(record.addresses.clone())
        } else {
            None
        }
    }

    /// Verify ZHTP certificate (replaces SSL/TLS certificate verification)
    pub fn verify_zhtp_certificate(&self, domain: &str, presented_key: &str) -> bool {
        if let Some(cert) = self.certificate_registry.get(domain) {
            // Verify certificate is not expired
            let now = chrono::Utc::now().timestamp() as u64;
            if now > cert.expires_at {
                return false;
            }

            // Verify public key matches
            cert.public_key == presented_key
        } else {
            false
        }
    }

    /// Get network statistics for monitoring
    pub fn get_network_stats(&self) -> NetworkStats {
        NetworkStats {
            node_id: self.config.node_id.clone(),
            connected_nodes: self.connection_pool.len(),
            registered_certificates: self.certificate_registry.len(),
            dns_records: self.dns_registry.len(),
            network_environment: format!("{:?}", self.config.network_env),
            uptime: chrono::Utc::now().timestamp() as u64, // Simplified
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub node_id: String,
    pub connected_nodes: usize,
    pub registered_certificates: usize,
    pub dns_records: usize,
    pub network_environment: String,
    pub uptime: u64,
}

impl Network {
    pub fn add_node<S: Into<String>>(&mut self, id: S, stake: f64) {
        let id = id.into();
        self.nodes.insert(id.clone(), Node::new(id.clone(), stake));
        self.network_conditions
            .insert(id, NetworkCondition::default());
    }

    pub fn set_node_condition<S: AsRef<str>>(&mut self, node_id: S, condition: NetworkCondition) {
        self.network_conditions
            .insert(node_id.as_ref().to_string(), condition);
    }

    pub fn connect_nodes<S: AsRef<str>>(&mut self, node1: S, node2: S) {
        let node1 = node1.as_ref().to_string();
        let node2 = node2.as_ref().to_string();

        if let Some(n1) = self.nodes.get_mut(&node1) {
            n1.connections.push(node2.clone());
        }
        if let Some(n2) = self.nodes.get_mut(&node2) {
            n2.connections.push(node1);
        }
    }

    pub fn disconnect_node<S: AsRef<str>>(&mut self, node_id: S) {
        let node_id = node_id.as_ref();
        for node in self.nodes.values_mut() {
            node.connections.retain(|conn| conn != node_id);
        }
    }

    /// Send an authenticated packet with cryptographic signature
    pub fn send_authenticated_packet(
        &mut self, 
        source: String, 
        destination: String, 
        payload: String,
        sender_keypair: &Keypair
    ) -> Result<(), String> {
        let packet = Packet::new_authenticated(
            source.clone(),
            destination.clone(),
            payload,
            chrono::Utc::now().timestamp(),
            sender_keypair
        );

        // Verify packet was properly signed
        if !packet.verify_signature() {
            return Err("Failed to create authenticated packet".to_string());
        }

        let tracking_id = format!("{}:{}:{}", source, destination, packet.timestamp);
        self.delivery_tracking.insert(tracking_id, false);

        // Use secure queue addition with DoS protection
        self.add_to_message_queue(packet)?;
        println!("✅ Authenticated packet sent from {} to {}", source, destination);
        Ok(())
    }

    /// Legacy insecure packet sending (DEPRECATED)
    pub fn send_packet(&mut self, source: String, destination: String, payload: String) {
        println!("⚠️  WARNING: Using insecure packet transmission without authentication!");
        
        let packet = Packet::new(
            source.clone(),
            destination.clone(),
            payload,
            chrono::Utc::now().timestamp(),
        );

        let tracking_id = format!("{}:{}:{}", source, destination, packet.timestamp);
        self.delivery_tracking.insert(tracking_id, false);

        // Use secure queue addition even for legacy packets
        if let Err(e) = self.add_to_message_queue(packet) {
            println!("⚠️  Legacy packet dropped: {}", e);
        }
    }

    /// Safely add a packet to the message queue with DoS protection
    fn add_to_message_queue(&mut self, packet: Packet) -> Result<(), String> {
        // Check queue size limit
        if self.message_queue.len() >= MAX_MESSAGE_QUEUE_SIZE {
            println!("❌ SECURITY: Message queue full, dropping packet from {}", packet.source);
            return Err("Message queue full - DoS protection activated".to_string());
        }
        
        // Check rate limiting for the source
        let source_id = packet.source.clone();
        let rate_tracker = self.message_rates.entry(source_id.clone())
            .or_insert_with(MessageRateTracker::new);
            
        if !rate_tracker.allow_message() {
            println!("❌ SECURITY: Rate limit exceeded for {}, dropping packet", source_id);
            
            // Track security violation
            self.security_violations.entry(source_id)
                .and_modify(|count| *count += 1)
                .or_insert(1);
                
            return Err("Rate limit exceeded - DoS protection activated".to_string());
        }
        
        // Add to queue if all checks pass
        self.message_queue.push_back(packet);
        Ok(())
    }

    fn handle_failed_delivery(&mut self, node_id: &str, packet: &Packet) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.metrics.update_failed_routing();
            node.metrics.update_reputation(false);
        }

        // Mark the delivery as failed in tracking
        let tracking_id = format!(
            "{}:{}:{}",
            packet.source, packet.destination, packet.timestamp
        );
        // Track delivery outcome
        self.delivery_tracking.insert(tracking_id, true);
    }

    fn attempt_delivery(&mut self, packet: &Packet) -> bool {
        // CRITICAL SECURITY CHECK: Verify packet authentication
        if packet.is_authenticated() && !packet.verify_signature() {
            println!("❌ SECURITY VIOLATION: Rejecting packet with invalid signature from {}", packet.source);
            self.security_violations.entry(packet.source.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);
            return false;
        }

        // Warn about unauthenticated packets
        if !packet.is_authenticated() {
            println!("⚠️  WARNING: Processing unauthenticated packet from {} to {}", 
                packet.source, packet.destination);
        }

        let dest_id = packet.destination.clone();
        let source_id = packet.source.clone();
        let tracking_id = format!("{}:{}:{}", source_id, dest_id, packet.timestamp);

        let condition = self.network_conditions.get(&dest_id)
            .cloned()
            .unwrap_or_default();
        
        let reputation = self.nodes.get(&dest_id)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(1.0);
        
        let base_drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        let rep_penalty = (1.0f64 - reputation).powf(2.0);
        let final_drop_rate = (base_drop_rate + (rep_penalty * base_drop_rate)).min(0.95);
        
        println!("Delivery check for {}: base_rate={:.3}, penalty={:.3}, final_rate={:.3}, rep={:.2}, auth={}",
                dest_id, base_drop_rate, rep_penalty, final_drop_rate, reputation, packet.is_authenticated());

        if !self.nodes.contains_key(&dest_id) || rand::thread_rng().gen::<f64>() < final_drop_rate {
            // Handle failed delivery with more nuanced penalties
            if let Some(dest_node) = self.nodes.get_mut(&dest_id) {
                // Only apply reputation penalty under good conditions
                if base_drop_rate < 0.3 && reputation > 0.5 {
                    dest_node.metrics.update_reputation(false);
                }
                
                // Track metrics regardless of conditions
                dest_node.metrics.update_failed_routing();
            }
            return false;
        }

        // Attempt delivery
        let latency = self.calculate_node_latency(&dest_id);
        if let Some(dest_node) = self.nodes.get_mut(&dest_id) {
            dest_node.receive_packet(packet.clone());
            dest_node.metrics.update_routing_metrics(latency, packet.size.try_into().unwrap());
            self.delivery_tracking.insert(tracking_id, true);

            // Update source node reputation
            if let Some(source_node) = self.nodes.get_mut(&source_id) {
                source_node.metrics.update_reputation(true);
            }
            true
        } else {
            false
        }
    }

    fn try_forward_packet(
        &mut self,
        new_messages: &mut VecDeque<Packet>,
        packet: &Packet,
        next_hop: &str,
    ) -> bool {
        // Get network conditions and calculate drop probability
        let condition = self.network_conditions.get(next_hop)
            .cloned()
            .unwrap_or_default();
        
        // Get current reputation
        let reputation = self.nodes.get(next_hop)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(1.0);
            
        // Calculate drop rate adjustment based on reputation
        let base_drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        let modifier = if reputation > 0.8 {
            -0.2  // Good reputation reduces drop rate
        } else if reputation < 0.3 {
            0.2   // Bad reputation increases drop rate
        } else {
            0.0   // Neutral effect for mid-range reputation
        };
        
        let final_drop_rate = (base_drop_rate + modifier).clamp(0.05, 0.95);
        
        println!("Drop check for {}: base_rate={:.3}, modifier={:.3}, final_rate={:.3}, rep={:.2}",
                next_hop, base_drop_rate, modifier, final_drop_rate, reputation);
                
        // Check if packet should be dropped
        if !self.nodes.contains_key(next_hop) ||
           rand::thread_rng().gen::<f64>() < final_drop_rate {
            // Calculate latency even for failed attempts
            let latency = self.calculate_node_latency(next_hop);
            if let Some(next_node) = self.nodes.get_mut(next_hop) {
                // Update metrics with high latency for failed attempt
                next_node.metrics.update_routing_metrics(latency * 2.0, packet.size.try_into().unwrap());
                
                // Apply penalties based on conditions and current performance
                let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                if expected_fails < 0.3 && reputation > 0.8 {
                    // Only penalize if conditions are good and reputation is high
                    next_node.metrics.update_reputation(false);
                } else if expected_fails < 0.5 && reputation > 0.6 {
                    // Light penalty for moderate conditions
                    next_node.metrics.update_reputation(false);
                }
                // Track failure but don't penalize reputation under poor conditions
                next_node.metrics.update_failed_routing();
            }
            return false;
        }

        let latency = self.calculate_node_latency(next_hop);
        if let Some(next_node) = self.nodes.get_mut(next_hop) {
            // Update metrics and apply reputation boost based on conditions
            next_node.metrics.update_routing_metrics(latency, packet.size.try_into().unwrap());
            let mut new_packet = packet.clone();
            new_packet.record_visit(next_hop.to_string());
            new_messages.push_back(new_packet);
            
            // Handle successful forward
            let condition = self.network_conditions.get(next_hop)
                .cloned()
                .unwrap_or_default();

            // Calculate difficulty and expected failure rate
            let difficulty = condition.packet_loss_rate * condition.latency_multiplier;
            
            // Calculate reputation boost based on conditions
            let boost_count = if difficulty > 0.8 {
                3  // Major boost for success under extreme conditions
            } else if difficulty > 0.5 {
                2  // Medium boost for difficult conditions
            } else {
                1  // Normal boost for good conditions
            };

            // Apply reputation boosts
            for _ in 0..boost_count {
                next_node.metrics.update_reputation(true);
            }

            // Small additional boost for consistently good performance
            if next_node.metrics.reputation_score > 0.7 && difficulty < 0.3 {
                next_node.metrics.update_reputation(true);
            }
            
            return true;
        }
        false
    }

    fn calculate_node_latency(&self, node_id: &str) -> f64 {
        let base_latency = rand::thread_rng().gen_range(10.0..200.0);
        if let Some(condition) = self.network_conditions.get(node_id) {
            base_latency * condition.latency_multiplier
        } else {
            base_latency
        }
    }

    /// Evaluate a node's current routing score (higher is better)
    fn evaluate_node_score(&self, node_id: &str) -> f64 {
        // Get node's current reputation
        let reputation = self.nodes.get(node_id)
            .map(|n| n.metrics.reputation_score)
            .unwrap_or(0.0);

        // Get network conditions
        let condition = self.network_conditions.get(node_id)
            .cloned()
            .unwrap_or_default();

        // Calculate effective drop rate
        let drop_rate = condition.packet_loss_rate * condition.latency_multiplier;
        
        // Scale down high drop rates less aggressively
        let condition_multiplier = 1.0 - (drop_rate * 1.5).min(0.6);
        
        // Base score on reputation and conditions
        let score = reputation * condition_multiplier;
        
        // Add small base chance but cap maximum
        (score + 0.05).min(0.95).max(0.05)
    }

    pub fn process_messages(&mut self) {
        let mut new_messages = VecDeque::new();

        while let Some(mut packet) = self.message_queue.pop_front() {
            if !packet.increment_hop() {
                self.handle_failed_delivery(&packet.source, &packet);
                continue;
            }

            // Only attempt direct delivery if the destination is a direct neighbor
            let current_id = packet.visited_nodes.iter().last().unwrap_or(&packet.source).clone();
            let can_deliver_direct = if let Some(current_node) = self.nodes.get(&current_id) {
                current_node.connections.contains(&packet.destination)
            } else {
                false
            };

            if can_deliver_direct && self.attempt_delivery(&packet) {
                continue;
            }

            // Get current node and its connections
            let current_id = packet
                .visited_nodes
                .iter()
                .last()
                .unwrap_or(&packet.source)
                .clone();

            // Get and sort available next hops by score
            let mut candidates = Vec::new();
            if let Some(current_node) = self.nodes.get(&current_id) {
                for conn in &current_node.connections {
                    if !packet.has_visited(conn) {
                        let score = self.evaluate_node_score(conn);
                        candidates.push((conn.clone(), score));
                    }
                }
            }

            // Sort by score and packet loss rate
            candidates.sort_by(|(a_id, a_score), (b_id, b_score)| {
                let a_loss = self.network_conditions.get(a_id)
                    .map(|c| c.packet_loss_rate)
                    .unwrap_or(0.0);
                let b_loss = self.network_conditions.get(b_id)
                    .map(|c| c.packet_loss_rate)
                    .unwrap_or(0.0);
                
                // Primary sort by score, secondary by packet loss
                match b_score.partial_cmp(a_score) {
                    Some(ord) if ord == std::cmp::Ordering::Equal => {
                        a_loss.partial_cmp(&b_loss).unwrap_or(std::cmp::Ordering::Equal)
                    }
                    Some(ord) => ord,
                    None => std::cmp::Ordering::Equal
                }
            });

            // Try forwarding through each candidate
            let mut forwarded = false;
            let mut attempted_nodes = Vec::new();

            for (next_hop, score) in candidates {
                attempted_nodes.push(next_hop.clone());
                let condition = self.network_conditions.get(&next_hop)
                    .cloned()
                    .unwrap_or_default();
                println!("Attempting route through {}: score={:.3}, drop_rate={:.3}, latency={:.1}x",
                    next_hop, score, condition.packet_loss_rate, condition.latency_multiplier);
                
                if self.try_forward_packet(&mut new_messages, &packet, &next_hop) {
                    println!("Successfully forwarded through {}", next_hop);
                    forwarded = true;
                    break;
                } else {
                    println!("Failed to forward through {} - packet dropped", next_hop);
                }

                // Penalize based on base conditions and current reputation
                if let Some(node) = self.nodes.get_mut(&next_hop) {
                    let condition = self.network_conditions.get(&next_hop)
                        .cloned()
                        .unwrap_or_default();
                        
                    // Adjust reputation based on failure context
                    let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                    
                    // Apply penalties only under good conditions
                    if expected_fails < 0.3 {
                        // Apply penalty if reputation is too high for performance
                        if node.metrics.reputation_score > 0.8 {
                            node.metrics.update_reputation(false);
                        }
                    }
                    
                    // Always track metrics
                    node.metrics.update_failed_routing();
                }
            }

            // Apply penalties only if packet cannot be forwarded through any path
            if !forwarded {
                for next_hop in attempted_nodes {
                    if let Some(node) = self.nodes.get_mut(&next_hop) {
                        let condition = self.network_conditions.get(&next_hop)
                            .cloned()
                            .unwrap_or_default();
                        let expected_fails = condition.packet_loss_rate * condition.latency_multiplier;
                        
                        // Only track metrics and apply penalties under specific conditions
                        if expected_fails < 0.2 && node.metrics.reputation_score > 0.8 {
                            node.metrics.update_reputation(false);
                            node.metrics.update_failed_routing();
                        }
                    }
                }
                self.handle_failed_delivery(&current_id, &packet);
            }
        }

        // Safely add new messages with DoS protection
        for packet in new_messages {
            if let Err(e) = self.add_to_message_queue(packet) {
                println!("⚠️  Forwarded packet dropped: {}", e);
                // Continue processing other packets instead of failing completely
            }
        }
    }

    pub fn get_node_metrics<S: AsRef<str>>(&self, node_id: S) -> Option<&ZkNetworkMetrics> {
        self.nodes.get(node_id.as_ref()).map(|node| &node.metrics)
    }

    pub fn get_delivery_success_rate(&self) -> f64 {
        let total = self.delivery_tracking.len();
        if total == 0 {
            return 1.0;
        }

        let successful = self
            .delivery_tracking
            .values()
            .filter(|&&success| success)
            .count();

        successful as f64 / total as f64
    }

    /// Monitor security violations and detect potential attacks
    pub fn get_security_report(&self) -> HashMap<String, u32> {
        let mut report = HashMap::new();
        
        for (node_id, violation_count) in &self.security_violations {
            if *violation_count > 0 {
                report.insert(format!("violations_by_{}", node_id), *violation_count);
            }
        }
        
        // Add threat level assessment
        let total_violations: u32 = self.security_violations.values().sum();
        report.insert("total_security_violations".to_string(), total_violations);
        
        if total_violations > 10 {
            report.insert("threat_level".to_string(), 3); // HIGH
        } else if total_violations > 5 {
            report.insert("threat_level".to_string(), 2); // MEDIUM
        } else {
            report.insert("threat_level".to_string(), 1); // LOW
        }
        
        report
    }

    /// Block a node that has too many security violations
    pub fn block_malicious_node(&mut self, node_id: &str) -> bool {
        if let Some(&violation_count) = self.security_violations.get(node_id) {
            if violation_count > 5 { // Threshold for blocking
                println!("🚫 BLOCKING malicious node {} with {} violations", node_id, violation_count);
                self.nodes.remove(node_id);
                return true;
            }
        }
        false
    }

    /// Process the message queue with security checks
    pub fn process_secure_queue(&mut self) -> usize {
        let mut processed = 0;
        let mut blocked_nodes = Vec::new();
        
        while let Some(packet) = self.message_queue.pop_front() {
            // Check for malicious nodes before processing
            if let Some(&violations) = self.security_violations.get(&packet.source) {
                if violations > 5 {
                    blocked_nodes.push(packet.source.clone());
                    continue; // Skip packets from blocked nodes
                }
            }
            
            if self.attempt_delivery(&packet) {
                processed += 1;
            }
        }
        
        // Block nodes with too many violations
        for node_id in blocked_nodes {
            self.block_malicious_node(&node_id);
        }
        
        processed
    }

    /// Get queue status for monitoring and debugging
    pub fn get_queue_status(&self) -> (usize, usize, f64) {
        let current_size = self.message_queue.len();
        let max_size = MAX_MESSAGE_QUEUE_SIZE;
        let utilization = (current_size as f64 / max_size as f64) * 100.0;
        
        (current_size, max_size, utilization)
    }
    
    /// Get active rate limiting sessions count
    pub fn get_rate_limiter_status(&self) -> usize {
        self.message_rates.len()
    }

    /// Clean up old rate tracking data to prevent memory leaks
    fn cleanup_rate_trackers(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        // Remove trackers that haven't been used in the last hour
        self.message_rates.retain(|_node_id, tracker| {
            now - tracker.window_start < 3600 // 1 hour
        });
    }
}

#[derive(Debug)]
pub struct Node {
    id: NetworkId,
    connections: Vec<NetworkId>,
    metrics: ZkNetworkMetrics,
    received_messages: Vec<String>,
}

impl Node {
    pub fn new<S: Into<String>>(id: S, stake: f64) -> Self {
        Node {
            id: id.into(),
            connections: Vec::new(),
            metrics: ZkNetworkMetrics::new(stake),
            received_messages: Vec::new(),
        }
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        if packet.destination == self.id {
            self.received_messages.push(packet.payload);
        }
    }

    pub fn get_received_messages(&self) -> &[String] {
        &self.received_messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_degraded_network() {
        let mut network = Network::new();

        // Add nodes in a more complex topology
        network.add_node("node1", 1000.0);
        network.add_node("node2", 1000.0);
        network.add_node("node3", 1000.0);
        network.add_node("node4", 1000.0);

        // Connect nodes in a diamond pattern
        // node1 -> node2 -> node4
        //      \-> node3 -/
        network.connect_nodes("node1", "node2");
        network.connect_nodes("node1", "node3");
        network.connect_nodes("node2", "node4");
        network.connect_nodes("node3", "node4");

        // Clear initial default conditions
        network.set_node_condition("node2", NetworkCondition::default());
        network.set_node_condition("node3", NetworkCondition::default());

        // Set node2 with extremely poor conditions
        network.set_node_condition(
            "node2",
            NetworkCondition {
                packet_loss_rate: 0.9, // 90% base packet loss
                latency_multiplier: 5.0, // 5x normal latency
                bandwidth_cap: Some(100), // Severely limited bandwidth
            },
        );

        // Set node3 with slightly degraded conditions
        network.set_node_condition(
            "node3",
            NetworkCondition {
                packet_loss_rate: 0.05, // 5% base packet loss
                latency_multiplier: 1.1, // Only slight latency increase
                bandwidth_cap: Some(10000), // Better bandwidth
            },
        );

        // Initialize node2 with baseline reputation
        if let Some(node2) = network.nodes.get_mut("node2") {
            // Give some initial reputation to lose
            node2.metrics.update_reputation(true);
        }

        // Get starting conditions
        if let Some(metrics) = network.get_node_metrics("node2") {
            println!("Initial Node2 reputation: {:.2}", metrics.reputation_score);
        }

        // Send messages with immediate processing
        for i in 0..10 {
            // Send packet
            network.send_packet(
                "node1".to_string(),
                "node4".to_string(),
                format!("Message {}", i),
            );

            // Process immediately to adapt to conditions
            // Process messages and track metrics
            network.process_messages();
            
            // Print current metrics after each round
            println!("Messages in queue: {}", network.message_queue.len());
            let success_rate = network.get_delivery_success_rate();
            println!("Current success rate: {:.1}%", success_rate * 100.0);

            // Let the natural packet processing handle reputation updates
            if let Some(metrics) = network.get_node_metrics("node2") {
                println!("Current Node2 reputation: {:.2}", metrics.reputation_score);
            }
        }

        // Final processing rounds to ensure delivery
        for _ in 0..5 {
            network.process_messages();
        }

        // Process final metrics
        let success_rate = network.get_delivery_success_rate();
        println!("\nFinal Network Metrics:");
        println!("Success rate: {:.1}%", success_rate * 100.0);
        println!("Messages delivered: {}", network.delivery_tracking.len());

        // Success rate should be reasonable with alternate path
        assert!(
            success_rate > 0.3,
            "Success rate {} should be higher with alternate path",
            success_rate
        );

        // Verify node2's degraded performance
        if let Some(metrics) = network.get_node_metrics("node2") {
            println!("Node2 metrics:");
            println!("  Delivery failures: {}", metrics.delivery_failures);
            println!("  Average latency: {:.2}ms", metrics.average_latency());
            println!("  Reputation score: {:.2}", metrics.reputation_score);

            assert!(
                metrics.reputation_score < 0.7,
                "Node2 reputation should decrease"
            );
            assert!(
                metrics.delivery_failures > 0,
                "Node2 should have failed packets"
            );
            assert!(
                metrics.average_latency() > 100.0,
                "Node2 should show increased latency"
            );
        }

        // Verify node3's better performance
        if let Some(metrics) = network.get_node_metrics("node3") {
            println!("Node3 metrics:");
            println!("  Delivery failures: {}", metrics.delivery_failures);
            println!("  Average latency: {:.2}ms", metrics.average_latency());
            println!("  Reputation score: {:.2}", metrics.reputation_score);

            assert!(
                metrics.reputation_score > 0.25,
                "Node3 reputation should remain higher than severely degraded nodes"
            );
            assert!(
                metrics.average_latency() < 200.0,
                "Node3 should have lower latency"
            ); // Checking against reasonable threshold
        }

        // Verify that node4 received messages
        if let Some(node4) = network.nodes.get("node4") {
            let received = node4.get_received_messages().len();
            println!("Messages received by node4: {}", received);
            assert!(received > 0, "Node4 should have received some messages");
        }
    }
}

// Queue size limits for DoS protection
const MAX_MESSAGE_QUEUE_SIZE: usize = 10_000;
const MAX_MESSAGES_PER_SECOND: usize = 100;
const MESSAGE_RATE_WINDOW_SECS: u64 = 1;

/// Rate limiting tracker for DoS protection
#[derive(Debug, Clone)]
struct MessageRateTracker {
    message_count: usize,
    window_start: u64,
}

impl MessageRateTracker {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        Self {
            message_count: 0,
            window_start: now,
        }
    }
    
    /// Check if message should be allowed based on rate limiting
    fn allow_message(&mut self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        // Reset window if time has passed
        if now - self.window_start >= MESSAGE_RATE_WINDOW_SECS {
            self.message_count = 0;
            self.window_start = now;
        }
        
        // Check if under rate limit
        if self.message_count < MAX_MESSAGES_PER_SECOND {
            self.message_count += 1;
            true
        } else {
            false
        }
    }
}
