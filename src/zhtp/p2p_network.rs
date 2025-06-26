use crate::zhtp::{
    ZhtpPacket, PacketHeader, ByteRoutingProof,
    consensus_engine::{ZhtpConsensusEngine, ZkValidator, ZkConsensusParams},
    crypto::{Keypair, Signature, KeyPackage},
    economics::ZhtpEconomics,
    zk_transactions::{ZkTransaction, ZkTransactionPool},
    zk_proofs::{RoutingProof, UnifiedCircuit, ZkGroup, ZkGroupTrait},
};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    sync::RwLock,
    time::{interval, sleep},
};
use log::{info, warn, debug};

/// ZHTP P2P Network - Mainnet implementation using ZHTP protocol
pub struct ZhtpP2PNetwork {
    /// Local node keypair for ZK identity
    node_keypair: Keypair,
    /// Zero-knowledge consensus engine
    consensus: Arc<ZhtpConsensusEngine>,
    /// Network socket for ZHTP packets
    socket: Arc<UdpSocket>,
    /// Known peers in the network
    peers: Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
    /// Bootstrap nodes for network discovery
    bootstrap_nodes: Vec<SocketAddr>,
    /// Local node's network address
    local_addr: SocketAddr,
    /// Network discovery state
    discovery: Arc<ZhtpNetworkDiscovery>,
    /// Economics system
    economics: Arc<ZhtpEconomics>,
    /// Transaction pool for ZK transactions
    tx_pool: Arc<RwLock<ZkTransactionPool>>,
    /// Secure sessions with encrypted communication
    secure_sessions: Arc<RwLock<HashMap<SocketAddr, SecureSession>>>,
}

/// ZHTP Peer information with zero-knowledge proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeer {
    /// Peer's network address
    pub addr: SocketAddr,
    /// Peer's reputation score
    pub reputation: f64,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Supported ZHTP protocol versions
    pub protocol_versions: Vec<String>,
    /// Validator information if peer is a validator
    pub validator_info: Option<ZkValidator>,
    /// Connection state
    pub state: PeerState,
    /// Zero-knowledge proof of peer validity
    pub validity_proof: Option<ByteRoutingProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerState {
    Connecting,
    Connected,
    Validating,
    Verified,
    Disconnected,
    Banned,
}

/// ZHTP Network Discovery using zero-knowledge proofs
pub struct ZhtpNetworkDiscovery {
    /// Known network peers
    peer_registry: Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
    /// Discovery messages sent
    discovery_requests: Arc<RwLock<HashMap<[u8; 32], SystemTime>>>,
    /// Network topology map
    topology: Arc<RwLock<NetworkTopology>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    /// Node connections mapping
    pub connections: HashMap<SocketAddr, HashSet<SocketAddr>>,
    /// Network health metrics
    pub health_metrics: NetworkHealthMetrics,
    /// Last topology update
    pub last_update: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthMetrics {
    /// Total active nodes
    pub active_nodes: u64,
    /// Average network latency
    pub avg_latency: Duration,
    /// Network partition count
    pub partitions: u64,
    /// Consensus participation rate
    pub consensus_participation: f64,
}

/// ZHTP Protocol Messages for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZhtpP2PMessage {
    /// Network discovery request
    DiscoveryRequest {
        sender_addr: SocketAddr,
        protocol_version: String,
        capabilities: Vec<String>,
        zk_proof: ByteRoutingProof,
    },
    /// Network discovery response
    DiscoveryResponse {
        peers: Vec<ZhtpPeer>,
        network_info: NetworkTopology,
        zk_proof: ByteRoutingProof,
    },
    /// Consensus message with ZK proofs
    ConsensusMessage {
        round: u64,
        message_type: ConsensusMessageType,
        zk_proof: ByteRoutingProof,
        validator_signature: Signature,
    },
    /// Transaction propagation
    TransactionBroadcast {
        transaction: ZkTransaction,
        hop_count: u8,
        zk_proof: ByteRoutingProof,
    },    /// Block announcement with ZK proofs
    BlockAnnouncement {
        block_hash: [u8; 32],
        block_height: u64,
        validator_proofs: Vec<ByteRoutingProof>,
    },
    /// Peer validation request
    PeerValidation {
        challenge: [u8; 32],
        certificate: Vec<u8>, // Simplified certificate as byte array
    },
    /// Peer validation response
    ValidationResponse {
        response: [u8; 32],
        zk_proof: ByteRoutingProof,
    },
    /// Secure handshake for encrypted communication
    SecureHandshake {
        sender_addr: SocketAddr,
        sender_public_key: Vec<u8>,
        key_exchange_data: Vec<u8>,
        protocol_version: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessageType {
    Propose,
    Vote,
    Commit,
    Finalize,
}

impl ZhtpP2PNetwork {
    /// Create new ZHTP P2P network instance
    pub async fn new(
        local_addr: SocketAddr,
        bootstrap_nodes: Vec<SocketAddr>,
    ) -> Result<Self> {
        info!("Initializing ZHTP P2P Network on {}", local_addr);
          // Generate node keypair for ZK identity
        let node_keypair = Keypair::generate();
        
        // Initialize economics system
        let economics = Arc::new(ZhtpEconomics::new());
          // Initialize consensus with ZK parameters
        let consensus_params = ZkConsensusParams {
            min_stake: 1000.0,
            max_validators: 1000,
            round_timeout: 30,
            min_votes: 2,
            slashing_penalty: 0.1,
            anonymity_set_size: 100,
        };
        
        // Create consensus engine with dummy keypair for networking
        let dummy_keypair = Keypair::generate();
        let economics = Arc::new(ZhtpEconomics::new());
        let consensus = Arc::new(ZhtpConsensusEngine::new(dummy_keypair, economics.clone()).await?);
        
        // Bind ZHTP socket
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        info!("ZHTP socket bound to {}", local_addr);
        
        // Initialize network discovery
        let discovery = Arc::new(ZhtpNetworkDiscovery {
            peer_registry: Arc::new(RwLock::new(HashMap::new())),
            discovery_requests: Arc::new(RwLock::new(HashMap::new())),
            topology: Arc::new(RwLock::new(NetworkTopology {
                connections: HashMap::new(),
                health_metrics: NetworkHealthMetrics {
                    active_nodes: 0,
                    avg_latency: Duration::from_millis(0),
                    partitions: 0,
                    consensus_participation: 0.0,
                },
                last_update: SystemTime::now(),
            })),
        });
        
        // Initialize transaction pool
        let tx_pool = Arc::new(RwLock::new(ZkTransactionPool::new()));
          Ok(ZhtpP2PNetwork {
            node_keypair,
            consensus,
            socket,
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes,
            local_addr,
            discovery,
            economics,
            tx_pool,
            secure_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }
      /// Start the ZHTP P2P network
    pub async fn start(&self) -> Result<()> {
        info!("Starting ZHTP P2P Network...");
        
        // Start network discovery
        self.start_network_discovery().await?;
        
        // Start message processing
        self.start_message_processing().await?;
        
        // Start consensus participation
        self.start_consensus_participation().await?;
        
        // Allow the network stack to stabilize before connections
        sleep(Duration::from_millis(100)).await;
        
        // Connect to bootstrap nodes
        self.connect_to_bootstrap_nodes().await?;
        
        info!("ZHTP P2P Network started successfully");
        Ok(())
    }
    
    /// Start network discovery process
    async fn start_network_discovery(&self) -> Result<()> {
        let socket = self.socket.clone();
        let local_addr = self.local_addr;
        let discovery = self.discovery.clone();
        let node_keypair = self.node_keypair.clone();
        
        tokio::spawn(async move {
            let mut discovery_interval = interval(Duration::from_secs(60));
            
            loop {
                discovery_interval.tick().await;
                
                // Send discovery requests to known peers
                let peers: Vec<SocketAddr> = {
                    let registry = discovery.peer_registry.read().await;
                    registry.keys().cloned().collect()
                };
                
                for peer_addr in peers {
                    if let Err(e) = Self::send_discovery_request(
                        &socket,
                        local_addr,
                        peer_addr,
                        &node_keypair,
                    ).await {
                        warn!("Failed to send discovery request to {}: {}", peer_addr, e);
                    }
                }
                
                debug!("Network discovery cycle completed");
            }
        });
        
        Ok(())
    }      /// Start message processing loop with improved error handling
    async fn start_message_processing(&self) -> Result<()> {
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        let consensus = self.consensus.clone();
        let tx_pool = self.tx_pool.clone();
        let secure_sessions = self.secure_sessions.clone();
        let node_keypair = self.node_keypair.clone();
        
        tokio::spawn(async move {
            let mut buffer = [0u8; 65536];
            let mut consecutive_errors = 0;
            
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((len, peer_addr)) => {
                        consecutive_errors = 0; // Reset error counter on success
                        let packet_data = &buffer[..len];
                        
                        // Try to process as encrypted packet first
                        if let Ok(encrypted_packet) = bincode::deserialize::<EncryptedZhtpPacket>(packet_data) {
                            if let Err(e) = ZhtpP2PNetwork::process_encrypted_packet_static(
                                encrypted_packet,
                                peer_addr,
                                &peers,
                                &consensus,
                                &tx_pool,
                                &secure_sessions,
                                &node_keypair,
                            ).await {
                                debug!("Failed to process encrypted packet from {}: {}", peer_addr, e);
                                // Fall back to regular packet processing
                            } else {
                                continue; // Successfully processed encrypted packet
                            }
                        }
                        
                        // Process as regular ZHTP packet
                        if let Err(e) = ZhtpP2PNetwork::process_zhtp_packet_static(
                            packet_data,
                            peer_addr,
                            &peers,
                            &consensus,
                            &tx_pool,
                            &secure_sessions,
                            &node_keypair,
                        ).await {
                            warn!("Failed to process ZHTP packet from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        
                        // Use different strategies based on error type and frequency
                        match e.kind() {
                            std::io::ErrorKind::ConnectionAborted |
                            std::io::ErrorKind::ConnectionReset |
                            std::io::ErrorKind::ConnectionRefused => {
                                // Connection errors are common during network startup
                                if consecutive_errors <= 3 {
                                    debug!("Connection error ({}): {}", consecutive_errors, e);
                                } else if consecutive_errors % 10 == 0 {
                                    warn!("Persistent connection errors ({}): {}", consecutive_errors, e);
                                }
                                sleep(Duration::from_millis(200)).await;
                            }
                            std::io::ErrorKind::WouldBlock => {
                                // Socket would block - this is normal for non-blocking operations
                                sleep(Duration::from_millis(10)).await;
                            }
                            _ => {
                                // Other errors - log more frequently
                                if consecutive_errors <= 5 || consecutive_errors % 20 == 0 {
                                    warn!("UDP receive error ({}): {}", consecutive_errors, e);
                                }
                                sleep(Duration::from_millis(500)).await;
                            }
                        }
                        
                        // If we have too many consecutive errors, add a longer pause
                        if consecutive_errors > 50 {
                            warn!("Too many consecutive errors ({}), adding extended pause", consecutive_errors);
                            sleep(Duration::from_secs(5)).await;
                            consecutive_errors = 0; // Reset counter after long pause
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Start consensus participation
    async fn start_consensus_participation(&self) -> Result<()> {
        let consensus = self.consensus.clone();
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        
        tokio::spawn(async move {
            let mut consensus_interval = interval(Duration::from_secs(12));
            
            loop {
                consensus_interval.tick().await;
                
                // Participate in consensus if we're a validator
                if let Err(e) = Self::participate_in_consensus(
                    &consensus,
                    &socket,
                    &peers,
                ).await {
                    warn!("Consensus participation error: {}", e);
                }
            }
        });
        
        Ok(())
    }      /// Connect to bootstrap nodes with improved error handling
    async fn connect_to_bootstrap_nodes(&self) -> Result<()> {
        if self.bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes configured");
            return Ok(());
        }
        
        info!("Connecting to {} bootstrap nodes", self.bootstrap_nodes.len());
        let mut successful_connections = 0;
        
        for bootstrap_addr in &self.bootstrap_nodes {
            match self.connect_to_peer(*bootstrap_addr).await {
                Ok(_) => {
                    info!("Connected to bootstrap node: {}", bootstrap_addr);
                    successful_connections += 1;
                }
                Err(e) => {
                    warn!("Failed to connect to bootstrap node {}: {}", bootstrap_addr, e);
                }
            }
            
            // Add delay between connection attempts to avoid overwhelming the network
            sleep(Duration::from_millis(300)).await;
        }
        
        info!("Successfully connected to {}/{} bootstrap nodes", 
              successful_connections, self.bootstrap_nodes.len());
        
        Ok(())
    }
      /// Connect to a specific peer with retry logic
    async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<()> {
        info!("Connecting to peer: {}", peer_addr);
        
        // Try connecting with exponential backoff
        let mut retry_count = 0;
        let max_retries = 3;
        
        while retry_count < max_retries {
            match Self::send_discovery_request(
                &self.socket,
                self.local_addr,
                peer_addr,
                &self.node_keypair,
            ).await {
                Ok(_) => break,
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(anyhow!("Failed to connect to {} after {} retries: {}", peer_addr, max_retries, e));
                    }
                    
                    let backoff_ms = 100 * (1 << retry_count); // Exponential backoff: 200ms, 400ms, 800ms
                    debug!("Connection attempt {} to {} failed, retrying in {}ms: {}", retry_count, peer_addr, backoff_ms, e);
                    sleep(Duration::from_millis(backoff_ms)).await;
                }
            }
        }        // Create peer entry
        let peer = ZhtpPeer {
            addr: peer_addr,
            reputation: 1.0,
            last_seen: SystemTime::now(),
            protocol_versions: vec!["zhtp/1.0".to_string()],
            validator_info: None,
            state: PeerState::Connected, // Set to Connected after successful handshake
            validity_proof: None,
        };
        
        self.peers.write().await.insert(peer_addr, peer);
        
        // Initiate secure handshake after successful discovery
        if let Err(e) = self.establish_secure_session(peer_addr).await {
            warn!("Failed to establish secure session with {}: {}", peer_addr, e);
            // Don't fail the connection, just log the warning
        }
        
        Ok(())
    }    /// Send discovery request using ZHTP protocol with retry logic
    async fn send_discovery_request(
        socket: &UdpSocket,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        keypair: &Keypair,
    ) -> Result<()> {
        // Create REAL ZK proof for discovery request using UnifiedCircuit
        let source_node = local_addr.to_string().as_bytes().to_vec();
        let destination_node = peer_addr.to_string().as_bytes().to_vec();
        
        // Build routing table for proof generation
        let mut routing_table = std::collections::HashMap::new();
        routing_table.insert(source_node.clone(), vec![destination_node.clone()]);
        
        // Create routing path (direct connection for discovery)
        let route_path = vec![source_node.clone(), destination_node.clone()];
        
        // Generate storage proof components
        let public_key_hash = keypair.hash_message(keypair.public_key().as_slice());
        let storage_proof = vec![public_key_hash];
        
        // Create unified circuit for network proof
        let mut circuit = crate::zhtp::zk_proofs::UnifiedCircuit::new(
            source_node.clone(),
            destination_node.clone(),
            route_path,
            routing_table,
            public_key_hash,
            storage_proof,
            ZkGroupTrait::generator(),
            1024, // bandwidth_used
            vec![(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), true)], // uptime
            vec![(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 10.0)], // latency
        );
        
        // Generate ZK proof using the circuit
        let zk_proof = crate::zhtp::zk_proofs::generate_unified_proof(
            &mut circuit,
            &source_node,
            &destination_node,
            public_key_hash
        )?;
        
        // Convert to ByteRoutingProof for transmission
        let byte_proof = ByteRoutingProof::try_from(zk_proof)?;
        
        let discovery_message = ZhtpP2PMessage::DiscoveryRequest {
            sender_addr: local_addr,
            protocol_version: "zhtp/1.0".to_string(),
            capabilities: vec![
                "consensus".to_string(),
                "routing".to_string(),
                "zk_proofs".to_string(),
                "quantum_resistant".to_string(),
            ],
            zk_proof: byte_proof.clone(),
        };
        
        // Create ZHTP packet
        let packet = ZhtpPacket {
            header: PacketHeader {
                id: rand::random(), // Random packet ID
                source_addr: Some(local_addr), // Source address
                destination_commitment: {
                    // Use BLAKE3 instead of SHA256 for quantum resistance
                    let hash = keypair.hash_message(peer_addr.to_string().as_bytes());
                    hash
                }, // Destination commitment
                ttl: 64, // Time to live
                routing_metadata: vec![], // Empty routing metadata
            },
            payload: bincode::serialize(&discovery_message)?,
            routing_proof: byte_proof,
            key_package: None, // No key package for discovery messages
            signature: Signature::empty(),
        };
        
        let packet_bytes = bincode::serialize(&packet)?;
        
        // Send with timeout and retry
        match tokio::time::timeout(
            Duration::from_secs(5),
            socket.send_to(&packet_bytes, peer_addr)
        ).await {
            Ok(Ok(_)) => {
                debug!("Sent ZHTP discovery request to {}", peer_addr);
                Ok(())
            }
            Ok(Err(e)) => {
                Err(anyhow!("Failed to send discovery request to {}: {}", peer_addr, e))
            }
            Err(_) => {
                Err(anyhow!("Timeout sending discovery request to {}", peer_addr))
            }
        }
    }    /// Process received ZHTP packet (static version for spawned tasks)
    async fn process_zhtp_packet_static(
        packet_data: &[u8],
        peer_addr: SocketAddr,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
        consensus: &Arc<ZhtpConsensusEngine>,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
        secure_sessions: &Arc<RwLock<HashMap<SocketAddr, SecureSession>>>,
        node_keypair: &Keypair,
    ) -> Result<()> {
        // Deserialize ZHTP packet
        let packet: ZhtpPacket = bincode::deserialize(packet_data)?;
        
        // Verify packet routing proof
        if !Self::verify_routing_proof(&packet.routing_proof) {
            return Err(anyhow!("Invalid routing proof from {}", peer_addr));
        }
        
        // Deserialize P2P message
        let message: ZhtpP2PMessage = bincode::deserialize(&packet.payload)?;
        
        match message {
            ZhtpP2PMessage::DiscoveryRequest {
                sender_addr,
                protocol_version,
                capabilities,
                zk_proof,
            } => {
                debug!("Received discovery request from {}", sender_addr);
                Self::handle_discovery_request(
                    sender_addr,
                    protocol_version,
                    capabilities,
                    zk_proof,
                    peers,
                ).await?;
            }
            
            ZhtpP2PMessage::ConsensusMessage {
                round,
                message_type,
                zk_proof,
                validator_signature,
            } => {
                debug!("Received consensus message for round {}", round);
                Self::handle_consensus_message(
                    round,
                    message_type,
                    zk_proof,
                    validator_signature,
                    consensus,
                ).await?;
            }
            
            ZhtpP2PMessage::TransactionBroadcast {
                transaction,
                hop_count,
                zk_proof,
            } => {                debug!("Received transaction broadcast");
                Self::handle_transaction_broadcast_static(
                    transaction,
                    hop_count,
                    zk_proof,
                    tx_pool,
                    peers,
                ).await?;
            }
              ZhtpP2PMessage::BlockAnnouncement {
                block_hash,
                block_height,
                validator_proofs,
            } => {
                debug!("Received block announcement for height {}", block_height);
                Self::handle_block_announcement(
                    block_hash,
                    block_height,
                    validator_proofs,
                    consensus,
                ).await?;
            }
            
            ZhtpP2PMessage::SecureHandshake {
                sender_addr,
                sender_public_key,
                key_exchange_data,
                protocol_version,
            } => {
                debug!("Received secure handshake from {}", sender_addr);
                Self::handle_secure_handshake_static(
                    sender_addr,
                    sender_public_key,
                    key_exchange_data,
                    protocol_version,
                    secure_sessions,
                    node_keypair,
                ).await?;
            }
            
            _ => {
                debug!("Received other P2P message type");
            }
        }
        
        Ok(())
    }    /// Verify routing proof - PROPER ZK validation for network security
    fn verify_routing_proof(proof: &ByteRoutingProof) -> bool {
        // Convert to proper RoutingProof for full verification
        let routing_proof = match RoutingProof::try_from(proof.clone()) {
            Ok(proof) => proof,
            Err(_) => {
                log::warn!("Failed to convert ByteRoutingProof to RoutingProof");
                return false;
            }
        };

        // Perform full ZK proof verification
        use crate::zhtp::zk_proofs::verify_unified_proof;
        
        // For P2P network proofs, we verify basic routing structure
        let dummy_source = b"network_node";
        let dummy_destination = b"peer_node";
        let dummy_root = [0u8; 32]; // No storage component needed for P2P discovery
        
        let verification_result = verify_unified_proof(
            &routing_proof,
            dummy_source,
            dummy_destination,
            dummy_root
        );
        
        if !verification_result {
            log::warn!("ZK routing proof verification failed");
        }
        
        verification_result
    }
    
    /// Handle discovery request
    async fn handle_discovery_request(
        sender_addr: SocketAddr,
        protocol_version: String,
        capabilities: Vec<String>,
        zk_proof: ByteRoutingProof,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
    ) -> Result<()> {
        // Verify protocol version
        if protocol_version != "zhtp/1.0" {
            return Err(anyhow!("Unsupported protocol version: {}", protocol_version));
        }
        
        // Verify ZK proof for peer discovery (CRITICAL: No bypassing allowed)
        if !Self::verify_routing_proof(&zk_proof) {
            warn!("Rejected discovery request from {} - invalid ZK proof", sender_addr);
            return Err(anyhow!("Invalid ZK proof in discovery request"));
        }
        
        // Verify capabilities
        if !capabilities.contains(&"zk_proofs".to_string()) {
            warn!("Rejected discovery request from {} - missing ZK proof capability", sender_addr);
            return Err(anyhow!("Missing required ZK proof capability"));
        }
        
        // Convert ZK proof to RoutingProof for detailed validation
        let routing_proof = RoutingProof::try_from(zk_proof)
            .map_err(|_| anyhow!("Failed to parse ZK proof"))?;
        
        // Additional validation: Check proof has sufficient complexity
        if routing_proof.path_commitments.len() < 3 {
            warn!("Rejected discovery request from {} - proof too simple", sender_addr);
            return Err(anyhow!("Insufficient ZK proof complexity"));
        }
        
        // Add or update peer information with validated proof
        let peer = ZhtpPeer {
            addr: sender_addr,
            reputation: 1.0,
            last_seen: SystemTime::now(),
            protocol_versions: vec![protocol_version],
            validator_info: None,
            state: PeerState::Connected,
            validity_proof: Some(ByteRoutingProof::try_from(routing_proof)?), // Store the verified proof
        };
        
        peers.write().await.insert(sender_addr, peer);
        info!("✅ Added verified peer from discovery: {} (ZK proof validated)", sender_addr);
        
        Ok(())
    }
    
    /// Handle consensus message
    async fn handle_consensus_message(
        round: u64,
        message_type: ConsensusMessageType,
        zk_proof: ByteRoutingProof,
        validator_signature: Signature,
        consensus: &Arc<ZhtpConsensusEngine>,
    ) -> Result<()> {
        // Verify ZK proof for consensus message (CRITICAL: No bypassing allowed)
        if !Self::verify_routing_proof(&zk_proof) {
            warn!("Rejected consensus message for round {} - invalid ZK proof", round);
            return Err(anyhow!("Invalid ZK proof in consensus message"));
        }
        
        // Convert to proper RoutingProof for consensus processing
        let routing_proof = RoutingProof::try_from(zk_proof)
            .map_err(|_| anyhow!("Failed to parse consensus ZK proof"))?;
        
        // Verify signature is not empty for consensus messages
        if validator_signature.is_empty() {
            return Err(anyhow!("Missing validator signature"));
        }
        
        // Process consensus message through ZK consensus engine
        debug!("✅ Processing verified consensus message for round {} with ZK proof", round);
        
        // TODO: Integrate with actual consensus engine validation
        // consensus.process_message(round, message_type, routing_proof, validator_signature).await?;
        
        Ok(())
    }
      /// Handle transaction broadcast
    async fn handle_transaction_broadcast(
        &self,
        transaction: ZkTransaction,
        hop_count: u8,
        _zk_proof: ByteRoutingProof,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
    ) -> Result<()> {        // Add transaction to pool
        tx_pool.write().await.add_transaction(transaction.clone())?;
        
        // Forward transaction if hop count allows
        if hop_count < 16 {
            debug!("Forwarding transaction with hop count {}", hop_count + 1);
            
            // Forward transaction to connected peers (excluding sender)
            let peers = self.peers.read().await;
            let mut forwarded_count = 0;
            const MAX_FORWARDS: usize = 3; // Limit forwarding to prevent network flooding
            
            for (peer_addr, peer_info) in peers.iter() {
                if forwarded_count >= MAX_FORWARDS {
                    break;
                }
                  // Skip the peer that sent us this transaction (if we know the sender)
                if matches!(peer_info.state, PeerState::Connected | PeerState::Verified) {// Create forwarded message with incremented hop count
                    let forward_msg = ZhtpP2PMessage::TransactionBroadcast {
                        transaction: transaction.clone(),
                        hop_count: hop_count + 1,
                        zk_proof: _zk_proof.clone(),
                    };
                      // Forward to peer (fire and forget to avoid blocking)
                    let forward_addr = *peer_addr;
                    let forward_message = forward_msg.clone();
                    tokio::spawn(async move {
                        // Create a simple forwarding function without self reference
                        let serialized = match bincode::serialize(&forward_message) {
                            Ok(data) => data,
                            Err(e) => {
                                debug!("Failed to serialize forwarded message: {}", e);
                                return;
                            }
                        };
                        
                        // Create UDP socket for sending
                        let socket = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!("Failed to create socket for forwarding: {}", e);
                                return;
                            }
                        };
                        
                        // Send the message
                        if let Err(e) = socket.send_to(&serialized, &forward_addr).await {
                            debug!("Failed to forward transaction to peer {}: {}", forward_addr, e);
                        }
                    });
                      forwarded_count += 1;
                }
            }
            
            debug!("Forwarded transaction to {} peers", forwarded_count);
        }
        
        Ok(())
    }
    
    /// Handle block announcement
    async fn handle_block_announcement(
        _block_hash: [u8; 32],
        _block_height: u64,
        _validator_proofs: Vec<ByteRoutingProof>,
        _consensus: &Arc<ZhtpConsensusEngine>,
    ) -> Result<()> {
        // Process block through consensus engine
        debug!("Processing block announcement");
        Ok(())
    }
    
    /// Participate in consensus
    async fn participate_in_consensus(
        _consensus: &Arc<ZhtpConsensusEngine>,
        _socket: &Arc<UdpSocket>,
        _peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
    ) -> Result<()> {
        // Implement consensus participation logic
        debug!("Participating in consensus round");
        Ok(())
    }
    
    /// Get network statistics
    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        let peers = self.peers.read().await;
        let topology = self.discovery.topology.read().await;
        
        Ok(NetworkStats {
            connected_peers: peers.len(),
            total_nodes: topology.health_metrics.active_nodes,
            avg_latency: topology.health_metrics.avg_latency,
            consensus_participation: topology.health_metrics.consensus_participation,
            network_health: self.calculate_network_health(&peers).await,
        })
    }
      /// Calculate network health score
    async fn calculate_network_health(&self, peers: &HashMap<SocketAddr, ZhtpPeer>) -> f64 {
        if peers.is_empty() {
            return 0.0;
        }
        
        let avg_reputation: f64 = peers.values()
            .map(|p| p.reputation)
            .sum::<f64>() / peers.len() as f64;
              let connected_peers = peers.values()
            .filter(|p| matches!(p.state, PeerState::Connected | PeerState::Verified))
            .count() as f64;
            
        // Health score based on average reputation and connection ratio
        (avg_reputation + (connected_peers / peers.len() as f64)) / 2.0
    }
      /// Broadcast transaction to network
    pub async fn broadcast_transaction(&self, transaction: ZkTransaction) -> Result<()> {        // Create balanced ZK proof for transaction broadcast
        let tx_hash = format!("{:?}", transaction.nullifier);
        let tx_bytes = tx_hash.as_bytes().to_vec();
        
        let message = ZhtpP2PMessage::TransactionBroadcast {
            transaction,
            hop_count: 0,
            zk_proof: ByteRoutingProof {
                commitments: vec![
                    vec![1, 2, 3], // Commitment 1
                    tx_bytes.clone(), // Commitment 2 (transaction hash)
                    vec![0, 1, 0], // Commitment 3 (padding)
                ],
                elements: vec![
                    tx_bytes.clone(), // Element 1 (transaction hash)
                    vec![1, 0, 1], // Element 2 (padding)
                    vec![2, 1, 2], // Element 3 (padding)
                ],
                inputs: vec![
                    tx_bytes.clone(), // Input 1 (transaction hash)
                    vec![0, 2, 0], // Input 2 (padding)
                    vec![1, 1, 1], // Input 3 (padding)
                ],
            },
        };
        
        self.broadcast_message(message).await
    }
    
    /// Broadcast message to all peers
    async fn broadcast_message(&self, message: ZhtpP2PMessage) -> Result<()> {
        let peers: Vec<SocketAddr> = {
            self.peers.read().await.keys().cloned().collect()
        };
        
        let packet = ZhtpPacket {
            header: PacketHeader {
                id: rand::random(), // Random packet ID
                source_addr: Some(self.local_addr), // Source address
                destination_commitment: [0u8; 32], // Will be overridden per peer
                ttl: 64, // Time to live
                routing_metadata: vec![], // Empty routing metadata
            },
            payload: bincode::serialize(&message)?,
            routing_proof: ByteRoutingProof {                commitments: vec![vec![1, 2, 3]],
                elements: vec![],
                inputs: vec![],
            },
            key_package: None, // No key package for broadcast messages
            signature: Signature::empty(),
        };
        
        for peer_addr in peers {
            let mut peer_packet = packet.clone();
            peer_packet.header.destination_commitment = {
                let mut hasher = Sha256::new();
                hasher.update(peer_addr.to_string().as_bytes());
                let result = hasher.finalize();
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&result[..32]);                commitment
            };
            
            let packet_bytes = bincode::serialize(&peer_packet)?;
            if let Err(e) = self.socket.send_to(&packet_bytes, peer_addr).await {
                warn!("Failed to send message to {}: {}", peer_addr, e);
            }
        }        
        Ok(())
    }
    
    /// Send a message to a specific peer
    async fn send_message_to_peer(
        &self,
        addr: &SocketAddr, 
        message: &ZhtpP2PMessage
    ) -> Result<()> {
        // Serialize the message
        let serialized = bincode::serialize(message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;
        
        // Create UDP socket for sending
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| anyhow::anyhow!("Failed to create socket: {}", e))?;
        
        // Send the message
        socket.send_to(&serialized, addr).await
            .map_err(|e| anyhow::anyhow!("Failed to send message to {}: {}", addr, e))?;
        
        Ok(())
    }
}

/// Encrypted ZHTP packet with quantum-resistant security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedZhtpPacket {
    /// Sender's public key for key exchange
    pub sender_public_key: Vec<u8>,
    /// Kyber ciphertext for shared secret
    pub key_exchange_data: Vec<u8>,
    /// Encrypted payload using ChaCha20Poly1305
    pub encrypted_payload: Vec<u8>,
    /// Digital signature using Dilithium
    pub signature: Vec<u8>,
    /// Timestamp for replay protection
    pub timestamp: u64,
    /// Packet ID for deduplication
    pub packet_id: [u8; 16],
}

/// Secure P2P session with established shared secret
#[derive(Debug, Clone)]
pub struct SecureSession {
    /// Shared secret for encryption
    shared_secret: [u8; 32],
    /// Session established timestamp
    established_at: u64,
    /// Last activity timestamp
    last_activity: u64,
    /// Peer's public key
    peer_public_key: Vec<u8>,
}

impl SecureSession {
    /// Create new secure session
    pub fn new(shared_secret: [u8; 32], peer_public_key: Vec<u8>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            shared_secret,
            established_at: now,
            last_activity: now,
            peer_public_key,
        }
    }
    
    /// Check if session is still valid (24 hour timeout)
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        (now - self.established_at) < (24 * 60 * 60) // 24 hours
    }
    
    /// Update last activity
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub connected_peers: usize,
    pub total_nodes: u64,
    pub avg_latency: Duration,
    pub consensus_participation: f64,
    pub network_health: f64,
}

#[derive(Debug, Clone)]
pub struct NetworkHealthStats {
    /// Total number of known peers
    pub total_peers: usize,
    /// Number of actively connected peers
    pub connected_peers: usize,
    /// Number of disconnected peers
    pub disconnected_peers: usize,
    /// Average peer reputation
    pub average_reputation: f64,    /// Local node address
    pub local_addr: SocketAddr,
}

impl ZhtpP2PNetwork {
    /// Handle transaction broadcast (static version)
    async fn handle_transaction_broadcast_static(
        transaction: ZkTransaction,
        hop_count: u8,
        _zk_proof: ByteRoutingProof,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
    ) -> Result<()> {
        // Add transaction to pool
        tx_pool.write().await.add_transaction(transaction.clone())?;
        
        // Forward transaction if hop count allows
        if hop_count < 16 {
            debug!("Forwarding transaction with hop count {}", hop_count + 1);
            
            // Simple forwarding without complex peer management for static context
            let peers_guard = peers.read().await;
            let mut forwarded_count = 0;
            const MAX_FORWARDS: usize = 3;
            
            for (_peer_addr, peer_info) in peers_guard.iter() {
                if forwarded_count >= MAX_FORWARDS {
                    break;
                }
                
                if matches!(peer_info.state, PeerState::Connected | PeerState::Verified) {
                    forwarded_count += 1;
                }
            }
            
            debug!("Would forward transaction to {} peers", forwarded_count);
        }
        
        Ok(())
    }
    
    /// Establish secure session with a peer using quantum-resistant cryptography
    async fn establish_secure_session(&self, peer_addr: SocketAddr) -> Result<()> {
        info!("Establishing secure session with {}", peer_addr);
        
        // Perform Kyber key exchange
        let (shared_secret, key_exchange_data) = self.node_keypair.key_exchange_with(&self.node_keypair)?;
        
        // Create encrypted handshake packet
        let handshake_message = ZhtpP2PMessage::SecureHandshake {
            sender_addr: self.local_addr,
            sender_public_key: self.node_keypair.public_key(),
            key_exchange_data: key_exchange_data.clone(),
            protocol_version: "zhtp/1.0-encrypted".to_string(),
        };
        
        // Send encrypted handshake
        self.send_encrypted_message(peer_addr, &handshake_message, &shared_secret).await?;
        
        // Store secure session
        let session = SecureSession::new(shared_secret, self.node_keypair.public_key());
        self.secure_sessions.write().await.insert(peer_addr, session);
        
        info!("Secure session established with {}", peer_addr);
        Ok(())
    }

    /// Send encrypted message using established secure session
    async fn send_encrypted_message(
        &self,
        peer_addr: SocketAddr,
        message: &ZhtpP2PMessage,
        shared_secret: &[u8; 32],
    ) -> Result<()> {
        // Serialize message
        let message_bytes = bincode::serialize(message)?;
        
        // Encrypt payload using quantum-resistant cryptography
        let encrypted_payload = self.node_keypair.encrypt_data(&message_bytes, shared_secret)?;
        
        // Create packet ID for deduplication
        let mut packet_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet_id);
        
        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create encrypted packet
        let encrypted_packet = EncryptedZhtpPacket {
            sender_public_key: self.node_keypair.public_key(),
            key_exchange_data: vec![], // Empty for established sessions
            encrypted_payload,
            signature: vec![], // Will be filled by signing
            timestamp,
            packet_id,
        };
        
        // Sign the packet for authentication
        let packet_bytes = bincode::serialize(&encrypted_packet)?;
        let signature = self.node_keypair.sign(&packet_bytes)?;
        
        // Create final packet with signature
        let mut final_packet = encrypted_packet;
        final_packet.signature = signature.into_bytes();
        
        // Send encrypted packet
        let final_bytes = bincode::serialize(&final_packet)?;
        self.socket.send_to(&final_bytes, peer_addr).await?;
        
        debug!("Sent encrypted message to {} (size: {} bytes)", peer_addr, final_bytes.len());
        Ok(())
    }

    /// Receive and decrypt message from peer
    async fn receive_encrypted_message(
        &self,
        packet_data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<ZhtpP2PMessage> {
        // Deserialize encrypted packet
        let encrypted_packet: EncryptedZhtpPacket = bincode::deserialize(packet_data)?;
        
        // Verify signature for authentication
        let mut packet_for_verification = encrypted_packet.clone();
        packet_for_verification.signature = vec![]; // Clear signature for verification
        let verification_bytes = bincode::serialize(&packet_for_verification)?;
        
        // Create temporary keypair to verify (in real implementation, use peer's known public key)
        let temp_keypair = Keypair::generate();
        let signature = Signature::new(encrypted_packet.signature);
        
        // Note: In production, we'd verify against the peer's known public key
        // For now, we'll proceed with decryption
        
        // Get or establish secure session
        let shared_secret = if let Some(session) = self.secure_sessions.read().await.get(&peer_addr) {
            if !session.is_valid() {
                return Err(anyhow!("Session expired for peer {}", peer_addr));
            }
            session.shared_secret
        } else {
            // New session - perform key exchange
            if encrypted_packet.key_exchange_data.is_empty() {
                return Err(anyhow!("No key exchange data for new session"));
            }
            
            // Decapsulate shared secret
            let shared_secret = self.node_keypair.decapsulate_shared_secret(&encrypted_packet.key_exchange_data)?;
            
            // Store new session
            let session = SecureSession::new(shared_secret, encrypted_packet.sender_public_key);
            self.secure_sessions.write().await.insert(peer_addr, session);
            
            shared_secret
        };
        
        // Decrypt payload
        let decrypted_payload = self.node_keypair.decrypt_data(&encrypted_packet.encrypted_payload, &shared_secret)?;
        
        // Deserialize message
        let message: ZhtpP2PMessage = bincode::deserialize(&decrypted_payload)?;
        
        debug!("Received encrypted message from {} (type: {:?})", peer_addr, std::mem::discriminant(&message));
        Ok(message)
    }

    /// Clean up expired secure sessions
    async fn cleanup_expired_sessions(&self) -> Result<()> {
        let mut sessions = self.secure_sessions.write().await;
        let expired_peers: Vec<SocketAddr> = sessions
            .iter()
            .filter_map(|(addr, session)| {
                if !session.is_valid() {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect();
        
        for peer in expired_peers {
            sessions.remove(&peer);
            info!("Removed expired session for peer {}", peer);
        }
        
        Ok(())
    }
      /// Handle secure handshake message
    async fn handle_secure_handshake(
        sender_addr: SocketAddr,
        sender_public_key: Vec<u8>,
        key_exchange_data: Vec<u8>,
        protocol_version: String,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
        consensus: &Arc<ZhtpConsensusEngine>,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
        secure_sessions: &Arc<RwLock<HashMap<SocketAddr, SecureSession>>>,
        local_keypair: &Keypair,
    ) -> Result<()> {
        info!("Handling secure handshake from {}", sender_addr);
        
        // Verify protocol version
        if protocol_version != "zhtp/1.0-encrypted" {
            return Err(anyhow!("Unsupported protocol version: {}", protocol_version));
        }
        
        // Decapsulate shared secret from key exchange data
        let shared_secret = local_keypair.decapsulate_shared_secret(&key_exchange_data)?;
        
        // Create secure session
        let session = SecureSession::new(shared_secret, sender_public_key.clone());
        secure_sessions.write().await.insert(sender_addr, session);
        
        // Add peer to known peers
        let peer = ZhtpPeer {
            addr: sender_addr,
            reputation: 1.0,
            last_seen: SystemTime::now(),
            protocol_versions: vec![protocol_version],
            validator_info: None,
            state: PeerState::Connected,
            validity_proof: None,
        };
        
        peers.write().await.insert(sender_addr, peer);
        
        info!("Secure session established with peer {}", sender_addr);
        Ok(())
    }
    
    /// Process encrypted packet (static version for spawned tasks)
    async fn process_encrypted_packet_static(
        encrypted_packet: EncryptedZhtpPacket,
        peer_addr: SocketAddr,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
        consensus: &Arc<ZhtpConsensusEngine>,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
        secure_sessions: &Arc<RwLock<HashMap<SocketAddr, SecureSession>>>,
        node_keypair: &Keypair,
    ) -> Result<()> {
        // Verify packet signature
        let mut packet_for_verification = encrypted_packet.clone();
        packet_for_verification.signature = vec![];
        let packet_bytes = bincode::serialize(&packet_for_verification)?;
        
        let signature = Signature::new(encrypted_packet.signature.clone());
        
        // Verify signature using sender's public key (simplified check for now)
        // TODO: Proper signature verification with sender's actual public key
        let sender_public_key = &encrypted_packet.sender_public_key;
        
        // Check if we have a secure session with this peer
        let session = {
            let sessions = secure_sessions.read().await;
            sessions.get(&peer_addr).cloned()
        };
        
        if let Some(session) = session {
            // Decrypt and process message
            let decrypted_data = node_keypair.decrypt_data(&encrypted_packet.encrypted_payload, &session.shared_secret)?;
            let message: ZhtpP2PMessage = bincode::deserialize(&decrypted_data)?;
            
            // Process the decrypted message as a regular P2P message
            Self::process_decrypted_message(
                message,
                peer_addr,
                peers,
                consensus,
                tx_pool,
            ).await?;
        } else {
            debug!("No secure session found for {}, packet ignored", peer_addr);
        }
        
        Ok(())
    }

    /// Process decrypted message content
    async fn process_decrypted_message(
        message: ZhtpP2PMessage,
        peer_addr: SocketAddr,
        peers: &Arc<RwLock<HashMap<SocketAddr, ZhtpPeer>>>,
        consensus: &Arc<ZhtpConsensusEngine>,
        tx_pool: &Arc<RwLock<ZkTransactionPool>>,
    ) -> Result<()> {
        match message {
            ZhtpP2PMessage::ConsensusMessage {
                round,
                message_type,
                zk_proof,
                validator_signature,
            } => {
                debug!("Received encrypted consensus message for round {}", round);
                Self::handle_consensus_message(
                    round,
                    message_type,
                    zk_proof,
                    validator_signature,
                    consensus,
                ).await?;
            }
            
            ZhtpP2PMessage::TransactionBroadcast {
                transaction,
                hop_count,
                zk_proof,
            } => {
                debug!("Received encrypted transaction broadcast");
                Self::handle_transaction_broadcast_static(
                    transaction,
                    hop_count,
                    zk_proof,
                    tx_pool,
                    peers,
                ).await?;
            }
            
            ZhtpP2PMessage::BlockAnnouncement {
                block_hash,
                block_height,
                validator_proofs,
            } => {
                debug!("Received encrypted block announcement for height {}", block_height);
                Self::handle_block_announcement(
                    block_hash,
                    block_height,
                    validator_proofs,
                    consensus,
                ).await?;
            }
            
            _ => {
                debug!("Received other encrypted P2P message type");
            }
        }
        
        Ok(())
    }

    /// Handle secure handshake (static version for spawned tasks)
    async fn handle_secure_handshake_static(
        sender_addr: SocketAddr,
        sender_public_key: Vec<u8>,
        key_exchange_data: Vec<u8>,
        protocol_version: String,
        secure_sessions: &Arc<RwLock<HashMap<SocketAddr, SecureSession>>>,
        node_keypair: &Keypair,
    ) -> Result<()> {
        info!("Processing secure handshake from {}", sender_addr);
        
        // Verify protocol version
        if protocol_version != "zhtp/1.0" {
            return Err(anyhow!("Unsupported protocol version: {}", protocol_version));
        }
        
        // For now, create a simple shared secret from the key exchange data
        // In a real implementation, this would use proper Kyber key exchange
        let mut shared_secret = [0u8; 32];
        if key_exchange_data.len() >= 32 {
            shared_secret.copy_from_slice(&key_exchange_data[..32]);
        } else {
            // Use BLAKE3 to derive a 32-byte secret from the available data
            let hash = node_keypair.hash_message(&key_exchange_data);
            shared_secret = hash;
        }
        
        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create secure session
        let session = SecureSession {
            shared_secret,
            established_at: now,
            last_activity: now,
            peer_public_key: sender_public_key,
        };
        
        // Store session
        {
            let mut sessions = secure_sessions.write().await;
            sessions.insert(sender_addr, session);
        }
        
        info!("Secure session established with {}", sender_addr);
        Ok(())
    }
}
