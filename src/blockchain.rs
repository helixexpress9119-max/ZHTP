use crate::zhtp::{
    consensus_engine::ZkNetworkMetrics,
    zk_transactions::{ZkTransaction, ZkBalance, ZkTransactionPool},
    zk_proofs::ByteRoutingProof,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;
use rand;

/// Statistics about zero-knowledge transactions in the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkBlockchainStats {
    pub total_zk_transactions: u64,
    pub blocks_with_private_txs: u64,
    pub pending_zk_transactions: u64,
    pub private_accounts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: i64,
    pub signature: String,
    pub nonce: u64,
    pub data: Vec<u8>,
    // Zero-knowledge transaction data (optional for privacy)
    pub zk_transaction: Option<ZkTransaction>,
    // If true, transaction details are encrypted in zk_transaction
    pub is_private: bool,
    // ZK proof that this transaction is valid (when private)
    pub validity_proof: Option<ByteRoutingProof>,
}

impl Transaction {
    pub fn new(from: String, to: String, amount: f64) -> Self {
        Transaction {
            from,
            to,
            amount,
            timestamp: Utc::now().timestamp(),
            signature: String::new(),
            nonce: 0,
            data: Vec::new(),
            zk_transaction: None,
            is_private: false,
            validity_proof: None,
        }
    }

    pub fn with_data(from: String, to: String, amount: f64, data: Vec<u8>) -> Self {
        Transaction {
            from,
            to,
            amount,
            timestamp: Utc::now().timestamp(),
            signature: String::new(),
            nonce: 0,
            data,
            zk_transaction: None,
            is_private: false,
            validity_proof: None,
        }
    }

    /// Create a zero-knowledge private transaction
    pub fn new_private(zk_transaction: ZkTransaction) -> Result<Self, anyhow::Error> {
        let tx_hash = zk_transaction.get_hash();
        
        Ok(Transaction {
            from: "private".to_string(),  // Hidden in ZK transaction
            to: "private".to_string(),    // Hidden in ZK transaction  
            amount: zk_transaction.fee,   // Only fee visible
            timestamp: zk_transaction.timestamp as i64,
            signature: format!("zk_proof:{}", hex::encode(&tx_hash[0..16])),
            nonce: 0, // Nonce handled in ZK transaction
            data: tx_hash.to_vec(), // Store transaction hash
            zk_transaction: Some(zk_transaction.clone()),
            is_private: true,
            validity_proof: Some(zk_transaction.validity_proof.clone()),
        })
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let data = format!(
            "{}{}{}{}{}",
            self.from, self.to, self.amount, self.timestamp, self.nonce
        );
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign transaction using post-quantum Dilithium5 signatures
    pub fn sign(&mut self, private_key: &[u8]) -> Result<(), anyhow::Error> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{SignedMessage, SecretKey};
        
        // Convert private key bytes to Dilithium5 secret key
        let secret_key = dilithium5::SecretKey::from_bytes(private_key)
            .map_err(|_| anyhow::anyhow!("Invalid secret key format"))?;
        
        // Create message to sign (transaction hash)
        let hash = self.calculate_hash();
        let message = hash.as_bytes();
        
        // Generate post-quantum signature
        let signed_message = dilithium5::sign(message, &secret_key);
        let signature_bytes = signed_message.as_bytes();
        
        // Store as base64 for serialization  
        self.signature = base64::prelude::BASE64_STANDARD.encode(signature_bytes);
        Ok(())
    }

    /// Verify transaction signature using post-quantum Dilithium5 verification
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{PublicKey, SignedMessage};
        
        if self.signature.is_empty() {
            return false;
        }
        
        // Decode signature from base64
        let signature_bytes = match base64::prelude::BASE64_STANDARD.decode(&self.signature) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        
        // Convert public key bytes to Dilithium5 public key
        let public_key = match dilithium5::PublicKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        
        // Create signed message from signature bytes
        let signed_message = match dilithium5::SignedMessage::from_bytes(&signature_bytes) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        // Verify signature against transaction hash
        let hash = self.calculate_hash();
        let message = hash.as_bytes();
        
        match dilithium5::open(&signed_message, &public_key) {
            Ok(verified_message) => verified_message == message,
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub validator: String,
    pub validator_score: f64,
    pub network_metrics: Option<ZkNetworkMetrics>,
    // Zero-knowledge block features
    pub zk_transaction_count: u64,
    pub private_transaction_root: Option<[u8; 32]>,
    pub block_validity_proof: Option<ByteRoutingProof>,
    pub has_private_transactions: bool,
}

impl Block {
    pub fn new(
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        validator: String,
        validator_score: f64,
        network_metrics: Option<ZkNetworkMetrics>,
    ) -> Self {
        // Count ZK transactions and calculate private transaction root
        let zk_transaction_count = transactions.iter().filter(|tx| tx.is_private).count() as u64;
        let has_private_transactions = zk_transaction_count > 0;
        
        let private_transaction_root = if has_private_transactions {
            Some(Self::calculate_private_transaction_root(&transactions))
        } else {
            None
        };
        
        let mut block = Block {
            index,
            timestamp: Utc::now().timestamp(),
            transactions,
            previous_hash,
            hash: String::new(),
            validator,
            validator_score,
            network_metrics,
            zk_transaction_count,
            private_transaction_root,
            block_validity_proof: None, // Generated after block creation
            has_private_transactions,
        };
        block.hash = block.calculate_hash();
        block
    }

    /// Calculate Merkle root of private transaction commitments
    fn calculate_private_transaction_root(transactions: &[Transaction]) -> [u8; 32] {
        let private_hashes: Vec<[u8; 32]> = transactions
            .iter()
            .filter(|tx| tx.is_private)
            .map(|tx| {
                if let Some(zk_tx) = &tx.zk_transaction {
                    zk_tx.commitment
                } else {
                    [0u8; 32] // Fallback for invalid private transactions
                }
            })
            .collect();
        
        if private_hashes.is_empty() {
            return [0u8; 32];
        }
        
        // Simple Merkle root calculation (in production, use proper Merkle tree)
        let mut hasher = Sha256::new();
        for hash in &private_hashes {
            hasher.update(hash);
        }
        let result = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&result[..32]);
        root
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let data = format!(
            "{}{}{}{}{}{}",
            self.index,
            self.timestamp,
            serde_json::to_string(&self.transactions).unwrap(),
            self.previous_hash,
            self.validator,
            self.validator_score
        );
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone)]
struct ChainState {
    chain: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    balances: HashMap<String, f64>,
    transaction_nonces: HashMap<String, u64>,
    // Zero-knowledge transaction management
    zk_transaction_pool: ZkTransactionPool,
    private_balances: HashMap<String, ZkBalance>,
}

impl ChainState {
    fn new() -> Self {
        let mut chain = Vec::new();
        chain.push(Block::new(
            0,
            Vec::new(),
            String::from("0"),
            String::from("genesis"),
            0.0,
            None,
        ));

        Self {
            chain,
            pending_transactions: Vec::new(),
            balances: HashMap::new(),
            transaction_nonces: HashMap::new(),
            zk_transaction_pool: ZkTransactionPool::new(),
            private_balances: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Blockchain {
    state: Arc<RwLock<ChainState>>,
    pub base_reward: f64,
}

impl Blockchain {    pub fn new(base_reward: f64) -> Self {
        Self {
            state: Arc::new(RwLock::new(ChainState::new())),
            base_reward,
        }
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> bool {
        if transaction.from.is_empty() || transaction.to.is_empty() {
            return false;
        }

        let mut state = self.state.write().await;
        
        // Prevent nonce manipulation - validate provided nonce
        let expected_nonce = {
            let current_nonce = state.transaction_nonces
                .entry(transaction.from.clone())
                .or_insert(0);
            *current_nonce
        };
        
        // Always validate the provided nonce to prevent replay attacks
        if transaction.nonce != expected_nonce {
            // Nonce validation working correctly - only log occasionally to reduce spam
            if rand::random::<u8>() < 10 { // Log ~4% of nonce errors
                println!("🔒 Nonce validation active: expected {}, got {} from {}", 
                    expected_nonce, transaction.nonce, transaction.from);
            }
            return false;
        }
        
        // Update nonce ONLY after validation
        if let Some(nonce_entry) = state.transaction_nonces.get_mut(&transaction.from) {
            *nonce_entry += 1;
        }

        // Check balance
        if transaction.from != "network" {
            let balance = state.balances.get(&transaction.from).unwrap_or(&0.0);
            if *balance < transaction.amount {
                return false;
            }
        }

        state.pending_transactions.push(transaction);
        true
    }

    /// Add a zero-knowledge transaction to the pool
    pub async fn add_zk_transaction(&self, zk_transaction: ZkTransaction) -> Result<bool, anyhow::Error> {
        let mut state = self.state.write().await;
        
        // Add to ZK transaction pool
        let result = state.zk_transaction_pool.add_transaction(zk_transaction.clone());
        
        if result.is_ok() {
            // Convert to regular transaction for blockchain inclusion
            let blockchain_tx = Transaction::new_private(zk_transaction)?;
            state.pending_transactions.push(blockchain_tx);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get a copy of pending ZK transactions
    pub async fn get_pending_zk_transactions(&self) -> Vec<ZkTransaction> {
        let state = self.state.read().await;
        state.zk_transaction_pool.get_pending_transactions()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Process ZK transactions and update private balances
    pub async fn process_zk_transactions(&self, block: &Block) -> Result<(), anyhow::Error> {
        let _state = self.state.read().await;
        
        for transaction in &block.transactions {
            if transaction.is_private {
                if let Some(zk_tx) = &transaction.zk_transaction {
                    // Update private balances based on ZK transaction commitments
                    // In a real implementation, this would use the ZK proofs to update balances
                    // without revealing the actual amounts
                    
                    // For now, we track the transaction commitment
                    let _tx_hash = hex::encode(zk_tx.get_hash());
                    println!("Processed private transaction with commitment: {}", 
                             hex::encode(zk_tx.commitment));
                }
            }
        }
        
        Ok(())
    }

    /// Get private balance for an account (returns commitment)
    pub async fn get_private_balance(&self, account: &str) -> Option<ZkBalance> {
        let state = self.state.read().await;
        state.private_balances.get(account).cloned()
    }

    /// Set private balance for an account
    pub async fn set_private_balance(&self, account: String, balance: ZkBalance) {
        let mut state = self.state.write().await;
        state.private_balances.insert(account, balance);
    }

    /// Check if the blockchain supports zero-knowledge transactions
    pub fn supports_zk_transactions(&self) -> bool {
        true
    }

    /// Get statistics about ZK transactions in the blockchain
    pub async fn get_zk_statistics(&self) -> ZkBlockchainStats {
        let state = self.state.read().await;
        
        let mut total_zk_transactions = 0u64;
        let mut blocks_with_private_txs = 0u64;
        
        for block in &state.chain {
            total_zk_transactions += block.zk_transaction_count;
            if block.has_private_transactions {
                blocks_with_private_txs += 1;
            }
        }
        
        ZkBlockchainStats {
            total_zk_transactions,
            blocks_with_private_txs,
            pending_zk_transactions: state.zk_transaction_pool.get_pending_transactions().len() as u64,
            private_accounts: state.private_balances.len() as u64,
        }
    }

    pub fn calculate_reward(&self, validator_score: f64, network_metrics: &ZkNetworkMetrics) -> f64 {
        let base = self.base_reward * validator_score;
        let delivery_multiplier = network_metrics.get_delivery_success_rate();
        let latency_multiplier = (1000.0 - network_metrics.average_latency().min(1000.0)) / 1000.0;
        let routing_multiplier = 1.0 + (network_metrics.packets_routed as f64 / 100.0).min(0.2);
        base * delivery_multiplier * latency_multiplier * routing_multiplier
    }

    pub async fn get_latest_block(&self) -> Block {
        let state = self.state.read().await;
        state.chain.last().unwrap().clone()
    }

    pub async fn get_balance(&self, address: &str) -> f64 {
        let state = self.state.read().await;
        *state.balances.get(address).unwrap_or(&0.0)
    }

    pub async fn get_transactions(&self) -> Vec<Transaction> {
        let state = self.state.read().await;
        let mut all_transactions = Vec::new();
        
        // Get transactions from all blocks
        for block in state.chain.iter() {
            all_transactions.extend(block.transactions.clone());
        }
        
        // Add pending transactions
        all_transactions.extend(state.pending_transactions.clone());
        
        all_transactions
    }

    pub async fn create_block(
        &self,
        validator_id: &str,
        validator_score: f64,
        network_metrics: Option<ZkNetworkMetrics>,
    ) {
        let mut state = self.state.write().await;

        // Calculate reward
        let reward = if let Some(metrics) = &network_metrics {
            self.calculate_reward(validator_score, metrics)
        } else {
            self.base_reward * validator_score
        };

        // Create reward transaction with proper network signature
        let mut reward_tx = Transaction::new(
            String::from("network"),
            validator_id.to_string(),
            reward,
        );
        
        // Generate network keypair for signing (in production, this would be a persistent network key)
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::SecretKey;
        let (_network_pk, network_sk) = dilithium5::keypair();
        
        reward_tx.sign(network_sk.as_bytes()).map_err(|e| {
            eprintln!("Failed to sign network reward transaction: {}", e);
        }).ok();

        // Get all transactions
        let mut transactions = Vec::new();
        transactions.push(reward_tx);
        transactions.append(&mut state.pending_transactions);

        // Create new block
        let new_block = Block::new(
            state.chain.len() as u64,
            transactions,
            state.chain.last().unwrap().hash.clone(),
            validator_id.to_string(),
            validator_score,
            network_metrics,
        );

        // Add block and update balances
        state.chain.push(new_block);

        // Update balances
        let mut new_balances = HashMap::new();
        for block in &state.chain {
            for tx in &block.transactions {
                if tx.from != "network" {
                    *new_balances.entry(tx.from.clone()).or_insert(0.0) -= tx.amount;
                }
                *new_balances.entry(tx.to.clone()).or_insert(0.0) += tx.amount;
            }
        }
        state.balances = new_balances;
    }
}

// ...existing code...
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dynamic_rewards() {
        let blockchain = Blockchain::new(100.0);

        let mut good_metrics = ZkNetworkMetrics::new(1000.0);
        good_metrics.packets_routed = 50;
        good_metrics.update_routing_metrics(50.0, 1024);
        good_metrics.update_reputation(true);
        good_metrics.update_reputation(true);

        let mut poor_metrics = ZkNetworkMetrics::new(1000.0);
        poor_metrics.packets_routed = 10;
        poor_metrics.update_routing_metrics(500.0, 1024);
        poor_metrics.update_reputation(false);
        poor_metrics.update_reputation(false);

        blockchain.create_block("good_node", 0.9, Some(good_metrics.clone())).await;
        blockchain.create_block("poor_node", 0.9, Some(poor_metrics.clone())).await;

        let good_balance = blockchain.get_balance("good_node").await;
        let poor_balance = blockchain.get_balance("poor_node").await;

        assert!(good_balance > poor_balance);
        assert!(good_balance > blockchain.base_reward * 0.9);
        assert!(poor_balance < blockchain.base_reward * 0.9);
    }
}
