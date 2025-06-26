# ZHTP Examples and Tutorials

Practical examples and step-by-step tutorials for building on ZHTP.

## 🚀 Quick Start Examples

### 1. Hello World DApp

Create your first ZHTP DApp in 5 minutes:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Hello ZHTP</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px;
            background: linear-gradient(135deg, #0f0f23 0%, #4a0080 100%);
            color: white;
        }
        .container { max-width: 600px; margin: 0 auto; }
        button { 
            background: linear-gradient(45deg, #00ffff, #0080ff);
            color: white; border: none; padding: 15px 30px;
            border-radius: 10px; cursor: pointer; margin: 10px;
        }
        .wallet-info { 
            background: rgba(255,255,255,0.1); 
            padding: 20px; border-radius: 15px; margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Hello ZHTP World!</h1>
        <p>Your first decentralized application</p>
        
        <button onclick="connectWallet()">Connect Wallet</button>
        <button onclick="sendGreeting()">Send Greeting</button>
        
        <div id="walletInfo" class="wallet-info" style="display:none;">
            <h3>Wallet Connected</h3>
            <p><strong>Address:</strong> <span id="address"></span></p>
            <p><strong>Balance:</strong> <span id="balance"></span> ZHTP</p>
        </div>
        
        <div id="messages"></div>
    </div>

    <script>
        let wallet = null;
        
        async function connectWallet() {
            try {
                // Connect to local ZHTP node
                const response = await fetch('/api/wallet/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_type: 'quantum' })
                });
                
                wallet = await response.json();
                
                document.getElementById('address').textContent = 
                    wallet.wallet.address.substring(0, 20) + '...';
                document.getElementById('balance').textContent = '0';
                document.getElementById('walletInfo').style.display = 'block';
                
                addMessage('✅ Wallet connected successfully!');
            } catch (error) {
                addMessage('❌ Failed to connect wallet: ' + error.message);
            }
        }
        
        async function sendGreeting() {
            if (!wallet) {
                addMessage('⚠️ Please connect wallet first');
                return;
            }
            
            try {
                const response = await fetch('/api/wallet/faucet', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        wallet_address: wallet.wallet.address 
                    })
                });
                
                const result = await response.json();
                addMessage('🎉 Hello ZHTP! Received ' + result.amount + ' test tokens');
                document.getElementById('balance').textContent = result.amount;
            } catch (error) {
                addMessage('❌ Failed to send greeting: ' + error.message);
            }
        }
        
        function addMessage(msg) {
            const div = document.createElement('div');
            div.style.padding = '10px';
            div.style.margin = '10px 0';
            div.style.background = 'rgba(0,255,255,0.1)';
            div.style.borderRadius = '10px';
            div.textContent = new Date().toLocaleTimeString() + ' - ' + msg;
            document.getElementById('messages').appendChild(div);
        }
    </script>
</body>
</html>
```

**Deploy this DApp:**
1. Save as `hello-zhtp.html`
2. Upload via ZHTP browser DApp Explorer
3. Register domain `hello.zhtp`
4. Share with others!

### 2. Simple Token Contract

```rust
use zhtp_sdk::*;

#[derive(Serialize, Deserialize)]
pub struct SimpleToken {
    name: String,
    symbol: String,
    total_supply: u64,
    balances: HashMap<Address, u64>,
    owner: Address,
}

impl SimpleToken {
    #[constructor]
    pub fn new(name: String, symbol: String, initial_supply: u64) -> Self {
        let owner = msg_sender();
        let mut balances = HashMap::new();
        balances.insert(owner.clone(), initial_supply);
        
        Self {
            name,
            symbol,
            total_supply: initial_supply,
            balances,
            owner,
        }
    }
    
    #[view]
    pub fn balance_of(&self, account: &Address) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }
    
    pub fn transfer(&mut self, to: Address, amount: u64) -> Result<()> {
        let from = msg_sender();
        let from_balance = self.balance_of(&from);
        
        require!(from_balance >= amount, "Insufficient balance");
        
        self.balances.insert(from.clone(), from_balance - amount);
        let to_balance = self.balance_of(&to);
        self.balances.insert(to.clone(), to_balance + amount);
        
        emit!(Transfer { from, to, amount });
        Ok(())
    }
    
    pub fn mint(&mut self, to: Address, amount: u64) -> Result<()> {
        require!(msg_sender() == self.owner, "Not authorized");
        
        let balance = self.balance_of(&to);
        self.balances.insert(to.clone(), balance + amount);
        self.total_supply += amount;
        
        emit!(Mint { to, amount });
        Ok(())
    }
}
```

### 3. Voting Contract with ZK Privacy

```rust
use zhtp_sdk::*;
use zhtp_zk::*;

#[derive(Serialize, Deserialize)]
pub struct PrivateVoting {
    proposal: String,
    votes_for: u32,
    votes_against: u32,
    voting_end: u64,
    voted: HashSet<String>, // ZK nullifiers to prevent double voting
}

impl PrivateVoting {
    #[constructor]
    pub fn new(proposal: String, voting_duration: u64) -> Self {
        Self {
            proposal,
            votes_for: 0,
            votes_against: 0,
            voting_end: block_timestamp() + voting_duration,
            voted: HashSet::new(),
        }
    }
    
    pub fn vote(&mut self, vote: bool, proof: ZkProof) -> Result<()> {
        require!(block_timestamp() < self.voting_end, "Voting ended");
        
        // Verify ZK proof of voting eligibility
        let public_inputs = vec![vote as u64];
        require!(verify_proof(&proof, &public_inputs)?, "Invalid proof");
        
        // Extract nullifier to prevent double voting
        let nullifier = proof.nullifier();
        require!(!self.voted.contains(&nullifier), "Already voted");
        
        self.voted.insert(nullifier);
        
        if vote {
            self.votes_for += 1;
        } else {
            self.votes_against += 1;
        }
        
        emit!(VoteCast { vote });
        Ok(())
    }
    
    #[view]
    pub fn results(&self) -> (u32, u32) {
        (self.votes_for, self.votes_against)
    }
}
```

## 📚 Step-by-Step Tutorials

### Tutorial 1: Building a Decentralized Marketplace

#### Step 1: Project Setup
```bash
mkdir zhtp-marketplace
cd zhtp-marketplace
cargo init --lib
```

#### Step 2: Define Product Structure
```rust
// src/lib.rs
use zhtp_sdk::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct Product {
    id: u64,
    name: String,
    description: String,
    price: u64,
    seller: Address,
    available: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Marketplace {
    products: HashMap<u64, Product>,
    next_id: u64,
    escrow: HashMap<u64, EscrowOrder>,
}

#[derive(Serialize, Deserialize)]
pub struct EscrowOrder {
    product_id: u64,
    buyer: Address,
    amount: u64,
    created_at: u64,
}
```

#### Step 3: Implement Core Functions
```rust
impl Marketplace {
    #[constructor]
    pub fn new() -> Self {
        Self {
            products: HashMap::new(),
            next_id: 1,
            escrow: HashMap::new(),
        }
    }
    
    pub fn list_product(&mut self, 
        name: String, 
        description: String, 
        price: u64
    ) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        
        let product = Product {
            id,
            name: name.clone(),
            description,
            price,
            seller: msg_sender(),
            available: true,
        };
        
        self.products.insert(id, product);
        emit!(ProductListed { id, name, price });
        Ok(id)
    }
    
    #[payable]
    pub fn purchase(&mut self, product_id: u64) -> Result<()> {
        let product = self.products.get(&product_id)
            .ok_or("Product not found")?;
        
        require!(product.available, "Product not available");
        require!(msg_value() >= product.price, "Insufficient payment");
        
        let order = EscrowOrder {
            product_id,
            buyer: msg_sender(),
            amount: msg_value(),
            created_at: block_timestamp(),
        };
        
        self.escrow.insert(product_id, order);
        emit!(ProductPurchased { product_id, buyer: msg_sender() });
        Ok(())
    }
    
    pub fn confirm_delivery(&mut self, product_id: u64) -> Result<()> {
        let order = self.escrow.get(&product_id)
            .ok_or("Order not found")?;
        
        require!(msg_sender() == order.buyer, "Not the buyer");
        
        let product = self.products.get(&product_id).unwrap();
        transfer(product.seller.clone(), order.amount);
        
        self.escrow.remove(&product_id);
        emit!(DeliveryConfirmed { product_id });
        Ok(())
    }
}
```

#### Step 4: Frontend Integration
```html
<!DOCTYPE html>
<html>
<head>
    <title>ZHTP Marketplace</title>
    <style>
        /* Quantum marketplace styling */
        body { 
            background: linear-gradient(135deg, #0f0f23 0%, #4a0080 100%);
            color: white; font-family: Arial, sans-serif; 
        }
        .product-grid { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px; padding: 20px; 
        }
        .product-card {
            background: rgba(255,255,255,0.1); border-radius: 15px;
            padding: 20px; transition: transform 0.3s;
        }
        .product-card:hover { transform: translateY(-5px); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛒 ZHTP Decentralized Marketplace</h1>
        
        <div class="listing-form">
            <h2>List New Product</h2>
            <input type="text" id="productName" placeholder="Product name">
            <textarea id="productDesc" placeholder="Description"></textarea>
            <input type="number" id="productPrice" placeholder="Price (ZHTP)">
            <button onclick="listProduct()">List Product</button>
        </div>
        
        <div class="product-grid" id="productGrid">
            <!-- Products will be loaded here -->
        </div>
    </div>

    <script>
        let contract = null;
        
        async function init() {
            // Connect to marketplace contract
            contract = await zhtp.getContract('marketplace.zhtp');
            loadProducts();
        }
        
        async function listProduct() {
            const name = document.getElementById('productName').value;
            const desc = document.getElementById('productDesc').value;
            const price = document.getElementById('productPrice').value;
            
            try {
                await contract.list_product(name, desc, price * 1e18);
                alert('Product listed successfully!');
                loadProducts();
            } catch (error) {
                alert('Failed to list product: ' + error.message);
            }
        }
        
        async function loadProducts() {
            const products = await contract.get_all_products();
            const grid = document.getElementById('productGrid');
            grid.innerHTML = '';
            
            products.forEach(product => {
                const card = document.createElement('div');
                card.className = 'product-card';
                card.innerHTML = `
                    <h3>${product.name}</h3>
                    <p>${product.description}</p>
                    <p><strong>Price:</strong> ${product.price / 1e18} ZHTP</p>
                    <p><strong>Seller:</strong> ${product.seller.substring(0, 10)}...</p>
                    <button onclick="purchaseProduct(${product.id})">
                        Purchase
                    </button>
                `;
                grid.appendChild(card);
            });
        }
        
        async function purchaseProduct(productId) {
            try {
                const product = await contract.get_product(productId);
                await contract.purchase(productId, { value: product.price });
                alert('Product purchased! Waiting for delivery confirmation.');
            } catch (error) {
                alert('Purchase failed: ' + error.message);
            }
        }
        
        // Initialize on page load
        window.onload = init;
    </script>
</body>
</html>
```

### Tutorial 2: Privacy-Preserving DAO

#### Step 1: Anonymous Voting Circuit
```circom
pragma circom 2.0.0;

template AnonymousVote() {
    signal input voter_id;
    signal input vote; // 0 or 1
    signal input nullifier_secret;
    
    signal output nullifier;
    signal output vote_commitment;
    
    component hasher1 = Poseidon(2);
    hasher1.inputs[0] <== voter_id;
    hasher1.inputs[1] <== nullifier_secret;
    nullifier <== hasher1.out;
    
    component hasher2 = Poseidon(2);
    hasher2.inputs[0] <== vote;
    hasher2.inputs[1] <== voter_id;
    vote_commitment <== hasher2.out;
}

component main = AnonymousVote();
```

#### Step 2: DAO Smart Contract
```rust
use zhtp_sdk::*;
use zhtp_zk::*;

#[derive(Serialize, Deserialize)]
pub struct PrivateDAO {
    proposals: HashMap<u64, Proposal>,
    member_commitments: HashSet<String>,
    voting_nullifiers: HashSet<String>,
    next_proposal_id: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Proposal {
    id: u64,
    title: String,
    description: String,
    votes_for: u32,
    votes_against: u32,
    created_at: u64,
    voting_end: u64,
}

impl PrivateDAO {
    #[constructor]
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            member_commitments: HashSet::new(),
            voting_nullifiers: HashSet::new(),
            next_proposal_id: 1,
        }
    }
    
    pub fn join_dao(&mut self, membership_proof: ZkProof) -> Result<()> {
        // Verify membership eligibility (e.g., token holdings)
        require!(verify_membership_proof(&membership_proof)?, "Invalid membership proof");
        
        let commitment = membership_proof.commitment();
        require!(!self.member_commitments.contains(&commitment), "Already a member");
        
        self.member_commitments.insert(commitment);
        emit!(MemberJoined { commitment });
        Ok(())
    }
    
    pub fn create_proposal(&mut self, 
        title: String, 
        description: String,
        voting_duration: u64
    ) -> Result<u64> {
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        
        let proposal = Proposal {
            id,
            title: title.clone(),
            description,
            votes_for: 0,
            votes_against: 0,
            created_at: block_timestamp(),
            voting_end: block_timestamp() + voting_duration,
        };
        
        self.proposals.insert(id, proposal);
        emit!(ProposalCreated { id, title });
        Ok(id)
    }
    
    pub fn vote(&mut self, 
        proposal_id: u64, 
        vote_proof: ZkProof
    ) -> Result<()> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or("Proposal not found")?;
        
        require!(block_timestamp() < proposal.voting_end, "Voting period ended");
        
        // Verify anonymous vote proof
        require!(verify_vote_proof(&vote_proof)?, "Invalid vote proof");
        
        let nullifier = vote_proof.nullifier();
        require!(!self.voting_nullifiers.contains(&nullifier), "Already voted");
        
        self.voting_nullifiers.insert(nullifier);
        
        // Extract vote from proof
        let vote = vote_proof.public_signal(0) == 1;
        if vote {
            proposal.votes_for += 1;
        } else {
            proposal.votes_against += 1;
        }
        
        emit!(VoteCast { proposal_id, vote });
        Ok(())
    }
}
```

## 🛠️ Development Patterns

### 1. Secure State Management

```rust
// Use proper access controls
#[derive(Serialize, Deserialize)]
pub struct SecureContract {
    owner: Address,
    admins: HashSet<Address>,
    paused: bool,
}

impl SecureContract {
    fn only_owner(&self) -> Result<()> {
        require!(msg_sender() == self.owner, "Only owner");
        Ok(())
    }
    
    fn only_admin(&self) -> Result<()> {
        require!(
            self.admins.contains(&msg_sender()) || msg_sender() == self.owner,
            "Only admin"
        );
        Ok(())
    }
    
    fn when_not_paused(&self) -> Result<()> {
        require!(!self.paused, "Contract paused");
        Ok(())
    }
    
    pub fn emergency_pause(&mut self) -> Result<()> {
        self.only_admin()?;
        self.paused = true;
        emit!(EmergencyPause {});
        Ok(())
    }
}
```

### 2. Efficient Storage Patterns

```rust
// Use packed structs for gas optimization
#[derive(Serialize, Deserialize)]
pub struct PackedData {
    // Pack multiple small values into single u64
    // bits 0-31: user_id (32 bits)
    // bits 32-63: timestamp (32 bits)
    packed: u64,
}

impl PackedData {
    pub fn new(user_id: u32, timestamp: u32) -> Self {
        let packed = (timestamp as u64) << 32 | (user_id as u64);
        Self { packed }
    }
    
    pub fn user_id(&self) -> u32 {
        (self.packed & 0xFFFFFFFF) as u32
    }
    
    pub fn timestamp(&self) -> u32 {
        (self.packed >> 32) as u32
    }
}
```

### 3. Event-Driven Architecture

```rust
// Define comprehensive events
#[derive(Serialize, Deserialize)]
pub enum ContractEvent {
    UserRegistered { user: Address, timestamp: u64 },
    TokenMinted { to: Address, amount: u64 },
    TransferCompleted { from: Address, to: Address, amount: u64 },
    ProposalCreated { id: u64, proposer: Address },
    VoteCast { proposal_id: u64, voter: Address, vote: bool },
}

// Emit events for off-chain monitoring
impl MyContract {
    pub fn transfer(&mut self, to: Address, amount: u64) -> Result<()> {
        // ... transfer logic ...
        
        emit!(ContractEvent::TransferCompleted {
            from: msg_sender(),
            to: to.clone(),
            amount
        });
        
        Ok(())
    }
}
```

## 🔍 Testing Examples

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use zhtp_test_utils::*;
    
    #[test]
    fn test_token_transfer() {
        let mut token = SimpleToken::new(
            "Test Token".to_string(),
            "TEST".to_string(),
            1000
        );
        
        let alice = Address::from("alice");
        let bob = Address::from("bob");
        
        // Setup test context
        set_msg_sender(alice.clone());
        
        // Test successful transfer
        assert!(token.transfer(bob.clone(), 100).is_ok());
        assert_eq!(token.balance_of(&alice), 900);
        assert_eq!(token.balance_of(&bob), 100);
        
        // Test insufficient balance
        assert!(token.transfer(bob, 1000).is_err());
    }
    
    #[tokio::test]
    async fn test_integration() {
        let network = TestNetwork::new().await;
        let alice = network.create_account().await;
        let bob = network.create_account().await;
        
        // Deploy contract
        let contract = SimpleToken::deploy(
            &network,
            alice.clone(),
            ("Test Token".to_string(), "TEST".to_string(), 1000)
        ).await.unwrap();
        
        // Test transfer
        let result = contract
            .transfer(&alice, bob.address(), 100)
            .await;
        
        assert!(result.is_ok());
    }
}
```

### Load Testing

```rust
use tokio::time::{sleep, Duration};
use futures::future::join_all;

#[tokio::test]
async fn load_test_transfers() {
    let network = TestNetwork::new().await;
    let contract = deploy_test_token(&network).await;
    
    // Create 100 concurrent transfer operations
    let mut tasks = vec![];
    
    for i in 0..100 {
        let contract_clone = contract.clone();
        let task = tokio::spawn(async move {
            contract_clone.transfer(
                random_address(),
                10
            ).await
        });
        tasks.push(task);
    }
    
    // Wait for all transfers to complete
    let results = join_all(tasks).await;
    
    // Verify success rate
    let successful = results.iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();
    
    assert!(successful >= 95); // 95% success rate
}
```

## 📦 Deployment Scripts

### Automated Deployment

```bash
#!/bin/bash
# deploy.sh

set -e

echo "🚀 Deploying ZHTP DApp..."

# Build contracts
echo "Building smart contracts..."
cargo build --release --target wasm32-unknown-unknown

# Deploy to testnet
echo "Deploying to testnet..."
CONTRACT_ADDRESS=$(curl -X POST http://localhost:3000/api/contracts/deploy \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"MyDApp\",
    \"code\": \"$(base64 -i target/wasm32-unknown-unknown/release/my_dapp.wasm)\",
    \"constructor_args\": [\"InitialValue\"]
  }" | jq -r '.contract_address')

echo "Contract deployed at: $CONTRACT_ADDRESS"

# Register domain
echo "Registering domain..."
curl -X POST http://localhost:3000/api/dns/register \
  -H "Content-Type: application/json" \
  -d "{
    \"domain\": \"mydapp.zhtp\",
    \"addresses\": [\"$CONTRACT_ADDRESS\"],
    \"ttl\": 3600
  }"

echo "✅ Deployment complete!"
echo "Access your DApp at: http://localhost:3000/mydapp.zhtp"
```

### Environment Configuration

```toml
# deploy.toml
[testnet]
node_url = "http://localhost:3000"
private_key = "your_deployer_private_key"
gas_limit = 1000000

[mainnet]
node_url = "https://mainnet.zhtp.network"
private_key_file = "/secure/path/to/mainnet.key"
gas_limit = 500000

[contracts]
token = "contracts/token.wasm"
marketplace = "contracts/marketplace.wasm"
dao = "contracts/dao.wasm"
```

## 🎯 Best Practices Summary

1. **Security First**
   - Always validate inputs
   - Use access controls
   - Implement emergency stops
   - Test extensively

2. **Gas Optimization**
   - Pack data structures
   - Batch operations
   - Use efficient algorithms
   - Cache frequently accessed data

3. **User Experience**
   - Provide clear feedback
   - Handle errors gracefully
   - Optimize loading times
   - Support mobile devices

4. **Maintainability**
   - Write comprehensive tests
   - Document your code
   - Use version control
   - Plan for upgrades

---

Ready to build on ZHTP? Start with the [Getting Started Guide](getting-started.md) and join our [Developer Community](https://discord.gg/zhtp)!
