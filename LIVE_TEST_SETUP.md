🚀 ZHTP Live Network Testing - Multi-Machine Setup
======================================================

## 🎯 Live Test Setup (Cross-System Network Testing)

**Purpose**: Test the ZHTP network across multiple physical machines to verify true decentralized functionality.

### Step 1: Connect to Test Machine
```bash
ssh user@your-test-machine-ip
```

### Step 2: Clone ZHTP Repository
```bash
git clone https://github.com/SOVEREIGN-NETWORK/ZHTP.git
cd ZHTP
```

### Step 3: Install Rust (if needed)
```bash
# Check if Rust is installed
cargo --version

# If not installed, install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Step 4: Build ZHTP
```bash
cargo build --release
```

### Step 5: Create Validator Configuration
```bash
# Create config directory
mkdir -p ~/.zhtp/validator

# Create validator config file
cat > ~/.zhtp/validator/config.toml << 'EOF'
[node]
name = "test-validator-node"
bind_address = "0.0.0.0:7000"
p2p_address = "0.0.0.0:8000"
public_address = "YOUR_PUBLIC_IP:8000"

[network]
bootstrap_nodes = ["BOOTSTRAP_NODE_IP:8000"]
max_peers = 50
discovery_interval = 30

[consensus]
validator = true
stake_amount = 1000

[economics]
enable_mining = true
reward_address = "auto"

[storage]
data_dir = "~/.zhtp/validator/data"
max_storage = "10GB"

[security]
enable_monitoring = true
log_level = "info"
EOF
```

### Step 6: Create Startup Script
```bash
# Create startup script
cat > ~/.zhtp/validator/start-node.sh << 'EOF'
#!/bin/bash
cd ~/.zhtp/validator
echo "🚀 Starting ZHTP Test Validator Node"
echo "====================================="
echo "Node Port: 7000"
echo "P2P Port: 8000"
echo "Bootstrap: BOOTSTRAP_NODE_IP:8000"
echo ""

export ZHTP_NODE_NAME="test-validator-node"
export ZHTP_CONFIG_PATH="~/.zhtp/validator/config.toml"
export RUST_LOG=info

~/ZHTP/target/release/network-service --config ~/.zhtp/validator/config.toml
EOF

# Make it executable
chmod +x ~/.zhtp/validator/start-node.sh
```

### Step 7: Run the Node
```bash
# Start the validator node
cd ~/.zhtp/validator
./start-node.sh
```

## 🌐 Alternative: Use Setup Script

If you prefer automated setup:

### For Windows Users:
```bash
# Run the automated setup
cd ZHTP
./setup-production-node.bat
```

### For Linux Users:
```bash
# Create and run Linux setup script
./setup-linux-node.sh
```

## 📊 Verify Connection

### Check Node Status:
```bash
curl http://localhost:7000/api/status
curl http://YOUR_PUBLIC_IP:7000/api/status  # External access
```

### Check P2P Connection:
```bash
curl http://localhost:7000/api/peers
```

### View Logs:
```bash
tail -f ~/.zhtp/validator/logs/node.log
```

## 🌍 Access DApps

Once running, access via browser:
- **Welcome Page**: http://YOUR_PUBLIC_IP:7000/browser/welcome.html
- **Main Browser**: http://YOUR_PUBLIC_IP:7000/browser/index.html
- **Whisper Chat**: http://YOUR_PUBLIC_IP:7000/browser/whisper.html
- **API Status**: http://YOUR_PUBLIC_IP:7000/api/status

## 🔧 Troubleshooting

### Firewall Issues:
```bash
# Open required ports (standard ZHTP ports)
sudo ufw allow 7000
sudo ufw allow 8000
```

### Build Issues:
```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

### Connection Issues:
```bash
# Check if bootstrap node is reachable
telnet BOOTSTRAP_NODE_IP 8000
ping BOOTSTRAP_NODE_IP
```

### Check Running Services:
```bash
ps aux | grep network-service
netstat -tulpn | grep 7000
netstat -tulpn | grep 8000
```

## 💰 Token Earnings

Once connected:
- ✅ Automatic ZHTP token earning starts
- ✅ Validator rewards for consensus participation  
- ✅ Network rewards for P2P routing
- ✅ Storage rewards for hosting content

Expected earnings: **30-100 ZHTP tokens per day**

## 🎯 Quick Commands Reference

```bash
# Start node
cd ~/.zhtp/validator && ./start-node.sh

# Stop node
pkill -f network-service

# Check status
curl localhost:7000/api/status

# View peers
curl localhost:7000/api/peers

# Check wallet
curl localhost:7000/api/wallet

# View network stats
curl localhost:7000/api/network/stats
```

## 🔗 Network Information

- **Bootstrap Node**: BOOTSTRAP_NODE_IP:8000 (provided separately)
- **Your Test Node**: YOUR_PUBLIC_IP:8000
- **Network ID**: zhtp-testnet
- **Consensus**: Proof-of-Stake with Economics

✅ **Your test node is now ready to join the ZHTP live test network!**

---

### 🌐 Cross-System Network Testing Overview

This setup allows testing ZHTP's true decentralized Web4 capabilities across:
- **Multiple Physical Machines**: Different computers, servers, or VPS instances
- **Different Networks**: Various ISPs, geographic locations, and network conditions  
- **Real Network Conditions**: Actual internet latency, packet loss, and routing
- **True Decentralization**: No single point of failure testing

### 📋 Pre-Test Requirements

**Network Requirements:**
- At least 2 separate machines (recommended: 3+ for proper testing)
- Open ports 7000-8005 for ZHTP traffic
- Stable internet connection on each machine
- Public IP or port forwarding capability

**Machine Requirements:**
- 4GB+ RAM per machine
- 10GB+ free disk space
- Modern OS (Windows 10+, Ubuntu 18.04+, macOS 10.15+)

### 🎯 Live Test Scenarios

#### Test 1: Bootstrap + Validator Connection
1. **Machine A (Bootstrap)**: Run main ZHTP network node
2. **Machine B (Validator)**: Connect as validator and verify consensus
3. **Verify**: Check ZK proof validation across machines

#### Test 2: Multi-Node Consensus
1. **Machine A**: Bootstrap node
2. **Machine B**: Validator node  
3. **Machine C**: Secondary validator
4. **Verify**: Consensus works with 3+ nodes, Byzantine fault tolerance

#### Test 3: Cross-Network DApp Testing
1. Deploy smart contract on Machine A
2. Execute contract call from Machine B
3. Verify state changes propagated to Machine C
4. **Verify**: True decentralized contract execution

#### Test 4: ZK Identity Testing
1. Create ZK identity on Machine A
2. Verify identity from Machine B
3. Perform anonymous transaction from Machine C
4. **Verify**: Cross-network privacy preservation

### 📋 **Network Configuration**

Before running live tests, configure your network settings:

1. **Copy the configuration template:**
   ```bash
   cp live-test-config.template live-test-config.env
   ```

2. **Edit the configuration file:**
   ```bash
   # Replace placeholder values with your actual network information
   nano live-test-config.env
   ```

3. **Key settings to configure:**
   - `BOOTSTRAP_NODE_IP`: IP address of your bootstrap node
   - `YOUR_PUBLIC_IP`: Public IP address of each test machine
   - Network ports (default: 7000 for HTTP, 8000 for P2P)

### 🔧 Network Verification Commands

After setup, run these on each machine to verify network health:

```bash
# Check node connectivity
curl http://localhost:7000/api/network/peers

# Verify consensus participation  
curl http://localhost:7000/api/consensus/status

# Test ZK proof generation
curl http://localhost:7000/api/zk/test-proof

# Check cross-node synchronization
curl http://localhost:7000/api/blockchain/sync-status
```

### 📊 Success Metrics

**Network Health Indicators:**
- ✅ Multiple peers discovered and connected
- ✅ ZK proofs validated across all nodes
- ✅ Consensus achieved with >67% validator participation
- ✅ Smart contracts executable from any node
- ✅ Anonymous transactions processed correctly
- ✅ No single point of failure

**Performance Benchmarks:**
- Transaction finality: <5 seconds
- ZK proof generation: <30 seconds
- Cross-node synchronization: <60 seconds
- Network discovery: <2 minutes
