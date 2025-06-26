#!/bin/bash
# ZHTP Validator Node Setup Script (Linux)
# This script sets up a validator node to connect to the bootstrap node

set -e

echo "🚀 ZHTP Validator Node Setup"
echo "============================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BOOTSTRAP_IP="172.56.201.218"
BOOTSTRAP_PORT="8000"
NODE_PORT="7000"
P2P_PORT="8000"
NODE_NAME="validator-node-1"

echo -e "${BLUE}📋 Configuration:${NC}"
echo "  Bootstrap Node: $BOOTSTRAP_IP:$BOOTSTRAP_PORT"
echo "  Node API Port: $NODE_PORT"
echo "  Node P2P Port: $P2P_PORT"
echo "  Node Name: $NODE_NAME"
echo ""

# Check if we're in the ZHTP directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}❌ Error: Please run this script from the ZHTP directory${NC}"
    echo "Run: cd ZHTP && ./setup-linux-node.sh"
    exit 1
fi

# Install Rust if not present
echo -e "${YELLOW}🔧 Checking Rust installation...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
else
    echo -e "${GREEN}✅ Rust is already installed${NC}"
fi

# Build ZHTP
echo -e "${YELLOW}🔨 Building ZHTP...${NC}"
cargo build --release

# Create validator directory
echo -e "${YELLOW}📁 Creating validator configuration...${NC}"
mkdir -p ~/.zhtp/validator/data
mkdir -p ~/.zhtp/validator/logs

# Create validator configuration
cat > ~/.zhtp/validator/config.toml << EOF
[node]
name = "$NODE_NAME"
bind_address = "0.0.0.0:$NODE_PORT"
p2p_address = "0.0.0.0:$P2P_PORT"
public_address = "$(curl -s ifconfig.me):$P2P_PORT"

[network]
bootstrap_nodes = ["$BOOTSTRAP_IP:$BOOTSTRAP_PORT"]
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

# Create wallet
echo -e "${YELLOW}💰 Creating validator wallet...${NC}"
WALLET_ID=$(date +%s | sha256sum | head -c 16)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > ~/.zhtp/validator/wallet.json << EOF
{
    "node_id": "$NODE_NAME",
    "created": "$TIMESTAMP",
    "balance": 10000,
    "staked": 1000,
    "rewards_earned": 0,
    "addresses": {
        "primary": "zhtp_$WALLET_ID",
        "staking": "zhtp_stake_$WALLET_ID"
    }
}
EOF

# Create startup script
echo -e "${YELLOW}🚀 Creating startup script...${NC}"
cat > ~/.zhtp/validator/start-node.sh << 'EOF'
#!/bin/bash
cd ~/.zhtp/validator
echo "🚀 Starting ZHTP Validator Node"
echo "================================"
echo "Node Port: 7000"
echo "P2P Port: 8000"
echo "Bootstrap: 172.56.201.218:8000"
echo ""

export ZHTP_NODE_NAME="validator-node-1"
export ZHTP_CONFIG_PATH="$HOME/.zhtp/validator/config.toml"
export RUST_LOG=info

# Get the ZHTP directory (where this script was run from)
ZHTP_DIR=$(find ~ -name "ZHTP" -type d | head -1)
if [ -z "$ZHTP_DIR" ]; then
    echo "❌ ZHTP directory not found!"
    exit 1
fi

echo "📍 Using ZHTP from: $ZHTP_DIR"
exec "$ZHTP_DIR/target/release/network-service" --config "$HOME/.zhtp/validator/config.toml"
EOF

chmod +x ~/.zhtp/validator/start-node.sh

# Create systemd service (optional)
echo -e "${YELLOW}🔧 Creating systemd service...${NC}"
ZHTP_DIR=$(pwd)
cat > ~/.zhtp/validator/zhtp-validator.service << EOF
[Unit]
Description=ZHTP Validator Node
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/.zhtp/validator
ExecStart=$HOME/.zhtp/validator/start-node.sh
Restart=always
RestartSec=10
Environment=RUST_LOG=info
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Set up firewall rules (if ufw is available)
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}🔥 Setting up firewall rules...${NC}"
    sudo ufw allow $NODE_PORT comment "ZHTP Node API"
    sudo ufw allow $P2P_PORT comment "ZHTP Node P2P"
else
    echo -e "${YELLOW}⚠️  Please manually open ports $NODE_PORT and $P2P_PORT in your firewall${NC}"
fi

echo ""
echo -e "${GREEN}✅ ZHTP Validator Node Setup Complete!${NC}"
echo "======================================"
echo ""
echo -e "${BLUE}📍 Node Location:${NC} ~/.zhtp/validator"
echo -e "${BLUE}🔑 Node Config:${NC} ~/.zhtp/validator/config.toml"
echo -e "${BLUE}💰 Wallet:${NC} ~/.zhtp/validator/wallet.json"
echo ""
echo -e "${GREEN}🚀 To start your node:${NC}"
echo "   cd ~/.zhtp/validator"
echo "   ./start-node.sh"
echo ""
echo -e "${GREEN}📊 To install as system service:${NC}"
echo "   sudo cp ~/.zhtp/validator/zhtp-validator.service /etc/systemd/system/"
echo "   sudo systemctl enable zhtp-validator"
echo "   sudo systemctl start zhtp-validator"
echo ""
echo -e "${GREEN}🌐 Monitor your node:${NC}"
echo "   Browser: http://localhost:$NODE_PORT"
echo "   API: http://localhost:$NODE_PORT/api/"
echo "   Status: curl http://localhost:$NODE_PORT/api/status"
echo ""
echo -e "${GREEN}💰 Expected Earnings:${NC} 30-100 ZHTP tokens per day"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
echo "   - Save your wallet.json file securely"
echo "   - Node will connect to bootstrap: $BOOTSTRAP_IP:$BOOTSTRAP_PORT"
echo "   - Token earning starts immediately upon connection"
echo ""

# Test connection to bootstrap
echo -e "${YELLOW}🔍 Testing connection to bootstrap node...${NC}"
if timeout 5 bash -c "echo >/dev/tcp/$BOOTSTRAP_IP/$BOOTSTRAP_PORT" 2>/dev/null; then
    echo -e "${GREEN}✅ Bootstrap node is reachable${NC}"
else
    echo -e "${RED}❌ Cannot reach bootstrap node at $BOOTSTRAP_IP:$BOOTSTRAP_PORT${NC}"
    echo -e "${YELLOW}   This might be normal if the bootstrap node isn't running yet${NC}"
fi

echo ""
echo -e "${BLUE}🎯 Ready to start? Run:${NC}"
echo "   cd ~/.zhtp/validator && ./start-node.sh"
echo ""
