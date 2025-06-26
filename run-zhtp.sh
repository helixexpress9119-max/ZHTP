#!/bin/bash
# ZHTP Launch Script - Linux/macOS
# Builds and runs the ZHTP network service

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo
echo "███████╗██╗  ██╗████████╗██████╗ "
echo "╚══███╔╝██║  ██║╚══██╔══╝██╔══██╗"
echo "   ███╔╝ ███████║   ██║   ██████╔╝"
echo "  ███╔╝  ██╔══██║   ██║   ██╔═══╝ "
echo " ███████╗██║  ██║   ██║   ██║     "
echo " ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     "
echo
echo "Zero-Knowledge HTTP Protocol"
echo

# Check Rust installation
echo -e "${YELLOW}🔧 Checking Rust installation...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
else
    echo -e "${GREEN}✅ Rust is already installed${NC}"
fi

# Build the project
echo -e "${YELLOW}🔨 Building ZHTP...${NC}"
cargo build --release --bin zhtp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build successful!${NC}"
else
    echo -e "${RED}❌ Build failed! Please check your Rust installation.${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}🚀 Starting ZHTP Network Service...${NC}"
echo -e "${BLUE}  Browser:  http://localhost:8000${NC}"
echo -e "${BLUE}  API:      http://localhost:8000/api/${NC}"
echo ""

# Check if port is available
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo -e "${YELLOW}⚠️  Port 8000 is already in use. Stopping existing service...${NC}"
    pkill -f "target/release/zhtp" || true
    sleep 2
fi

# Start the network service in background
echo -e "${GREEN}🔄 Starting ZHTP service...${NC}"
cargo run --release --bin zhtp &
ZHTP_PID=$!

# Wait for service to start
echo -e "${YELLOW}🔄 Waiting for ZHTP service to initialize...${NC}"
sleep 5

# Open browser automatically
echo -e "${GREEN}🌐 Opening browser window...${NC}"
if command -v xdg-open > /dev/null; then
    xdg-open http://localhost:8000
elif command -v open > /dev/null; then
    open http://localhost:8000
elif command -v start > /dev/null; then
    start http://localhost:8000
else
    echo -e "${YELLOW}⚠️  Could not open browser automatically. Please visit: http://localhost:8000${NC}"
fi

echo -e "${GREEN}✅ ZHTP Network running! Browser opened automatically.${NC}"
echo -e "${BLUE}📱 Access at: http://localhost:8000${NC}"
echo -e "${RED}🛑 Press Ctrl+C to stop the service.${NC}"

# Wait for the background process
wait $ZHTP_PID

echo ""
echo -e "${YELLOW}ZHTP service stopped.${NC}"
