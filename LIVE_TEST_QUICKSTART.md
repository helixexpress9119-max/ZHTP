# 🧪 ZHTP Live Test - Quick Network Verification

**Verify ZHTP Web4 network functionality across multiple machines in 5 minutes!**

## 🎯 Quick Live Test Setup

### Connect to your test machine and run:
```bash
# SSH to test machine
ssh user@your-test-machine-ip

# Quick live test setup (copy/paste this block):
curl -sSL https://raw.githubusercontent.com/SOVEREIGN-NETWORK/ZHTP/main/live-test-setup.sh | bash -s -- --test-mode --bootstrap=BOOTSTRAP_IP:7000
```

**The script will:**
- Install dependencies and Rust if needed
- Clone and build ZHTP for testing
- Configure test node to connect to network
- Start the test node with verification enabled
- Run cross-system validation checks

## 🌐 Test Network Access

Once setup completes, verify from your browser:

**🎯 Live Test Dashboard:**
```
http://your-test-machine-ip:7000/browser/welcome.html
```

## 📋 Complete Onboarding Pipeline

### Step 1: Create Your Wallet
1. Go to http://100.94.204.6:7000/browser/welcome.html
2. Click **"Create Wallet"**
3. **IMPORTANT**: Save your 12-word recovery phrase!
4. Complete the security checklist
5. Click **"Enter ZHTP Network"**

### Step 2: Get Verified as Citizen
1. The system will automatically:
   - Generate your ZK identity
   - Create your post-quantum wallet
   - Register you as a ZHTP citizen (1 governance token)
   - Connect to my bootstrap node (172.56.201.218)
   - Start earning ZHTP tokens immediately

### Step 3: Start Using Whisper Chat
1. After onboarding, you'll see the main ZHTP browser
2. Click **"Whisper.zhtp"** or go to:
   ```
   http://100.94.204.6:7000/browser/whisper.html
   ```
3. Start chatting! Messages are:
   - End-to-end encrypted
   - Zero-knowledge private
   - Censorship-resistant

## 🎮 Alternative: Manual Setup (if you prefer)

```bash
# 1. SSH to server
ssh nononode@100.94.204.6

# 2. Clone ZHTP
git clone https://github.com/SOVEREIGN-NETWORK/ZHTP.git
cd ZHTP

# 3. Build (takes 5-10 minutes)
cargo build --release

# 4. Run the node
./target/release/network-service
```

Then go to http://100.94.204.6:7000/browser/welcome.html

## 🔍 Verify Everything Works

### Check your node is running:
```bash
curl http://localhost:7000/api/status
```

### Check connection to my bootstrap:
```bash
curl http://localhost:7000/api/peers
```

### Expected response:
```json
{
  "status": "success",
  "peers": ["172.56.201.218:7000"],
  "network_id": "zhtp-mainnet"
}
```

## 💰 Token Earning Starts Immediately

Once connected, you earn ZHTP tokens for:
- **Routing**: Forward encrypted packets
- **Storage**: Store distributed content  
- **Consensus**: Validate transactions
- **Security**: Monitor network threats

**Expected earnings: 30-100 ZHTP tokens per day**

## 🎯 Quick Access URLs

| Service | URL |
|---------|-----|
| **Welcome/Setup** | http://100.94.204.6:7000/browser/welcome.html |
| **Whisper Chat** | http://100.94.204.6:7000/browser/whisper.html |
| **Main Browser** | http://100.94.204.6:7000/browser/index.html |
| **API Status** | http://100.94.204.6:7000/api/status |

## 🔧 Troubleshooting

### Node won't start?
```bash
# Check if ports are open
sudo ufw allow 7000 && sudo ufw allow 8000

# Restart the service
pkill -f network-service
./target/release/network-service
```

### Can't connect to bootstrap?
```bash
# Test connection to my node
ping 172.56.201.218
telnet 172.56.201.218 7000
```

### Browser shows errors?
```bash
# Check service is running
curl http://localhost:7000/api/status

# Check logs
tail -f ~/.zhtp/logs/node.log
```

## 🎊 You're Ready!

1. **Setup**: Run the one-liner or manual setup
2. **Onboard**: Go through welcome.html pipeline  
3. **Chat**: Start using Whisper for private messaging
4. **Earn**: Automatically earn ZHTP tokens

**Welcome to the decentralized internet!** 🌐

---

**Need help?** Your setup creates a connection to my bootstrap node at 172.56.201.218, so we'll be on the same network immediately!
