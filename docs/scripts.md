# ZHTP Scripts Overview

This folder contains various scripts to help you run and deploy ZHTP nodes across different platforms.

## Main Launch Scripts

### Windows
- **`run-zhtp.bat`** - Main launcher for ZHTP service (Windows)
- **`start-bootstrap-node.bat`** - Start a bootstrap node (Windows)  
- **`setup-production-node.bat`** - Interactive production node setup (Windows)

### Linux/macOS
- **`run-zhtp.sh`** - Main launcher for ZHTP service (Linux/macOS)
- **`start-bootstrap-node.sh`** - Start a bootstrap node (Linux/macOS)
- **`setup-production-node.sh`** - Interactive production node setup (Linux/macOS)
- **`setup-linux-node.sh`** - Complete Linux environment setup

## Quick Start

### Windows
```cmd
# Simple start
.\run-zhtp.bat

# Bootstrap node
.\start-bootstrap-node.bat

# Production setup
.\setup-production-node.bat
```

### Linux/macOS
```bash
# Make scripts executable
chmod +x *.sh

# Simple start  
./run-zhtp.sh

# Bootstrap node
./start-bootstrap-node.sh

# Production setup
./setup-production-node.sh

# Full Linux setup
./setup-linux-node.sh
```

## Script Details

### Main Service (`run-zhtp.*`)
- Builds and starts the ZHTP network service
- Provides browser interface at http://localhost:3000
- Includes API endpoints for external integration

### Bootstrap Node (`start-bootstrap-node.*`)
- Starts a bootstrap node for other nodes to connect to
- Essential for creating a new ZHTP network
- Uses default ports 3000 (HTTP) and 3001 (P2P)

### Production Setup (`setup-production-node.*`)
- Interactive setup for production deployments
- Creates node configuration files
- Sets up wallet and rewards system
- Configures networking and security

### Linux Environment Setup (`setup-linux-node.sh`)
- Complete environment setup for Linux systems
- Installs Rust and system dependencies
- Creates workspace structure and management scripts
- Sets up firewall rules and systemd services

## Network Configuration

All scripts support standard ZHTP configuration:
- **HTTP Port**: 3000 (configurable)
- **P2P Port**: 3001 (configurable)  
- **Data Directory**: `~/.zhtp/` (Linux) or `%USERPROFILE%\.zhtp\` (Windows)
- **Browser Interface**: Available at `http://localhost:3000`
- **API Endpoints**: Available at `http://localhost:3000/api/`

## Troubleshooting

1. **Build Failures**: Ensure Rust is installed and up to date
2. **Port Conflicts**: Change ports in configuration or use different values
3. **Permission Issues**: Run with appropriate permissions or as administrator
4. **Firewall Blocks**: Open ports 3000 and 3001 in your firewall

For more details, see the [Getting Started Guide](docs/getting-started.md).
