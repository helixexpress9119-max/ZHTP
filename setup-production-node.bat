@echo off
echo 🚀 ZHTP Production Node Setup Script (Windows)
echo ===============================================
echo.

:: Get node configuration
set /p NODE_NAME=Enter node name (e.g., node1, node2): 
set /p NODE_PORT=Enter node port (e.g., 7000, 7001): 
set /p P2P_PORT=Enter P2P port (e.g., 8000, 8001): 
set /p BUDDY_IP=Enter your buddy's IP address (for bootstrap): 
set /p BUDDY_P2P_PORT=Enter your buddy's P2P port: 

echo.
echo 🔧 Installing Dependencies
echo =========================

:: Check if Rust is installed
where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Installing Rust...
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh
    call %USERPROFILE%\.cargo\env.bat
)

echo.
echo 🔨 Building ZHTP Node
echo ====================

:: Build the project
cargo build --release

echo.
echo 🔐 Generating Node Identity
echo ==========================

:: Create node directory
if not exist "%USERPROFILE%\.zhtp\%NODE_NAME%" mkdir "%USERPROFILE%\.zhtp\%NODE_NAME%"
cd /d "%USERPROFILE%\.zhtp\%NODE_NAME%"

:: Generate node configuration
(
echo [node]
echo name = "%NODE_NAME%"
echo bind_address = "0.0.0.0:%NODE_PORT%"
echo p2p_address = "0.0.0.0:%P2P_PORT%"
echo public_address = "YOUR_PUBLIC_IP:%P2P_PORT%"
echo.
echo [network]
echo bootstrap_nodes = ["%BUDDY_IP%:%BUDDY_P2P_PORT%"]
echo max_peers = 50
echo discovery_interval = 30
echo.
echo [consensus]
echo validator = true
echo stake_amount = 1000
echo.
echo [economics]
echo enable_mining = true
echo reward_address = "auto"
echo.
echo [storage]
echo data_dir = "%USERPROFILE%\.zhtp\%NODE_NAME%\data"
echo max_storage = "10GB"
echo.
echo [security]
echo enable_monitoring = true
echo log_level = "info"
) > config.toml

echo.
echo 💰 Setting Up Token Economics
echo ============================

:: Create wallet for this node
for /f %%i in ('powershell -command "[System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')"') do set TIMESTAMP=%%i
for /f %%i in ('powershell -command "'{0:X}' -f (Get-Random -Minimum 0 -Maximum [int64]::MaxValue)"') do set WALLET_ID=%%i

(
echo {
echo     "node_id": "%NODE_NAME%",
echo     "created": "%TIMESTAMP%",
echo     "balance": 10000,
echo     "staked": 1000,
echo     "rewards_earned": 0,
echo     "addresses": {
echo         "primary": "zhtp_%WALLET_ID%",
echo         "staking": "zhtp_stake_%WALLET_ID%"
echo     }
echo }
) > wallet.json

echo.
echo 🌐 Creating Startup Script
echo =========================

:: Create startup script
(
echo @echo off
echo cd /d "%USERPROFILE%\.zhtp\%NODE_NAME%"
echo echo 🚀 Starting ZHTP Node: %NODE_NAME%
echo echo ================================
echo echo Node Port: %NODE_PORT%
echo echo P2P Port: %P2P_PORT%
echo echo Bootstrap: %BUDDY_IP%:%BUDDY_P2P_PORT%
echo echo.
echo.
echo set ZHTP_NODE_NAME=%NODE_NAME%
echo set ZHTP_CONFIG_PATH=%USERPROFILE%\.zhtp\%NODE_NAME%\config.toml
echo set RUST_LOG=info
echo.
echo "%~dp0..\..\target\release\network-service.exe" --config "%USERPROFILE%\.zhtp\%NODE_NAME%\config.toml"
echo pause
) > start-node.bat

echo.
echo ✅ ZHTP Production Node Setup Complete!
echo ======================================
echo.
echo 📍 Node Location: %USERPROFILE%\.zhtp\%NODE_NAME%
echo 🔑 Node Config: %USERPROFILE%\.zhtp\%NODE_NAME%\config.toml
echo 💰 Wallet: %USERPROFILE%\.zhtp\%NODE_NAME%\wallet.json
echo.
echo 🚀 To start your node:
echo    cd %USERPROFILE%\.zhtp\%NODE_NAME%
echo    start-node.bat
echo.
echo 📊 Monitor your node:
echo    Browser: http://localhost:%NODE_PORT%
echo    API: http://localhost:%NODE_PORT%/api/
echo.
echo 💡 Share with your buddy:
echo    Your P2P Port: %P2P_PORT%
echo    Get your public IP from: https://whatismyipaddress.com/
echo.
echo ⚠️  IMPORTANT:
echo    - Make sure ports %NODE_PORT% and %P2P_PORT% are open in Windows Firewall
echo    - Save your wallet.json file securely
echo    - Node will start earning ZHTP tokens immediately
echo.
pause
