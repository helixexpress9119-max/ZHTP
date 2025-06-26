@echo off
REM ZHTP Launch Script - Windows
REM Builds and runs the ZHTP network service

title ZHTP Network Service

echo.
echo ███████╗██╗  ██╗████████╗██████╗ 
echo ╚══███╔╝██║  ██║╚══██╔══╝██╔══██╗
echo   ███╔╝ ███████║   ██║   ██████╔╝
echo  ███╔╝  ██╔══██║   ██║   ██╔═══╝ 
echo ███████╗██║  ██║   ██║   ██║     
echo ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     
echo.
echo Zero-Knowledge HTTP Protocol
echo.

REM Build and run the main network service
echo 🔨 Building ZHTP...
cargo build --release --bin zhtp
if %errorlevel% neq 0 (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo ✅ Build successful!
echo.
echo 🚀 Starting ZHTP Network Service...
echo.
echo   Browser:  http://localhost:8000
echo   API:      http://localhost:8000/api/
echo.
echo Press Ctrl+C to stop the service.

REM Start ZHTP service in background and wait for it to start
start /B cargo run --release --bin zhtp

REM Wait a moment for service to start
echo 🔄 Waiting for ZHTP service to initialize...
timeout /t 5 /nobreak > nul

REM Open browser automatically
echo 🌐 Opening browser window...
start http://localhost:8000

REM Wait for the background process to continue
echo ✅ ZHTP Network running! Browser opened automatically.
echo 📱 Access at: http://localhost:8000
echo 🛑 Press Ctrl+C to stop the service.

REM Keep the window open and wait for the background process
cargo run --release --bin zhtp

echo.
echo Service stopped.
pause