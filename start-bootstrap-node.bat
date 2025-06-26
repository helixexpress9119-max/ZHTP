@echo off
echo 🚀 Starting ZHTP Bootstrap Node...
echo ========================================
echo.
echo Your bootstrap node will be available at:
echo - Local:     http://localhost:7000
echo - Network:   http://172.56.201.218:7000
echo - Browser:   http://localhost:7000/browser/welcome.html
echo.
echo Press Ctrl+C to stop the service
echo ========================================
echo.

cd /d "C:\Users\sethr\Desktop\ZHTP-main"
cargo run --bin network-service

pause
