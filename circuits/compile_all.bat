@echo off
REM ZHTP Quantum-Resistant Circuit Compilation Script
REM Compiles all Circom circuits to the compiled directory

echo Starting ZHTP Quantum-Resistant Circuit Compilation...
echo.

set SRC_DIR=circuits\src
set COMPILED_DIR=circuits\compiled
set KEYS_DIR=circuits\keys

REM Create subdirectories in compiled directory
if not exist "%COMPILED_DIR%\consensus" mkdir "%COMPILED_DIR%\consensus"
if not exist "%COMPILED_DIR%\transactions" mkdir "%COMPILED_DIR%\transactions"
if not exist "%COMPILED_DIR%\storage" mkdir "%COMPILED_DIR%\storage"
if not exist "%COMPILED_DIR%\dao" mkdir "%COMPILED_DIR%\dao"
if not exist "%COMPILED_DIR%\dns" mkdir "%COMPILED_DIR%\dns"

echo Compiling consensus circuits...
circom "%SRC_DIR%\consensus\stake_proof.circom" --r1cs --wasm --sym -o "%COMPILED_DIR%\consensus"
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile stake_proof.circom
    exit /b 1
)

echo Compiling transaction circuits...
circom "%SRC_DIR%\transactions\private_transfer.circom" --r1cs --wasm --sym -o "%COMPILED_DIR%\transactions"
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile private_transfer.circom
    exit /b 1
)

echo Compiling storage circuits...
circom "%SRC_DIR%\storage\integrity_proof.circom" --r1cs --wasm --sym -o "%COMPILED_DIR%\storage"
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile integrity_proof.circom
    exit /b 1
)

echo Compiling DAO circuits...
circom "%SRC_DIR%\dao\anonymous_voting.circom" --r1cs --wasm --sym -o "%COMPILED_DIR%\dao"
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile anonymous_voting.circom
    exit /b 1
)

echo Compiling DNS circuits...
circom "%SRC_DIR%\dns\ownership_proof.circom" --r1cs --wasm --sym -o "%COMPILED_DIR%\dns"
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile ownership_proof.circom
    exit /b 1
)

echo.
echo ✓ All circuits compiled successfully!
echo.
echo Generated artifacts:
echo - .r1cs files (constraint systems)
echo - .wasm files (witness generators)
echo - .sym files (symbol tables)
echo.
echo Next steps:
echo 1. Run trusted setup ceremony: circuits\setup\quantum_setup.sh
echo 2. Generate proving/verification keys
echo 3. Run quantum resistance tests
echo.
pause
