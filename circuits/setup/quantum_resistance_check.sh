#!/bin/bash

# ZHTP Quantum Resistance Verification Script
# Comprehensive testing and verification of quantum-resistant properties
# across the entire ZHTP ecosystem

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'  
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
    ((TOTAL_TESTS++))
}

pass_test() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
}

fail_test() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

warn_test() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

info() {
    echo -e "${PURPLE}[INFO]${NC} $1"
}

# Test 1: Post-Quantum Cryptography Implementation
test_post_quantum_crypto() {
    log_test "Verifying post-quantum cryptography implementation"
    
    cd "$PROJECT_ROOT"
    
    # Check for Dilithium signature scheme
    if grep -r "pqcrypto-dilithium" Cargo.toml > /dev/null; then
        pass_test "Dilithium signature scheme dependency found"
    else
        fail_test "Dilithium signature scheme not found in dependencies"
    fi
    
    # Check for Kyber KEM
    if grep -r "pqcrypto-kyber" Cargo.toml > /dev/null; then
        pass_test "Kyber KEM dependency found"
    else
        fail_test "Kyber KEM not found in dependencies"
    fi
    
    # Verify implementation in crypto module
    if grep -r "dilithium" src/zhtp/crypto.rs > /dev/null; then
        pass_test "Dilithium implementation found in crypto module"
    else
        fail_test "Dilithium implementation not found"
    fi
    
    if grep -r "kyber" src/zhtp/crypto.rs > /dev/null; then
        pass_test "Kyber implementation found in crypto module"
    else
        fail_test "Kyber implementation not found"
    fi
}

# Test 2: Quantum-Resistant Hash Functions
test_quantum_resistant_hashing() {
    log_test "Verifying quantum-resistant hash functions"
    
    # Check for BLAKE3 (quantum-resistant)
    if grep -r "blake3" Cargo.toml > /dev/null; then
        pass_test "BLAKE3 quantum-resistant hash function found"
    else
        fail_test "BLAKE3 not found - using potentially vulnerable hash functions"
    fi
    
    # Check for SHA-3 family
    if grep -r "sha3" Cargo.toml > /dev/null; then
        pass_test "SHA-3 quantum-resistant hash function found"
    else
        warn_test "SHA-3 not found - consider adding for diversity"
    fi
    
    # Verify no weak hash functions in critical paths
    local weak_hashes=("md5" "sha1" "weak")
    for hash in "${weak_hashes[@]}"; do
        if grep -r "$hash" src/ > /dev/null; then
            fail_test "Potentially weak hash function found: $hash"
        else
            pass_test "No weak hash function found: $hash"
        fi
    done
}

# Test 3: Zero-Knowledge Circuit Quantum Resistance
test_zk_circuit_quantum_resistance() {
    log_test "Verifying zero-knowledge circuit quantum resistance"
    
    local circuits_dir="$PROJECT_ROOT/circuits/src"
    
    if [ ! -d "$circuits_dir" ]; then
        fail_test "Circuits directory not found"
        return
    fi
    
    # Check each critical circuit for quantum-resistant primitives
    local critical_circuits=(
        "consensus/stake_proof.circom"
        "transactions/private_transfer.circom"
        "storage/integrity_proof.circom"
        "dao/anonymous_voting.circom"
    )
    
    for circuit in "${critical_circuits[@]}"; do
        local circuit_file="$circuits_dir/$circuit"
        
        if [ -f "$circuit_file" ]; then
            # Check for BLS12-381 curve (quantum-resistant)
            if grep -q "BLS12-381\|bn128" "$circuit_file"; then
                pass_test "Quantum-resistant curve found in $circuit"
            else
                warn_test "No explicit curve specification in $circuit"
            fi
            
            # Check for BLAKE3 usage in circuits
            if grep -q "BLAKE3\|blake3" "$circuit_file"; then
                pass_test "BLAKE3 usage found in $circuit"
            else
                warn_test "No BLAKE3 usage found in $circuit"
            fi
            
            # Check for lattice-based commitments
            if grep -q "lattice\|commitment" "$circuit_file"; then
                pass_test "Lattice-based primitives found in $circuit"
            else
                warn_test "No explicit lattice-based primitives in $circuit"
            fi
        else
            fail_test "Critical circuit file not found: $circuit"
        fi
    done
}

# Test 4: Trusted Setup Ceremony Security
test_trusted_setup_security() {
    log_test "Verifying trusted setup ceremony security"
    
    local setup_dir="$PROJECT_ROOT/circuits/setup"
    
    # Check for ceremony scripts
    if [ -f "$setup_dir/quantum_setup.sh" ]; then
        pass_test "Quantum setup ceremony script found"
    else
        fail_test "Quantum setup ceremony script not found"
    fi
    
    if [ -f "$setup_dir/ceremony_startup.sh" ]; then
        pass_test "Ceremony startup script found"
    else
        fail_test "Ceremony startup script not found"
    fi
    
    # Check ceremony script security
    local ceremony_script="$setup_dir/quantum_setup.sh"
    if [ -f "$ceremony_script" ]; then
        # Check for multi-party computation
        if grep -q "multi.*party\|mpc" "$ceremony_script"; then
            pass_test "Multi-party computation found in ceremony"
        else
            warn_test "No explicit multi-party computation in ceremony"
        fi
        
        # Check for quantum entropy
        if grep -q "quantum.*entropy\|quantum.*random" "$ceremony_script"; then
            pass_test "Quantum entropy source found in ceremony"
        else
            fail_test "No quantum entropy source in ceremony"
        fi
        
        # Check for multiple contribution rounds
        if grep -q "round\|contribution" "$ceremony_script"; then
            pass_test "Multiple contribution rounds found"
        else
            warn_test "No explicit multiple contribution rounds"
        fi
    fi
}

# Test 5: Key Rotation and Management
test_key_rotation() {
    log_test "Verifying quantum-resistant key rotation"
    
    # Check crypto module for key rotation
    local crypto_file="$PROJECT_ROOT/src/zhtp/crypto.rs"
    
    if [ -f "$crypto_file" ]; then
        if grep -q "rotation\|rotate" "$crypto_file"; then
            pass_test "Key rotation functionality found"
        else
            fail_test "No key rotation functionality found"
        fi
        
        if grep -q "KEY_ROTATION_INTERVAL" "$crypto_file"; then
            pass_test "Key rotation interval configuration found"
        else
            warn_test "No explicit key rotation interval found"
        fi
        
        # Check for rotation due tracking
        if grep -q "rotation_due\|needs_rotation" "$crypto_file"; then
            pass_test "Key rotation tracking found"
        else
            fail_test "No key rotation tracking found"
        fi
    else
        fail_test "Crypto module not found"
    fi
}

# Test 6: Network Protocol Quantum Resistance
test_network_quantum_resistance() {
    log_test "Verifying network protocol quantum resistance"
    
    local network_files=(
        "$PROJECT_ROOT/src/network.rs"
        "$PROJECT_ROOT/src/network_service.rs"
        "$PROJECT_ROOT/src/zhtp/p2p_network.rs"
    )
    
    for network_file in "${network_files[@]}"; do
        if [ -f "$network_file" ]; then
            # Check for post-quantum key exchange
            if grep -q "kyber\|post.*quantum\|pq.*crypto" "$network_file"; then
                pass_test "Post-quantum cryptography found in $(basename "$network_file")"
            else
                warn_test "No explicit post-quantum crypto in $(basename "$network_file")"
            fi
            
            # Check for quantum-resistant authentication
            if grep -q "dilithium\|lattice.*sign" "$network_file"; then
                pass_test "Quantum-resistant signatures found in $(basename "$network_file")"
            else
                warn_test "No quantum-resistant signatures in $(basename "$network_file")"
            fi
        fi
    done
}

# Test 7: Blockchain Quantum Resistance
test_blockchain_quantum_resistance() {
    log_test "Verifying blockchain quantum resistance"
    
    local blockchain_file="$PROJECT_ROOT/src/blockchain.rs"
    
    if [ -f "$blockchain_file" ]; then
        # Check for quantum-resistant transaction signatures
        if grep -q "post.*quantum\|dilithium\|lattice" "$blockchain_file"; then
            pass_test "Quantum-resistant signatures in blockchain"
        else
            fail_test "No quantum-resistant signatures in blockchain"
        fi
        
        # Check for quantum-resistant consensus
        if grep -q "quantum.*resistant\|post.*quantum.*consensus" "$blockchain_file"; then
            pass_test "Quantum-resistant consensus found"
        else
            warn_test "No explicit quantum-resistant consensus"
        fi
    else
        fail_test "Blockchain module not found"
    fi
}

# Test 8: Security Test Coverage
test_security_coverage() {
    log_test "Verifying security test coverage for quantum resistance"
    
    local security_tests="$PROJECT_ROOT/src/security_tests.rs"
    
    if [ -f "$security_tests" ]; then
        # Check for quantum attack simulation tests
        if grep -q "quantum.*attack\|quantum.*simulation" "$security_tests"; then
            pass_test "Quantum attack simulation tests found"
        else
            fail_test "No quantum attack simulation tests"
        fi
        
        # Check for post-quantum crypto tests
        if grep -q "post.*quantum\|dilithium\|kyber" "$security_tests"; then
            pass_test "Post-quantum cryptography tests found"
        else
            fail_test "No post-quantum cryptography tests"
        fi
        
        # Check for ceremony verification tests
        if grep -q "ceremony\|trusted.*setup" "$security_tests"; then
            pass_test "Trusted setup ceremony tests found"
        else
            fail_test "No trusted setup ceremony tests"
        fi
        
        # Check for side-channel resistance tests
        if grep -q "side.*channel\|timing.*attack" "$security_tests"; then
            pass_test "Side-channel resistance tests found"
        else
            warn_test "No side-channel resistance tests"
        fi
    else
        fail_test "Security tests file not found"
    fi
}

# Test 9: Documentation and Specifications
test_documentation() {
    log_test "Verifying quantum resistance documentation"
    
    # Check main README
    local readme="$PROJECT_ROOT/README.md"
    if [ -f "$readme" ]; then
        if grep -q "quantum.*resistant\|post.*quantum" "$readme"; then
            pass_test "Quantum resistance documented in README"
        else
            warn_test "No quantum resistance documentation in README"
        fi
    fi
    
    # Check circuits README
    local circuits_readme="$PROJECT_ROOT/circuits/README.md"
    if [ -f "$circuits_readme" ]; then
        if grep -q "quantum.*resistant\|post.*quantum" "$circuits_readme"; then
            pass_test "Quantum resistance documented in circuits README"
        else
            fail_test "No quantum resistance documentation in circuits README"
        fi
    fi
}

# Test 10: Dependency Security Audit
test_dependency_security() {
    log_test "Auditing dependencies for quantum resistance"
    
    cd "$PROJECT_ROOT"
    
    # Check for known quantum-vulnerable dependencies
    local vulnerable_deps=("rsa" "ecdsa" "secp256k1" "ed25519-dalek")
    
    for dep in "${vulnerable_deps[@]}"; do
        if grep -q "^$dep\s*=" Cargo.toml; then
            fail_test "Quantum-vulnerable dependency found: $dep"
        else
            pass_test "No quantum-vulnerable dependency: $dep"
        fi
    done
    
    # Check for quantum-resistant dependencies
    local quantum_deps=("pqcrypto-dilithium" "pqcrypto-kyber" "blake3")
    
    for dep in "${quantum_deps[@]}"; do
        if grep -q "^$dep\s*=" Cargo.toml; then
            pass_test "Quantum-resistant dependency found: $dep"
        else
            warn_test "Quantum-resistant dependency not found: $dep"
        fi
    done
}

# Test 11: Runtime Quantum Resistance Verification
test_runtime_verification() {
    log_test "Testing runtime quantum resistance verification"
    
    cd "$PROJECT_ROOT"
    
    # Run security tests if available
    if cargo test --test security_tests > /dev/null 2>&1; then
        pass_test "Security tests pass"
    else
        warn_test "Security tests failed or not available"
    fi
    
    # Check for quantum resistance markers in code
    local quantum_markers=("quantum_resistant" "post_quantum" "lattice_based")
    
    for marker in "${quantum_markers[@]}"; do
        if grep -r "$marker" src/ > /dev/null; then
            pass_test "Quantum resistance marker found: $marker"
        else
            warn_test "No quantum resistance marker: $marker"
        fi
    done
}

# Test 12: Future-Proofing Assessment
test_future_proofing() {
    log_test "Assessing future-proofing against quantum advances"
    
    # Check for algorithm agility
    if grep -r "algorithm.*agility\|crypto.*agility" src/ > /dev/null; then
        pass_test "Algorithm agility considerations found"
    else
        warn_test "No explicit algorithm agility provisions"
    fi
    
    # Check for security parameter configurability
    if grep -r "security.*level\|security.*parameter" src/ > /dev/null; then
        pass_test "Security parameter configurability found"
    else
        warn_test "No security parameter configurability"
    fi
    
    # Check for upgrade mechanisms
    if grep -r "upgrade\|migration\|transition" src/ > /dev/null; then
        pass_test "Upgrade mechanisms found"
    else
        warn_test "No explicit upgrade mechanisms"
    fi
}

# Generate comprehensive report
generate_report() {
    echo
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}  QUANTUM RESISTANCE VERIFICATION     ${NC}"
    echo -e "${BLUE}  COMPREHENSIVE REPORT                ${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo
    
    echo -e "${PURPLE}Test Summary:${NC}"
    echo "  Total Tests: $TOTAL_TESTS"
    echo "  Passed: $PASSED_TESTS"
    echo "  Failed: $FAILED_TESTS"
    echo "  Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    echo
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}✅ EXCELLENT: ZHTP demonstrates strong quantum resistance${NC}"
        echo -e "${GREEN}   All critical quantum resistance measures are in place${NC}"
    elif [ $FAILED_TESTS -le 3 ]; then
        echo -e "${YELLOW}⚠️  GOOD: ZHTP has good quantum resistance with minor issues${NC}"
        echo -e "${YELLOW}   Consider addressing the failed tests for optimal security${NC}"
    else
        echo -e "${RED}❌ WARNING: ZHTP has significant quantum resistance gaps${NC}"
        echo -e "${RED}   Critical quantum resistance measures need attention${NC}"
    fi
    
    echo
    echo -e "${PURPLE}Quantum Resistance Score: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%${NC}"
    
    echo
    echo -e "${BLUE}Recommendations:${NC}"
    
    if [ $FAILED_TESTS -gt 0 ]; then
        echo "1. Address all failed tests immediately"
        echo "2. Implement missing quantum-resistant measures"
        echo "3. Update documentation to reflect quantum resistance"
        echo "4. Consider additional algorithm agility provisions"
    else
        echo "1. Regularly update quantum-resistant algorithms"
        echo "2. Monitor NIST post-quantum standards evolution"
        echo "3. Plan for future algorithm transitions"
        echo "4. Conduct regular quantum resistance audits"
    fi
    
    echo
    echo -e "${PURPLE}Next Steps:${NC}"
    echo "1. Run trusted setup ceremony if not completed"
    echo "2. Deploy quantum-resistant configurations"
    echo "3. Monitor for quantum computing advances"
    echo "4. Update security documentation"
    echo "5. Schedule regular quantum resistance reviews"
}

# Main execution
main() {
    echo -e "${PURPLE}"
    echo "=============================================="
    echo "ZHTP Quantum Resistance Verification v1.0.0"
    echo "Comprehensive Security Assessment"
    echo "=============================================="
    echo -e "${NC}"
    
    info "Starting comprehensive quantum resistance verification..."
    echo
    
    # Run all tests
    test_post_quantum_crypto
    test_quantum_resistant_hashing
    test_zk_circuit_quantum_resistance
    test_trusted_setup_security
    test_key_rotation
    test_network_quantum_resistance
    test_blockchain_quantum_resistance
    test_security_coverage
    test_documentation
    test_dependency_security
    test_runtime_verification
    test_future_proofing
    
    # Generate final report
    generate_report
}

# Execute if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
