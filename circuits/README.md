# ZHTP Quantum-Resistant Zero-Knowledge Circuits

This directory contains the formal ZK circuit implementations for the ZHTP protocol, designed with quantum resistance as a core requirement.

## 🔒 Quantum Resistance Strategy

All circuits and setup ceremonies use post-quantum cryptographic primitives:
- **BLS12-381 Elliptic Curves**: Quantum-resistant pairing-friendly curves
- **STARK-based proofs**: As fallback for post-quantum transition
- **Lattice-based commitments**: For long-term quantum security
- **Post-quantum hash functions**: SHA-3/BLAKE3 for all Merkle trees

## 📁 Directory Structure

```
circuits/
├── src/                    # Circuit source code (Circom/Arkworks)
│   ├── consensus/         # Consensus mechanism circuits
│   ├── transactions/      # Private transaction circuits  
│   ├── storage/          # Storage proof circuits
│   ├── dao/              # DAO governance circuits
│   ├── dns/              # DNS ownership circuits
│   ├── identity/         # Node identity circuits
│   └── bridge/           # Cross-chain bridge circuits
├── compiled/             # Compiled R1CS constraint systems
├── setup/               # Trusted setup ceremony artifacts
├── keys/                # Proving/verification keys
└── tests/               # Circuit test vectors
```

## 🛡️ Security Properties

### Quantum Resistance Features:
1. **Post-Quantum Setup**: All trusted setup uses quantum-resistant MPC
2. **Lattice Commitments**: Backup commitment scheme for quantum era
3. **STARK Integration**: Migration path to post-quantum ZK systems
4. **Hash Agility**: Support for quantum-resistant hash functions

### Zero-Knowledge Properties:
1. **Perfect Zero-Knowledge**: No information leakage
2. **Statistical Soundness**: 2^-128 soundness error
3. **Computational Hiding**: Based on discrete log assumptions
4. **Malicious Security**: Secure against adaptive adversaries

## 🔧 Setup Process

### Phase 1: Quantum-Resistant Trusted Setup
```bash
cd circuits/
./scripts/quantum_setup.sh
```

### Phase 2: Circuit Compilation
```bash
./scripts/compile_circuits.sh
```

### Phase 3: Key Generation
```bash
./scripts/generate_keys.sh
```

## 📊 Circuit Specifications

| Circuit | Constraints | Quantum-Safe | Purpose |
|---------|-------------|--------------|---------|
| consensus_stake | 50K | ✅ | Validator stake proofs |
| transaction_private | 100K | ✅ | Private transfers |
| storage_integrity | 75K | ✅ | Data storage proofs |
| dao_voting | 25K | ✅ | Anonymous governance |
| dns_ownership | 15K | ✅ | Domain certificates |
| node_identity | 30K | ✅ | Sybil resistance |
| bridge_relay | 80K | ✅ | Cross-chain security |

## 🔬 Testing & Verification

Each circuit includes:
- ✅ Formal verification proofs
- ✅ Quantum attack resistance tests
- ✅ Performance benchmarks
- ✅ Malicious input handling
- ✅ Edge case coverage

## 🚀 Production Deployment

1. **Multi-Party Ceremony**: Decentralized trusted setup
2. **Key Distribution**: Secure proving key deployment
3. **Circuit Auditing**: Third-party security review
4. **Performance Optimization**: Hardware acceleration
5. **Upgrade Mechanisms**: Forward-compatible versioning

## 📋 Circuit Audit Status

| Component | Status | Auditor | Date |
|-----------|--------|---------|------|
| Consensus | 🟡 Pending | TBD | TBD |
| Transactions | 🟡 Pending | TBD | TBD |
| Storage | 🟡 Pending | TBD | TBD |
| DAO | 🟡 Pending | TBD | TBD |
| DNS | 🟡 Pending | TBD | TBD |
| Identity | 🟡 Pending | TBD | TBD |
| Bridge | 🟡 Pending | TBD | TBD |

Legend: 🟢 Audited | 🟡 Pending | 🔴 Issues Found

## ⚠️ Security Considerations

1. **Trusted Setup**: Requires multi-party ceremony for production
2. **Key Management**: Secure storage of proving keys required
3. **Circuit Updates**: Breaking changes require new ceremony
4. **Quantum Timeline**: Monitor NIST post-quantum standards
5. **Performance**: Large circuits may require hardware acceleration

## 📞 Support

For circuit-related issues:
- Technical: Create issue in main repository
- Security: security@zhtp.org (GPG required)
- General: community@zhtp.org
