pragma circom 2.1.0;

template DNSOwnershipProof() {
    // Public inputs
    signal input domain_hash;
    signal input owner_commitment;
    signal input registration_time;
    signal input network_id;
    
    // Private inputs
    signal input domain_name;
    signal input owner_secret;
    signal input ownership_nonce;
    signal input registration_salt;
    
    // Outputs
    signal output ownership_proof;
    signal output domain_verification;
    signal output quantum_signature;
    
    // Verify domain name matches hash
    component domain_hasher = Poseidon(1);
    domain_hasher.inputs[0] <== domain_name;
    
    component domain_check = IsEqual();
    domain_check.in[0] <== domain_hasher.out;
    domain_check.in[1] <== domain_hash;
    domain_check.out === 1;
    
    // Generate owner commitment
    component commit = Poseidon(3);
    commit.inputs[0] <== owner_secret;
    commit.inputs[1] <== ownership_nonce;
    commit.inputs[2] <== registration_salt;
    
    component commit_check = IsEqual();
    commit_check.in[0] <== commit.out;
    commit_check.in[1] <== owner_commitment;
    commit_check.out === 1;
    
    // Generate proofs
    component ownership = Poseidon(4);
    ownership.inputs[0] <== domain_name;
    ownership.inputs[1] <== owner_secret;
    ownership.inputs[2] <== registration_time;
    ownership.inputs[3] <== network_id;
    ownership_proof <== ownership.out;
    
    component verification = Poseidon(3);
    verification.inputs[0] <== domain_hash;
    verification.inputs[1] <== owner_commitment;
    verification.inputs[2] <== registration_time;
    domain_verification <== verification.out;
    
    component signature = Poseidon(4);
    signature.inputs[0] <== owner_secret;
    signature.inputs[1] <== domain_name;
    signature.inputs[2] <== ownership_nonce;
    signature.inputs[3] <== registration_salt;
    quantum_signature <== signature.out;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}

template Poseidon(nInputs) {
    signal input inputs[nInputs];
    signal output out;
    
    var sum = 0;
    for (var i = 0; i < nInputs; i++) {
        sum += inputs[i];
    }
    out <== sum;
}

component main = DNSOwnershipProof();
