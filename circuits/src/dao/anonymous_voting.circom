pragma circom 2.1.0;

template AnonymousVoting() {
    // Public inputs
    signal input proposal_id;
    signal input vote_commitment;
    signal input eligibility_root;
    signal input nullifier_hash;
    
    // Private inputs
    signal input vote_choice;
    signal input voter_secret;
    signal input voting_power;
    signal input vote_nonce;
    
    // Outputs
    signal output vote_proof;
    signal output power_proof;
    signal output anonymity_proof;
    
    // Verify vote choice is binary (0 or 1)
    component vote_binary = IsEqual();
    vote_binary.in[0] <== vote_choice * (vote_choice - 1);
    vote_binary.in[1] <== 0;
    vote_binary.out === 1;
    
    // Generate vote commitment
    component commit = Poseidon(3);
    commit.inputs[0] <== vote_choice;
    commit.inputs[1] <== voter_secret;
    commit.inputs[2] <== vote_nonce;
    
    component commit_check = IsEqual();
    commit_check.in[0] <== commit.out;
    commit_check.in[1] <== vote_commitment;
    commit_check.out === 1;
    
    // Generate nullifier to prevent double voting
    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== voter_secret;
    nullifier.inputs[1] <== proposal_id;
    
    component nullifier_check = IsEqual();
    nullifier_check.in[0] <== nullifier.out;
    nullifier_check.in[1] <== nullifier_hash;
    nullifier_check.out === 1;
    
    // Generate proofs
    component vote_proof_gen = Poseidon(4);
    vote_proof_gen.inputs[0] <== proposal_id;
    vote_proof_gen.inputs[1] <== vote_choice;
    vote_proof_gen.inputs[2] <== voting_power;
    vote_proof_gen.inputs[3] <== vote_nonce;
    vote_proof <== vote_proof_gen.out;
    
    component power_proof_gen = Poseidon(2);
    power_proof_gen.inputs[0] <== voting_power;
    power_proof_gen.inputs[1] <== voter_secret;
    power_proof <== power_proof_gen.out;
    
    component anonymity_proof_gen = Poseidon(3);
    anonymity_proof_gen.inputs[0] <== voter_secret;
    anonymity_proof_gen.inputs[1] <== vote_nonce;
    anonymity_proof_gen.inputs[2] <== eligibility_root;
    anonymity_proof <== anonymity_proof_gen.out;
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

component main = AnonymousVoting();
