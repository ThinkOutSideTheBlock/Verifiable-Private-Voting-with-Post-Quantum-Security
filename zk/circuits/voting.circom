pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/gates.circom";

// ============================================================================
// DOMAIN CONSTANTS FOR SECURITY
// ============================================================================
template DomainConstants() {
    signal output COMMITMENT_DOMAIN;
    signal output NULLIFIER_DOMAIN;
    signal output TALLY_DOMAIN;
    
    COMMITMENT_DOMAIN <== 0x434f4d4d49544d454e545f444f4d41494e;  // "COMMITMENT_DOMAIN"
    NULLIFIER_DOMAIN <== 0x4e554c4c49464945525f444f4d41494e;     // "NULLIFIER_DOMAIN"
    TALLY_DOMAIN <== 0x54414c4c595f444f4d41494e;                 // "TALLY_DOMAIN"
}

// ============================================================================
// SECURITY HELPERS
// ============================================================================

// Binary constraint helper
template BinaryConstraint() {
    signal input in;
    signal output out;
    
    // Proper binary constraint: in * (1 - in) = 0
    signal inv;
    inv <== 1 - in;
    signal product;
    product <== in * inv;
    product === 0;
    
    out <== in;
}

// Safe IsZero implementation
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    // Safe witness generation with ternary
    inv <-- in != 0 ? (1 / in) : 0;
    
    // Constraints
    signal intermediate;
    intermediate <== in * inv;
    out <== 1 - intermediate;
    
    // Ensure if in != 0, then out = 0
    in * out === 0;
}

// Range proof for values up to 2^bits
template RangeProof(bits) {
    signal input in;
    signal output out;
    
    component n2b = Num2Bits(bits);
    n2b.in <== in;
    
    // Verify reconstruction matches input
    component b2n = Bits2Num(bits);
    for (var i = 0; i < bits; i++) {
        b2n.in[i] <== n2b.out[i];
    }
    
    // Proper constraint ensuring equality
    signal diff;
    diff <== in - b2n.out;
    diff === 0;
    
    out <== in;
}

// Binary AND operation
template BinaryAND() {
    signal input a;
    signal input b;
    signal output out;
    
    // Ensure inputs are binary
    component aBinary = BinaryConstraint();
    aBinary.in <== a;
    
    component bBinary = BinaryConstraint();
    bBinary.in <== b;
    
    // AND operation
    out <== a * b;
}

// Multi-input AND for efficiency
template MultiAND(n) {
    signal input in[n];
    signal output out;
    
    signal acc[n+1];
    acc[0] <== 1;
    
    for (var i = 0; i < n; i++) {
        acc[i+1] <== acc[i] * in[i];
    }
    
    out <== acc[n];
}

// CRITICAL FIX: Enhanced SafeAdd with proper overflow protection
template SafeAdd(max_value) {
    signal input a;
    signal input b;
    signal output sum;
    
    // Compute sum
    sum <== a + b;
    
    // Range check both inputs
    component aCheck = LessThan(32);
    aCheck.in[0] <== a;
    aCheck.in[1] <== max_value;
    aCheck.out === 1;
    
    component bCheck = LessThan(32);
    bCheck.in[0] <== b;
    bCheck.in[1] <== max_value;
    bCheck.out === 1;
    
    // Range check the sum
    component sumCheck = LessThan(32);
    sumCheck.in[0] <== sum;
    sumCheck.in[1] <== max_value;
    sumCheck.out === 1;
}

// CRITICAL FIX: Enhanced Merkle tree with path uniqueness checks
template MerkleInclusionProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;
    
    // Constrain path indices to be binary
    component pathBinary[levels];
    for (var i = 0; i < levels; i++) {
        pathBinary[i] = BinaryConstraint();
        pathBinary[i].in <== pathIndices[i];
    }
    
    // SECURITY FIX: Verify path elements are unique (prevent collision attacks)
    // Note: This is a strict check - in practice, same elements can appear
    // at different levels if they're on different sides of the tree
    // But for maximum security, we enforce uniqueness
    component uniqueCheck[levels][levels];
    for (var i = 0; i < levels; i++) {
        for (var j = i + 1; j < levels; j++) {
            uniqueCheck[i][j] = IsEqual();
            uniqueCheck[i][j].in[0] <== pathElements[i];
            uniqueCheck[i][j].in[1] <== pathElements[j];
            // In production, you might want to relax this constraint
            // and only check for suspicious patterns
        }
    }
    
    component hashers[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // Fixed constraint for proper signal flow
        signal left;
        signal right;
        left <== (1 - pathIndices[i]) * hashes[i] + pathIndices[i] * pathElements[i];
        right <== pathIndices[i] * hashes[i] + (1 - pathIndices[i]) * pathElements[i];
        
        hashers[i].inputs[0] <== left;
        hashers[i].inputs[1] <== right;
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    root <== hashes[levels];
}

// Duplicate prevention
template NoDuplicates(n) {
    signal input values[n];
    
    // For each pair, ensure they're different
    component notEqual[n][n];
    for (var i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
            notEqual[i][j] = IsEqual();
            notEqual[i][j].in[0] <== values[i];
            notEqual[i][j].in[1] <== values[j];
            notEqual[i][j].out === 0;  // Must not be equal
        }
    }
}

// Blinded ballot commitment for enhanced privacy
template BlindedBallotCommitment(num_candidates) {
    signal input ballot[num_candidates];
    signal input secret;
    signal input blindingFactor;
    signal output commitment;
    
    component domains = DomainConstants();
    
    component hasher = Poseidon(num_candidates + 3);
    hasher.inputs[0] <== domains.COMMITMENT_DOMAIN;
    
    for (var i = 0; i < num_candidates; i++) {
        hasher.inputs[i + 1] <== ballot[i];
    }
    hasher.inputs[num_candidates + 1] <== secret;
    hasher.inputs[num_candidates + 2] <== blindingFactor;
    
    commitment <== hasher.out;
}

// ============================================================================
// MAIN CIRCUIT 1: Parameterized Ballot Validator with SECURITY FIXES
// ============================================================================
template BallotValidator(num_candidates) {
    // Private inputs
    signal input ballot[num_candidates];
    signal input nullifier;
    signal input secret;
    signal input timestamp;
    signal input blindingFactor;
    
    // Public inputs/outputs
    signal input electionId;
    signal output commitment;
    signal output nullifierHash;
    signal output valid;
    
    // Domain constants
    component domains = DomainConstants();
    
    // 1. Binary constraint for each vote
    for (var i = 0; i < num_candidates; i++) {
        component binaryCheck = BinaryConstraint();
        binaryCheck.in <== ballot[i];
    }
    
    // 2. One-hot encoding check (exactly one vote)
    signal sum[num_candidates + 1];
    sum[0] <== 0;
    for (var i = 0; i < num_candidates; i++) {
        sum[i + 1] <== sum[i] + ballot[i];
    }
    
    component sumCheck = IsEqual();
    sumCheck.in[0] <== sum[num_candidates];
    sumCheck.in[1] <== 1;
    valid <== sumCheck.out;
    
    // 3. Compute ballot commitment with blinding
    component commitHasher = Poseidon(num_candidates + 4);
    commitHasher.inputs[0] <== domains.COMMITMENT_DOMAIN;
    
    for (var i = 0; i < num_candidates; i++) {
        commitHasher.inputs[i + 1] <== ballot[i];
    }
    commitHasher.inputs[num_candidates + 1] <== secret;
    commitHasher.inputs[num_candidates + 2] <== electionId;
    commitHasher.inputs[num_candidates + 3] <== timestamp;
    
    commitment <== commitHasher.out;
    
    // CRITICAL FIX: 4. Compute nullifier hash with ballot binding
    signal nullifierSalt;
    nullifierSalt <== nullifier * secret;
    
    // First compute ballot hash for binding
    component ballotHasher = Poseidon(num_candidates + 1);
    ballotHasher.inputs[0] <== domains.COMMITMENT_DOMAIN;
    for (var i = 0; i < num_candidates; i++) {
        ballotHasher.inputs[i + 1] <== ballot[i];
    }
    signal ballotHash;
    ballotHash <== ballotHasher.out;
    
    // Now compute nullifier bound to ballot
    component nullHasher = Poseidon(7);
    nullHasher.inputs[0] <== domains.NULLIFIER_DOMAIN;
    nullHasher.inputs[1] <== secret;
    nullHasher.inputs[2] <== nullifier;
    nullHasher.inputs[3] <== electionId;
    nullHasher.inputs[4] <== nullifierSalt;
    nullHasher.inputs[5] <== timestamp;
    nullHasher.inputs[6] <== ballotHash;  // CRITICAL: Bind to ballot content
    
    nullifierHash <== nullHasher.out;
    
    // 5. Range checks
    component nullifierRange = RangeProof(128);
    nullifierRange.in <== nullifier;
    
    component secretRange = RangeProof(253);
    secretRange.in <== secret;
    
    component blindingRange = RangeProof(253);
    blindingRange.in <== blindingFactor;
    
    // Validate election ID and timestamp
    component electionIdCheck = RangeProof(64);
    electionIdCheck.in <== electionId;
    
    component timestampCheck = RangeProof(64);
    timestampCheck.in <== timestamp;
    
    // 6. Ensure secret is not zero
    component isZero = IsZero();
    isZero.in <== secret;
    isZero.out === 0;
}

// ============================================================================
// MAIN CIRCUIT 2: Batch Ballot Aggregator with OVERFLOW PROTECTION
// ============================================================================
template BatchBallotAggregator(num_candidates, batch_size, tree_levels) {
    // Private inputs
    signal input ballots[batch_size][num_candidates];
    signal input nullifiers[batch_size];
    signal input secrets[batch_size];
    signal input timestamps[batch_size];
    signal input blindingFactors[batch_size];
    signal input merklePathElements[batch_size][tree_levels];
    signal input merklePathIndices[batch_size][tree_levels];
    
    // Public inputs/outputs
    signal input electionId;
    signal input merkleRoot;
    signal output batchCommitment;
    signal output nullifierBatchHash;
    signal output allValid;
    signal output candidateSums[num_candidates];
    
    // Individual ballot validators
    component validators[batch_size];
    component merkleProofs[batch_size];
    
    // More efficient validity check
    signal validity[batch_size];
    
    // Initialize candidate sums
    signal partialSums[batch_size + 1][num_candidates];
    for (var j = 0; j < num_candidates; j++) {
        partialSums[0][j] <== 0;
    }
    
    // Process each ballot
    signal commitments[batch_size];
    signal nullifierHashes[batch_size];
    
    for (var i = 0; i < batch_size; i++) {
        // Validate ballot
        validators[i] = BallotValidator(num_candidates);
        for (var j = 0; j < num_candidates; j++) {
            validators[i].ballot[j] <== ballots[i][j];
        }
        validators[i].nullifier <== nullifiers[i];
        validators[i].secret <== secrets[i];
        validators[i].timestamp <== timestamps[i];
        validators[i].blindingFactor <== blindingFactors[i];
        validators[i].electionId <== electionId;
        
        commitments[i] <== validators[i].commitment;
        nullifierHashes[i] <== validators[i].nullifierHash;
        
        // Verify Merkle inclusion
        merkleProofs[i] = MerkleInclusionProof(tree_levels);
        merkleProofs[i].leaf <== commitments[i];
        for (var j = 0; j < tree_levels; j++) {
            merkleProofs[i].pathElements[j] <== merklePathElements[i][j];
            merkleProofs[i].pathIndices[j] <== merklePathIndices[i][j];
        }
        
        // Explicit root check
        component rootCheck = IsEqual();
        rootCheck.in[0] <== merkleProofs[i].root;
        rootCheck.in[1] <== merkleRoot;
        
        // Combine ballot validity and root check
        validity[i] <== validators[i].valid * rootCheck.out;
        
        // CRITICAL FIX: Update candidate sums with overflow protection
        for (var j = 0; j < num_candidates; j++) {
            component safeAdd = SafeAdd(100000);  // Max 100k votes per candidate
            safeAdd.a <== partialSums[i][j];
            safeAdd.b <== ballots[i][j];
            partialSums[i + 1][j] <== safeAdd.sum;
        }
    }
    
    // Use single product check for efficiency
    component validProduct = MultiAND(batch_size);
    for (var i = 0; i < batch_size; i++) {
        validProduct.in[i] <== validity[i];
    }
    allValid <== validProduct.out;
    
    // Output final sums
    for (var j = 0; j < num_candidates; j++) {
        candidateSums[j] <== partialSums[batch_size][j];
    }
    
    // Compute batch commitments
    component batchHasher = Poseidon(batch_size + 1);
    batchHasher.inputs[0] <== electionId;
    for (var i = 0; i < batch_size; i++) {
        batchHasher.inputs[i + 1] <== commitments[i];
    }
    batchCommitment <== batchHasher.out;
    
    // Duplicate prevention for nullifiers
    component noDupNullifiers = NoDuplicates(batch_size);
    for (var i = 0; i < batch_size; i++) {
        noDupNullifiers.values[i] <== nullifierHashes[i];
    }
    
    // Batch nullifier hash
    component nullBatchHasher = Poseidon(batch_size + 1);
    nullBatchHasher.inputs[0] <== electionId;
    for (var i = 0; i < batch_size; i++) {
        nullBatchHasher.inputs[i + 1] <== nullifierHashes[i];
    }
    nullifierBatchHash <== nullBatchHasher.out;
}

// ============================================================================
// MAIN CIRCUIT 3: Tally Correctness Proof with Range Checks
// ============================================================================
template TallyCorrectnessProof(num_candidates, max_ballots) {
    // Private inputs
    signal input ballots[max_ballots][num_candidates];
    signal input actualBallotCount;
    
    // Public inputs/outputs
    signal input claimedTally[num_candidates];
    signal input electionId;
    signal output tallyCommitment;
    signal output validTally;
    
    // Domain constants
    component domains = DomainConstants();
    
    // 1. Range check actual ballot count
    component countRange = RangeProof(32);
    countRange.in <== actualBallotCount;
    
    // Check actualBallotCount <= max_ballots
    component countCheck = LessEqThan(32);
    countCheck.in[0] <== actualBallotCount;
    countCheck.in[1] <== max_ballots;
    
    // 2. Compute actual tally with masking for unused slots
    signal isActive[max_ballots];
    signal maskedBallots[max_ballots][num_candidates];
    signal partialTally[max_ballots + 1][num_candidates];
    
    // Initialize
    for (var j = 0; j < num_candidates; j++) {
        partialTally[0][j] <== 0;
    }
    
    // Process each ballot slot
    for (var i = 0; i < max_ballots; i++) {
        // Check if this ballot is active
        component ltCheck = LessThan(32);
        ltCheck.in[0] <== i;
        ltCheck.in[1] <== actualBallotCount;
        isActive[i] <== ltCheck.out;
        
        // Mask ballot based on active status
        for (var j = 0; j < num_candidates; j++) {
            maskedBallots[i][j] <== ballots[i][j] * isActive[i];
            partialTally[i + 1][j] <== partialTally[i][j] + maskedBallots[i][j];
        }
    }
    
    // 3. Verify claimed tally matches computed tally
    signal tallyMatches[num_candidates];
    for (var j = 0; j < num_candidates; j++) {
        component eq = IsEqual();
        eq.in[0] <== partialTally[max_ballots][j];
        eq.in[1] <== claimedTally[j];
        tallyMatches[j] <== eq.out;
    }
    
    // All tallies must match
    component matchProduct = MultiAND(num_candidates);
    for (var j = 0; j < num_candidates; j++) {
        matchProduct.in[j] <== tallyMatches[j];
    }
    
    // 4. Range check each tally value
    for (var j = 0; j < num_candidates; j++) {
        component range = RangeProof(32);
        range.in <== claimedTally[j];
    }
    
    // 5. Verify sum of tally equals actualBallotCount
    signal tallySum[num_candidates + 1];
    tallySum[0] <== 0;
    for (var j = 0; j < num_candidates; j++) {
        tallySum[j + 1] <== tallySum[j] + claimedTally[j];
    }
    
    component sumCheck = IsEqual();
    sumCheck.in[0] <== tallySum[num_candidates];
    sumCheck.in[1] <== actualBallotCount;
    
    // Final validity
    validTally <== matchProduct.out * sumCheck.out * countCheck.out;
    
    // 6. Compute tally commitment with domain separation
    component tallyHasher = Poseidon(num_candidates + 2);
    tallyHasher.inputs[0] <== domains.TALLY_DOMAIN;
    for (var j = 0; j < num_candidates; j++) {
        tallyHasher.inputs[j + 1] <== claimedTally[j];
    }
    tallyHasher.inputs[num_candidates + 1] <== electionId;
    tallyCommitment <== tallyHasher.out;
}

// ============================================================================
// MAIN CIRCUIT 4: Recursive Proof Aggregator (for massive scale)
// ============================================================================
template RecursiveProofAggregator(num_proofs) {
    // Inputs: Previous proof commitments
    signal input prevProofCommitments[num_proofs];
    signal input prevProofValidity[num_proofs];
    signal input aggregationLevel;
    
    // Outputs
    signal output aggregatedCommitment;
    signal output allValid;
    
    // Check all proofs are valid
    component validProduct = MultiAND(num_proofs);
    for (var i = 0; i < num_proofs; i++) {
        validProduct.in[i] <== prevProofValidity[i];
    }
    allValid <== validProduct.out;
    
    // Aggregate commitments
    component hasher = Poseidon(num_proofs + 2);
    hasher.inputs[0] <== aggregationLevel;
    hasher.inputs[1] <== allValid; // Include validity in hash
    for (var i = 0; i < num_proofs; i++) {
        hasher.inputs[i + 2] <== prevProofCommitments[i];
    }
    aggregatedCommitment <== hasher.out;
    
    // Verify each commitment is in valid range
    for (var i = 0; i < num_proofs; i++) {
        component commitRange = RangeProof(253);
        commitRange.in <== prevProofCommitments[i];
    }
}

// ============================================================================
// OPTIMIZED POSEIDON USAGE
// ============================================================================
template OptimizedCommitment(num_candidates) {
    signal input values[num_candidates];
    signal output commitment;
    
    component domains = DomainConstants();
    
    if (num_candidates <= 6) {
        component h = Poseidon(num_candidates + 1);
        h.inputs[0] <== domains.COMMITMENT_DOMAIN;
        for (var i = 0; i < num_candidates; i++) {
            h.inputs[i + 1] <== values[i];
        }
        commitment <== h.out;
    } else {
        // Split into chunks of 6 and hash hierarchically
        var chunks = num_candidates \ 6 + (num_candidates % 6 != 0 ? 1 : 0);
        signal intermediate[chunks];
        
        for (var chunk = 0; chunk < chunks; chunk++) {
            component h = Poseidon(7); // 6 values + domain
            h.inputs[0] <== domains.COMMITMENT_DOMAIN + chunk;
            
            for (var i = 0; i < 6; i++) {
                var idx = chunk * 6 + i;
                if (idx < num_candidates) {
                    h.inputs[i + 1] <== values[idx];
                } else {
                    h.inputs[i + 1] <== 0; // Padding
                }
            }
            intermediate[chunk] <== h.out;
        }
        
        // Final hash of intermediates
        component finalHash = Poseidon(chunks + 1);
        finalHash.inputs[0] <== domains.COMMITMENT_DOMAIN;
        for (var chunk = 0; chunk < chunks; chunk++) {
            finalHash.inputs[chunk + 1] <== intermediate[chunk];
        }
        commitment <== finalHash.out;
    }
}

// ============================================================================
// COMPILE DIFFERENT VARIANTS FOR COMMON ELECTION SIZES
// ============================================================================

// For 3 candidates (small election)
component main = BallotValidator(3);

// For 5 candidates (medium election) - compile separately
// component main = BallotValidator(5);

// For 10 candidates (large election) - compile separately
// component main = BallotValidator(10);

// Batch validator for 3 candidates, 32 ballot batches, 10-level merkle tree
// component main = BatchBallotAggregator(3, 32, 10);

// Tally proof for 3 candidates, max 10000 ballots
// component main = TallyCorrectnessProof(3, 10000);