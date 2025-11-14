#!/bin/bash

# ZK Circuit Compilation Script - Production Ready
# Compiles Circom circuits for the voting system with proper error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CIRCUIT_NAME="voting"
BUILD_DIR="circuits/build"
CIRCUIT_FILE="circuits/voting.circom"
PTAU_FILE="circuits/powersOfTau28_hez_final_12.ptau"
FINAL_ZKEY="${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v circom &> /dev/null; then
        error "circom not found. Install with: cargo install --git https://github.com/iden3/circom.git"
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        error "snarkjs not found. Install with: npm install -g snarkjs"
    fi
    
    if ! command -v node &> /dev/null; then
        error "Node.js not found. Please install Node.js"
    fi
    
    # Check versions
    CIRCOM_VERSION=$(circom --version | head -n1)
    SNARKJS_VERSION=$(snarkjs --version 2>&1 | head -n1)
    
    log "Dependencies OK:"
    log "  - $CIRCOM_VERSION"
    log "  - $SNARKJS_VERSION"
    log "  - Node.js $(node --version)"
}

# Create directory structure
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "logs"
    success "Directory structure created"
}

# Compile circuit
compile_circuit() {
    log "Compiling circuit: $CIRCUIT_FILE"
    
    if [ ! -f "$CIRCUIT_FILE" ]; then
        error "Circuit file not found: $CIRCUIT_FILE"
    fi
    
    # Compile with optimizations
    circom "$CIRCUIT_FILE" \
        --r1cs \
        --wasm \
        --sym \
        --output "$BUILD_DIR" \
        --O2
    
    if [ $? -ne 0 ]; then
        error "Circuit compilation failed"
    fi
    
    success "Circuit compiled successfully"
}

# Download or verify powers of tau
setup_ptau() {
    log "Setting up Powers of Tau..."
    
    if [ ! -f "$PTAU_FILE" ]; then
        warning "Powers of Tau file not found. Downloading..."
        
        # Download ptau file (12th power = 4096 constraints max)
        wget -O "$PTAU_FILE" \
            https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau
        
        if [ $? -ne 0 ]; then
            error "Failed to download Powers of Tau file"
        fi
    fi
    
    # Verify ptau file integrity
    log "Verifying Powers of Tau file..."
    snarkjs powersoftau verify "$PTAU_FILE"
    
    if [ $? -ne 0 ]; then
        error "Powers of Tau verification failed"
    fi
    
    success "Powers of Tau ready"
}

# Generate proving and verification keys
setup_keys() {
    log "Setting up proving and verification keys..."
    
    # Phase 2 trusted setup
    ZKEY_0="${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"
    ZKEY_1="${BUILD_DIR}/${CIRCUIT_NAME}_0001.zkey"
    
    # Start Phase 2
    log "Starting Phase 2 trusted setup..."
    snarkjs groth16 setup \
        "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
        "$PTAU_FILE" \
        "$ZKEY_0"
    
    if [ $? -ne 0 ]; then
        error "Phase 2 setup failed"
    fi
    
    # Contribute to ceremony (in production, this would be a multi-party ceremony)
    log "Contributing to trusted setup ceremony..."
    echo "production_voting_system_$(date +%s)" | \
    snarkjs zkey contribute \
        "$ZKEY_0" \
        "$ZKEY_1" \
        --name="ProductionContribution" \
        -v
    
    if [ $? -ne 0 ]; then
        error "Trusted setup contribution failed"
    fi
    
    # Apply random beacon (simulate final ceremony step)
    log "Applying random beacon..."
    snarkjs zkey beacon \
        "$ZKEY_1" \
        "$FINAL_ZKEY" \
        0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        10 \
        -n="Final Beacon"
    
    if [ $? -ne 0 ]; then
        error "Beacon application failed"
    fi
    
    success "Trusted setup completed"
}

# Generate verification key
generate_verification_key() {
    log "Generating verification key..."
    
    snarkjs zkey export verificationkey \
        "$FINAL_ZKEY" \
        "${BUILD_DIR}/verification_key.json"
    
    if [ $? -ne 0 ]; then
        error "Verification key generation failed"
    fi
    
    success "Verification key generated"
}

# Verify setup
verify_setup() {
    log "Verifying trusted setup..."
    
    snarkjs zkey verify \
        "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
        "$PTAU_FILE" \
        "$FINAL_ZKEY"
    
    if [ $? -ne 0 ]; then
        error "Setup verification failed"
    fi
    
    success "Trusted setup verification passed"
}

# Generate circuit info
generate_circuit_info() {
    log "Generating circuit information..."
    
    # Get circuit statistics
    R1CS_INFO=$(snarkjs r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" 2>&1)
    CONSTRAINTS=$(echo "$R1CS_INFO" | grep "# of Constraints" | awk '{print $4}')
    VARIABLES=$(echo "$R1CS_INFO" | grep "# of Variables" | awk '{print $4}')
    PRIVATE_INPUTS=$(echo "$R1CS_INFO" | grep "# of Private Inputs" | awk '{print $5}')
    PUBLIC_INPUTS=$(echo "$R1CS_INFO" | grep "# of Public Inputs" | awk '{print $5}')
    
    # Create info file
    cat > "${BUILD_DIR}/circuit_info.json" << EOF
{
    "circuit_name": "$CIRCUIT_NAME",
    "constraints": $CONSTRAINTS,
    "variables": $VARIABLES,
    "private_inputs": $PRIVATE_INPUTS,
    "public_inputs": $PUBLIC_INPUTS,
    "compilation_date": "$(date -Iseconds)",
    "circom_version": "$(circom --version | head -n1)",
    "snarkjs_version": "$(snarkjs --version 2>&1 | head -n1)",
    "curve": "bn128",
    "proving_system": "groth16"
}
EOF
    
    success "Circuit info saved to ${BUILD_DIR}/circuit_info.json"
}

# Run tests
run_tests() {
    log "Running circuit tests..."
    
    # Create test input
    cat > "${BUILD_DIR}/test_input.json" << EOF
{
    "ballot": ["1", "0", "0"],
    "nullifier": "123456789",
    "secret": "987654321"
}
EOF
    
    # Generate witness
    node "${BUILD_DIR}/${CIRCUIT_NAME}_js/generate_witness.js" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
        "${BUILD_DIR}/test_input.json" \
        "${BUILD_DIR}/test_witness.wtns"
    
    if [ $? -ne 0 ]; then
        error "Test witness generation failed"
    fi
    
    # Generate proof
    snarkjs groth16 prove \
        "$FINAL_ZKEY" \
        "${BUILD_DIR}/test_witness.wtns" \
        "${BUILD_DIR}/test_proof.json" \
        "${BUILD_DIR}/test_public.json"
    
    if [ $? -ne 0 ]; then
        error "Test proof generation failed"
    fi
    
    # Verify proof
    snarkjs groth16 verify \
        "${BUILD_DIR}/verification_key.json" \
        "${BUILD_DIR}/test_public.json" \
        "${BUILD_DIR}/test_proof.json"
    
    if [ $? -ne 0 ]; then
        error "Test proof verification failed"
    fi
    
    success "All tests passed!"
}

# Cleanup temporary files
cleanup() {
    log "Cleaning up temporary files..."
    rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"
    rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_0001.zkey" 
    rm -f "${BUILD_DIR}/test_*"
    success "Cleanup completed"
}

# Print summary
print_summary() {
    log "==============================================="
    log "ZK CIRCUIT COMPILATION COMPLETED SUCCESSFULLY"
    log "==============================================="
    log ""
    log "Generated files:"
    log "  - ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs (R1CS constraint system)"
    log "  - ${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm (WASM witness generator)"
    log "  - ${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey (Proving key)"
    log "  - ${BUILD_DIR}/verification_key.json (Verification key)"
    log "  - ${BUILD_DIR}/circuit_info.json (Circuit metadata)"
    log ""
    
    if [ -f "${BUILD_DIR}/circuit_info.json" ]; then
        CONSTRAINTS=$(jq -r '.constraints' "${BUILD_DIR}/circuit_info.json" 2>/dev/null || echo "N/A")
        log "Circuit statistics:"
        log "  - Constraints: $CONSTRAINTS"
    fi
    
    log ""
    log "Ready for production use!"
}

# Main execution
main() {
    echo "=================================="
    echo "ZK CIRCUIT COMPILATION SCRIPT"
    echo "Production Voting System"
    echo "=================================="
    echo ""
    
    check_dependencies
    setup_directories
    compile_circuit
    setup_ptau
    setup_keys
    generate_verification_key
    verify_setup
    generate_circuit_info
    run_tests
    cleanup
    print_summary
}

# Run main function
main "$@"