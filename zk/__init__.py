"""
Zero-Knowledge Proof Module for Cryptographic Voting System
Production-ready ZK-SNARK implementation with Groth16 proofs
"""

from .zk_proofs import (
    # Core classes
    ZKProofSystem,
    ZKConfig,
    ProofArtifact,

    # Exceptions
    ZKError,
    CircuitCompilationError,
    TrustedSetupError,
    ProofGenerationError,
)

__version__ = "1.0.0"
__author__ = "Cryptographic Voting System Team"

__all__ = [
    # Classes
    'ZKProofSystem',
    'ZKConfig',
    'ProofArtifact',

    # Exceptions
    'ZKError',
    'CircuitCompilationError',
    'TrustedSetupError',
    'ProofGenerationError',
]
