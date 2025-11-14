"""Production Multi-Party Computation voting module with malicious security."""

from .mpc_voting import (
    # Main production API
    run_production_mpc_tally,

    # Core protocol classes
    ProductionMPCProtocol,
    MaliciousSecureMPCParty,
    ThresholdSecretSharing,
    PBFTConsensus,
    ProductionFieldArithmetic,

    # Data structures
    ThresholdShare,
    CryptographicCommitment,
    ByzantineMessage,
    MPCSecurityProof,

    # Enums and status
    MPCStatus,

    # Exceptions
    MPCSecurityError,
    MaliciousPartyError,
    ThresholdViolationError,
    ByzantineConsensusError,

    # Legacy compatibility (deprecated)
    validate_ballot,
    create_test_ballots
)

__version__ = "2.0.0"
__status__ = "Production Ready - Malicious Secure"

__all__ = [
    # Main API
    'run_production_mpc_tally',

    # Core classes
    'ProductionMPCProtocol',
    'MaliciousSecureMPCParty',
    'ThresholdSecretSharing',
    'PBFTConsensus',
    'ProductionFieldArithmetic',

    # Data structures
    'ThresholdShare',
    'CryptographicCommitment',
    'ByzantineMessage',
    'MPCSecurityProof',

    # Status and exceptions
    'MPCStatus',
    'MPCSecurityError',
    'MaliciousPartyError',
    'ThresholdViolationError',
    'ByzantineConsensusError',

    # Legacy (deprecated)
    'validate_ballot',
    'create_test_ballots'
]
