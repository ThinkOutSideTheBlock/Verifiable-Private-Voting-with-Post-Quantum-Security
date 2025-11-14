"""Production Post-Quantum Cryptography module with enterprise security."""

from .pq_crypto import (
    # Main production system
    ProductionPQCryptoSystem,

    # Configuration and enums
    PQConfig,
    PQAlgorithm,
    SecurityLevel,
    KeyType,

    # Core security components
    ProductionHSMManager,
    PostQuantumCertificateAuthority,
    ForwardSecrecyManager,
    KeyDistributionProtocol,
    SessionManager,
    SecureMemoryManager,

    # Data structures
    PQCertificate,
    SecureSession,
    EphemeralKey,
    HSMKeyHandle,
    SecureMemoryRegion,

    # Convenience functions
    create_production_system as create_production_pq_system,
    async_establish_session,
    async_encrypt_message,

    # Exceptions
    PQError,
    HSMError,
    CertificateError,
    ForwardSecrecyError,
    KeyDistributionError,
    SessionError
)

__version__ = "2.0.0"
__status__ = "Production Ready - Enterprise Security"

__all__ = [
    # Main system
    'ProductionPQCryptoSystem',

    # Configuration
    'PQConfig',
    'PQAlgorithm',
    'SecurityLevel',
    'KeyType',

    # Core components
    'ProductionHSMManager',
    'PostQuantumCertificateAuthority',
    'ForwardSecrecyManager',
    'KeyDistributionProtocol',
    'SessionManager',
    'SecureMemoryManager',

    # Data structures
    'PQCertificate',
    'SecureSession',
    'EphemeralKey',
    'HSMKeyHandle',
    'SecureMemoryRegion',

    # API functions
    'create_production_pq_system',
    'async_establish_session',
    'async_encrypt_message',

    # Exceptions
    'PQError',
    'HSMError',
    'CertificateError',
    'ForwardSecrecyError',
    'KeyDistributionError',
    'SessionError'
]
