from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
import os

# Import the actual modules to avoid circular imports
from pathlib import Path

# Define configs inline to avoid import issues


@dataclass
class ZKConfig:
    circuit_name: str = "voting"
    curve: str = "bn128"
    build_dir: Path = field(default_factory=lambda: Path("circuits/build"))
    ptau_file: Path = field(default_factory=lambda: Path(
        "circuits/powersOfTau28_hez_final_12.ptau"))
    force_real_proofs: bool = False
    proof_timeout: int = 60
    num_candidates: int = 3

    def __post_init__(self):
        self.build_dir = Path(self.build_dir)
        self.ptau_file = Path(self.ptau_file)


@dataclass
class PQConfig:
    kyber_variant: str = "KYBER768"
    dilithium_variant: str = "DILITHIUM3"
    key_storage_dir: Path = field(default_factory=lambda: Path("keys/pq_keys"))
    enable_key_rotation: bool = True
    rotation_interval_hours: int = 24
    allow_fallback: bool = True
    key_refresh_interval: int = 86400

    def __post_init__(self):
        self.key_storage_dir = Path(self.key_storage_dir)
        self.key_storage_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class SystemConfig:
    num_candidates: int = 3
    num_mpc_parties: int = 3

    zk_config: ZKConfig = field(default_factory=ZKConfig)
    pq_config: PQConfig = field(default_factory=PQConfig)

    log_dir: Path = field(default_factory=lambda: Path("logs"))
    results_dir: Path = field(default_factory=lambda: Path("results"))
    enable_benchmarking: bool = True
    enable_debug_mode: bool = False

    def __post_init__(self):
        self.log_dir = Path(self.log_dir)
        self.results_dir = Path(self.results_dir)

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Update sub-configs with system values
        self.zk_config.num_candidates = self.num_candidates
        self.pq_config.key_storage_dir.mkdir(parents=True, exist_ok=True)

        os.environ['RUST_LOG'] = 'debug' if self.enable_debug_mode else 'info'


def load_config(config_path: Optional[Path] = None) -> SystemConfig:
    """Load configuration from file or return default"""
    if config_path is None:
        config_path = Path("config.yaml")

    if config_path.exists():
        try:
            import yaml

            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)

            zk_data = config_data.get('zk_proofs', {})
            zk_config = ZKConfig(
                circuit_name=zk_data.get('circuit_name', 'voting'),
                curve=zk_data.get('curve', 'bn128'),
                build_dir=Path(zk_data.get('build_dir', 'circuits/build')),
                ptau_file=Path(zk_data.get(
                    'ptau_file', 'circuits/powersOfTau28_hez_final_12.ptau')),
                force_real_proofs=zk_data.get('force_real_proofs', False),
                proof_timeout=zk_data.get('proof_timeout', 60),
                num_candidates=config_data.get('num_candidates', 3)
            )

            pq_data = config_data.get('post_quantum', {})
            pq_config = PQConfig(
                kyber_variant=pq_data.get('kyber_variant', 'KYBER768'),
                dilithium_variant=pq_data.get(
                    'dilithium_variant', 'DILITHIUM3'),
                key_storage_dir=Path(pq_data.get(
                    'key_storage_dir', 'keys/pq_keys')),
                enable_key_rotation=pq_data.get('enable_key_rotation', True),
                rotation_interval_hours=pq_data.get(
                    'rotation_interval_hours', 24),
                allow_fallback=pq_data.get('allow_fallback', True)
            )

            return SystemConfig(
                num_candidates=config_data.get('num_candidates', 3),
                num_mpc_parties=config_data.get('num_mpc_parties', 3),
                zk_config=zk_config,
                pq_config=pq_config,
                log_dir=Path(config_data.get('log_dir', 'logs')),
                results_dir=Path(config_data.get('results_dir', 'results')),
                enable_benchmarking=config_data.get(
                    'enable_benchmarking', True),
                enable_debug_mode=config_data.get('enable_debug_mode', False)
            )
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
            print("Using default configuration")

    return SystemConfig()


def save_config(config: SystemConfig, config_path: Optional[Path] = None):
    """Save configuration to YAML file"""
    if config_path is None:
        config_path = Path("config.yaml")

    try:
        import yaml

        config_data = {
            'num_candidates': config.num_candidates,
            'num_mpc_parties': config.num_mpc_parties,
            'zk_proofs': {
                'circuit_name': config.zk_config.circuit_name,
                'curve': config.zk_config.curve,
                'build_dir': str(config.zk_config.build_dir),
                'ptau_file': str(config.zk_config.ptau_file),
                'force_real_proofs': config.zk_config.force_real_proofs,
                'proof_timeout': config.zk_config.proof_timeout
            },
            'post_quantum': {
                'kyber_variant': config.pq_config.kyber_variant,
                'dilithium_variant': config.pq_config.dilithium_variant,
                'key_storage_dir': str(config.pq_config.key_storage_dir),
                'enable_key_rotation': config.pq_config.enable_key_rotation,
                'rotation_interval_hours': config.pq_config.rotation_interval_hours,
                'allow_fallback': config.pq_config.allow_fallback
            },
            'log_dir': str(config.log_dir),
            'results_dir': str(config.results_dir),
            'enable_benchmarking': config.enable_benchmarking,
            'enable_debug_mode': config.enable_debug_mode
        }

        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)

    except ImportError:
        print("Warning: PyYAML not available, cannot save config file")
    except Exception as e:
        print(f"Warning: Could not save config file {config_path}: {e}")
