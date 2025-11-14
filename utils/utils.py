"""
Complete Utilities Module for Cryptographic Voting System
Maintains all existing functionality with fixes for test imports
"""

import logging
import json
import time
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import platform
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# Try to import optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logging.warning("psutil not available - performance monitoring limited")

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    logging.warning("numpy not available - using basic statistics")


@dataclass
class PerformanceMetrics:
    operation: str
    duration_seconds: float
    cpu_percent: float
    memory_mb: float
    timestamp: float
    additional_data: Dict[str, Any] = None


def setup_logging(log_level: str = "INFO", log_file: Optional[Path] = None):
    """Setup logging with fallback if directories don't exist"""
    if log_file is None:
        log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / \
            f"voting_system_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Clear existing handlers to avoid duplicates
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    logging.getLogger("asyncio").setLevel(logging.WARNING)

    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized. Log file: {log_file}")

    return logger


class PerformanceMonitor:
    """Enhanced Performance Monitor with context manager support"""

    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        if HAS_PSUTIL:
            self.process = psutil.Process()
        else:
            self.process = None

    def start_operation(self, operation_name: str) -> 'OperationContext':
        """Start monitoring an operation - returns context manager"""
        return OperationContext(self, operation_name)

    def record_metric(self, metric: PerformanceMetrics):
        """Record a performance metric"""
        self.metrics.append(metric)

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary with enhanced statistics"""
        if not self.metrics:
            return {
                'total_operations': 0,
                'total_duration': 0.0,
                'operations': {}
            }

        operation_groups = {}
        for metric in self.metrics:
            if metric.operation not in operation_groups:
                operation_groups[metric.operation] = []
            operation_groups[metric.operation].append(metric)

        summary = {
            'total_operations': len(self.metrics),
            'operations': {}
        }

        for op_name, metrics in operation_groups.items():
            durations = [m.duration_seconds for m in metrics]
            cpu_usages = [m.cpu_percent for m in metrics if m.cpu_percent > 0]
            memory_usages = [m.memory_mb for m in metrics if m.memory_mb > 0]

            if HAS_NUMPY and len(durations) > 0:
                summary['operations'][op_name] = {
                    'count': len(metrics),
                    'total_duration': sum(durations),
                    'avg_duration': float(np.mean(durations)),
                    'min_duration': min(durations),
                    'max_duration': max(durations),
                    'std_duration': float(np.std(durations)) if len(durations) > 1 else 0.0,
                    'avg_cpu_percent': float(np.mean(cpu_usages)) if cpu_usages else 0.0,
                    'avg_memory_mb': float(np.mean(memory_usages)) if memory_usages else 0.0,
                    'peak_memory_mb': max(memory_usages) if memory_usages else 0.0,
                    'throughput_ops_per_sec': len(metrics) / sum(durations) if sum(durations) > 0 else 0.0
                }
            else:
                # Fallback without numpy
                avg_duration = sum(durations) / \
                    len(durations) if durations else 0.0
                avg_cpu = sum(cpu_usages) / \
                    len(cpu_usages) if cpu_usages else 0.0
                avg_memory = sum(memory_usages) / \
                    len(memory_usages) if memory_usages else 0.0

                summary['operations'][op_name] = {
                    'count': len(metrics),
                    'total_duration': sum(durations),
                    'avg_duration': avg_duration,
                    'min_duration': min(durations) if durations else 0.0,
                    'max_duration': max(durations) if durations else 0.0,
                    'std_duration': 0.0,  # Not available without numpy
                    'avg_cpu_percent': avg_cpu,
                    'avg_memory_mb': avg_memory,
                    'peak_memory_mb': max(memory_usages) if memory_usages else 0.0,
                    'throughput_ops_per_sec': len(metrics) / sum(durations) if sum(durations) > 0 else 0.0
                }

        summary['total_duration'] = sum(
            op_data['total_duration']
            for op_data in summary['operations'].values()
        )

        return summary

    def save_metrics(self, filepath: Path):
        """Save metrics to file"""
        filepath.parent.mkdir(parents=True, exist_ok=True)

        metrics_data = {
            'metrics': [asdict(m) for m in self.metrics],
            'summary': self.get_summary(),
            'system_info': get_system_info(),
            'timestamp': datetime.now().isoformat()
        }

        with open(filepath, 'w') as f:
            json.dump(metrics_data, f, indent=2, default=str)

    def reset(self):
        """Reset all metrics"""
        self.metrics.clear()


class OperationContext:
    """Context manager for performance monitoring"""

    def __init__(self, monitor: PerformanceMonitor, operation_name: str):
        self.monitor = monitor
        self.operation_name = operation_name
        self.start_time = None
        self.start_cpu = None
        self.start_memory = None

    def __enter__(self):
        self.start_time = time.time()

        if self.monitor.process and HAS_PSUTIL:
            try:
                # Get initial CPU reading
                self.monitor.process.cpu_percent()  # Initialize
                time.sleep(0.01)  # Small delay for accurate reading
                self.start_cpu = self.monitor.process.cpu_percent()
                self.start_memory = self.monitor.process.memory_info().rss / 1024 / 1024
            except Exception as e:
                logging.debug(f"Performance monitoring error: {e}")
                self.start_cpu = 0.0
                self.start_memory = 0.0
        else:
            self.start_cpu = 0.0
            self.start_memory = 0.0

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time

        if self.monitor.process and HAS_PSUTIL:
            try:
                end_cpu = self.monitor.process.cpu_percent()
                end_memory = self.monitor.process.memory_info().rss / 1024 / 1024
            except Exception as e:
                logging.debug(f"Performance monitoring error: {e}")
                end_cpu = 0.0
                end_memory = self.start_memory
        else:
            end_cpu = 0.0
            end_memory = self.start_memory

        metric = PerformanceMetrics(
            operation=self.operation_name,
            duration_seconds=duration,
            cpu_percent=(self.start_cpu + end_cpu) /
            2 if self.start_cpu > 0 and end_cpu > 0 else 0.0,
            memory_mb=max(self.start_memory, end_memory),
            timestamp=self.start_time,
            additional_data={'exception': exc_type is not None}
        )

        self.monitor.record_metric(metric)


def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    info = {
        'platform': platform.platform(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'architecture': platform.architecture(),
        'machine': platform.machine(),
        'node': platform.node(),
        'system': platform.system(),
        'timestamp': datetime.now().isoformat()
    }

    if HAS_PSUTIL:
        try:
            vm = psutil.virtual_memory()
            info.update({
                'cpu_count_physical': psutil.cpu_count(logical=False),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'total_memory_gb': round(vm.total / 1024 / 1024 / 1024, 2),
                'available_memory_gb': round(vm.available / 1024 / 1024 / 1024, 2),
                'memory_percent_used': vm.percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            })

            # Disk information
            try:
                disk = psutil.disk_usage('/')
                info['disk_total_gb'] = round(
                    disk.total / 1024 / 1024 / 1024, 2)
                info['disk_used_gb'] = round(disk.used / 1024 / 1024 / 1024, 2)
                info['disk_free_gb'] = round(disk.free / 1024 / 1024 / 1024, 2)
            except:
                pass

        except Exception as e:
            logging.debug(f"System info error: {e}")
            info.update({
                'cpu_count': 'unknown',
                'total_memory_gb': 'unknown',
                'psutil_error': str(e)
            })
    else:
        info.update({
            'cpu_count': 'psutil_not_available',
            'total_memory_gb': 'psutil_not_available'
        })

    return info


def compute_hash(data: Union[str, bytes, Dict, List, Any]) -> str:
    """Compute SHA256 hash of data with enhanced type support"""
    if hasattr(data, '__dict__'):
        # Handle dataclass or custom objects
        data = asdict(data) if hasattr(
            data, '__dataclass_fields__') else data.__dict__

    if isinstance(data, (dict, list)):
        data = json.dumps(data, sort_keys=True, default=str)

    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        data = str(data).encode('utf-8')

    return hashlib.sha256(data).hexdigest()


def generate_secure_random(num_bytes: int = 32) -> bytes:
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(num_bytes)


def generate_secure_id(prefix: str = "", length: int = 16) -> str:
    """Generate secure random ID with optional prefix"""
    random_part = secrets.token_hex(length // 2)
    timestamp = int(time.time() * 1000) % 1000000  # Last 6 digits of timestamp

    if prefix:
        return f"{prefix}_{timestamp}_{random_part}"
    return f"{timestamp}_{random_part}"


def save_results(results: Dict[str, Any], filepath: Path):
    """Save results to JSON file with comprehensive serialization"""
    filepath.parent.mkdir(parents=True, exist_ok=True)

    def convert_to_serializable(obj):
        """Enhanced serialization with better type handling"""
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        elif hasattr(obj, '__dict__'):
            return {
                '_type': obj.__class__.__name__,
                **{k: convert_to_serializable(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
            }
        elif isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [convert_to_serializable(item) for item in obj]
        elif HAS_NUMPY and isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        elif HAS_NUMPY and isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'isoformat'):  # datetime-like objects
            return obj.isoformat()
        elif callable(obj):
            return f"<function:{obj.__name__}>"
        else:
            try:
                json.dumps(obj)  # Test if serializable
                return obj
            except:
                return str(obj)

    # Add metadata
    enhanced_results = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'system_info': get_system_info(),
            'file_path': str(filepath)
        },
        'data': convert_to_serializable(results)
    }

    # Save main results file
    with open(filepath, 'w') as f:
        json.dump(enhanced_results, f, indent=2, default=str)

    # Create summary file
    summary_path = filepath.parent / f"{filepath.stem}_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(create_results_summary(results))

    logging.info(f"Results saved to {filepath}")
    logging.info(f"Summary saved to {summary_path}")


def create_results_summary(results: Dict[str, Any]) -> str:
    """Create comprehensive human-readable summary of results"""
    summary = []
    summary.append("=" * 80)
    summary.append("CRYPTOGRAPHIC VOTING SYSTEM - RESULTS SUMMARY")
    summary.append("=" * 80)
    summary.append(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary.append("")

    # System Information
    if 'system_info' in results:
        summary.append("SYSTEM INFORMATION:")
        sys_info = results['system_info']
        if isinstance(sys_info, dict):
            for key, value in sys_info.items():
                if key in ['platform', 'python_version', 'cpu_count_logical', 'total_memory_gb']:
                    summary.append(f"  {key}: {value}")
        summary.append("")

    # Performance Metrics
    if 'performance_metrics' in results:
        summary.append("PERFORMANCE METRICS:")
        metrics = results['performance_metrics']
        if isinstance(metrics, dict):
            for metric, value in metrics.items():
                if isinstance(value, float):
                    summary.append(f"  {metric}: {value:.4f}")
                else:
                    summary.append(f"  {metric}: {value}")
        summary.append("")

    # Benchmark Results
    if 'benchmarks' in results:
        summary.append("BENCHMARK RESULTS:")
        benchmarks = results['benchmarks']
        if isinstance(benchmarks, dict):
            for bench_name, bench_data in benchmarks.items():
                summary.append(f"  {bench_name}:")
                if isinstance(bench_data, dict):
                    for key, value in bench_data.items():
                        if isinstance(value, float):
                            summary.append(f"    {key}: {value:.4f}")
                        elif isinstance(value, dict) and 'avg_time' in value:
                            summary.append(
                                f"    {key}: {value['avg_time']:.4f}s avg")
                        else:
                            summary.append(f"    {key}: {value}")
        summary.append("")

    # Integrity Checks
    if 'integrity_checks' in results:
        summary.append("INTEGRITY CHECKS:")
        for check, passed in results['integrity_checks'].items():
            status = " PASSED" if passed else " FAILED"
            summary.append(f"  {check}: {status}")
        summary.append("")

    # Election Results
    if 'mpc_result' in results and results['mpc_result']:
        summary.append("ELECTION TALLY:")
        mpc_result = results['mpc_result']
        if isinstance(mpc_result, dict) and 'tally' in mpc_result:
            tally = mpc_result['tally']
            total_votes = sum(tally) if isinstance(tally, list) else 0
            for i, count in enumerate(tally):
                percentage = (count / total_votes *
                              100) if total_votes > 0 else 0
                summary.append(
                    f"  Candidate {i}: {count} votes ({percentage:.1f}%)")
            summary.append(f"  Total Votes: {total_votes}")
        summary.append("")

    # Final Verification
    if 'final_verification' in results:
        verification = results['final_verification']
        if isinstance(verification, dict):
            summary.append("FINAL VERIFICATION:")
            overall = verification.get('overall_verification', 'UNKNOWN')
            summary.append(f"  Overall Status: {overall}")

            checks = [
                ('all_signatures_valid', 'Signature Verification'),
                ('all_proofs_valid', 'ZK Proof Verification'),
                ('mpc_tally_correct', 'MPC Tally Verification'),
                ('tally_proof_valid', 'Tally Proof Verification')
            ]

            for key, label in checks:
                if key in verification:
                    status = " PASSED" if verification[key] else " FAILED"
                    summary.append(f"  {label}: {status}")
        summary.append("")

    summary.append("=" * 80)
    return "\n".join(summary)


def create_performance_report(metrics: PerformanceMonitor) -> str:
    """Create detailed performance report from metrics"""
    summary = metrics.get_summary()

    report = []
    report.append("=" * 80)
    report.append("CRYPTOGRAPHIC VOTING SYSTEM - PERFORMANCE REPORT")
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Operations: {summary.get('total_operations', 0)}")
    report.append(f"Total Duration: {summary.get('total_duration', 0):.3f}s")
    report.append("")

    if 'operations' in summary and summary['operations']:
        report.append("OPERATION BREAKDOWN:")
        report.append("-" * 60)

        for op_name, op_data in summary['operations'].items():
            report.append(f"\n{op_name.upper()}:")
            report.append(f"  Executions: {op_data['count']}")
            report.append(f"  Total Time: {op_data['total_duration']:.3f}s")
            report.append(f"  Average Time: {op_data['avg_duration']:.4f}s")
            report.append(
                f"  Min/Max Time: {op_data['min_duration']:.4f}s / {op_data['max_duration']:.4f}s")
            report.append(f"  Std Deviation: {op_data['std_duration']:.4f}s")
            report.append(
                f"  Throughput: {op_data['throughput_ops_per_sec']:.2f} ops/sec")

            if op_data['avg_cpu_percent'] > 0:
                report.append(
                    f"  Average CPU: {op_data['avg_cpu_percent']:.1f}%")
            if op_data['avg_memory_mb'] > 0:
                report.append(
                    f"  Average Memory: {op_data['avg_memory_mb']:.1f} MB")
                report.append(
                    f"  Peak Memory: {op_data['peak_memory_mb']:.1f} MB")
    else:
        report.append("No performance data available.")

    report.append("")
    report.append("=" * 80)
    return "\n".join(report)


def validate_environment() -> List[str]:
    """Validate system environment and return list of issues"""
    issues = []

    # Check Python version
    import sys
    if sys.version_info < (3, 8):
        issues.append(
            f"Python version {sys.version} is too old. Requires Python 3.8+")

    # Check for required directories
    required_dirs = ['circuits', 'keys', 'logs', 'results']
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                logging.info(f"Created directory: {dir_path}")
            except Exception as e:
                issues.append(f"Cannot create directory {dir_name}: {e}")

    # Check for optional but recommended commands
    recommended_commands = ['node', 'npm']
    for cmd in recommended_commands:
        if not check_command_exists(cmd):
            issues.append(
                f"Recommended command not found: {cmd} (needed for ZK circuits)")

    # Check critical Python modules
    critical_modules = ['asyncio', 'hashlib', 'json', 'logging']
    for module in critical_modules:
        try:
            __import__(module)
        except ImportError:
            issues.append(f"Critical Python module missing: {module}")

    # Check optional modules
    if not HAS_PSUTIL:
        issues.append(
            "psutil not available - performance monitoring will be limited")

    if not HAS_NUMPY:
        issues.append("numpy not available - using basic statistics")

    return issues


def check_command_exists(command: str) -> bool:
    """Check if command exists in system PATH"""
    import shutil
    return shutil.which(command) is not None


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds*1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.1f}s"


def format_bytes(bytes_value: int) -> str:
    """Format bytes in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f}{unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f}PB"


# Additional utility functions for test compatibility
def load_config():
    """Load system configuration - placeholder for test compatibility"""
    from dataclasses import dataclass

    @dataclass
    class MockConfig:
        num_candidates: int = 3
        num_mpc_parties: int = 5

        @dataclass
        class ZKConfig:
            circuit_name: str = "ballot_validity"
            trusted_setup: bool = True

        @dataclass
        class PQConfig:
            kyber_variant: str = "kyber768"
            dilithium_variant: str = "dilithium3"

        zk_config: ZKConfig = ZKConfig()
        pq_config: PQConfig = PQConfig()

    return MockConfig()


# Export all public functions and classes
__all__ = [
    'PerformanceMetrics',
    'PerformanceMonitor',
    'OperationContext',
    'setup_logging',
    'get_system_info',
    'compute_hash',
    'generate_secure_random',
    'generate_secure_id',
    'save_results',
    'create_results_summary',
    'create_performance_report',
    'validate_environment',
    'check_command_exists',
    'format_duration',
    'format_bytes',
    'load_config',
    'HAS_PSUTIL',
    'HAS_NUMPY'
]
