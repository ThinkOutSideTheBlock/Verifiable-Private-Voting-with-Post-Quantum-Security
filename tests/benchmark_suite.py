#!/usr/bin/env python3
"""
Comprehensive Benchmark Suite for Academic Publication
Measures performance across all cryptographic components:
- Post-Quantum Key Generation, Encryption, Signatures
- Zero-Knowledge Proof Generation and Verification
- MPC Secret Sharing and Tally Computation
- End-to-End System Performance
"""

from mpc.mpc_voting import ProductionMPCProtocol
from zk.zk_proofs import ZKProofSystem, CircuitConfig
from pq.pq_crypto import PostQuantumCryptoSystem
from integrated_voting_system import IntegratedVotingSystem
import asyncio
import sys
import time
import json
import statistics
from pathlib import Path
from typing import List, Dict, Any, Tuple
import logging
import psutil
import os

sys.path.insert(0, str(Path(__file__).parent.parent))


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tests/logs/benchmark.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class BenchmarkSuite:
    """Comprehensive benchmark suite for academic publication"""

    def __init__(self):
        self.results = {
            'pq_crypto': {},
            'zk_proofs': {},
            'mpc': {},
            'integrated_system': {},
            'system_info': self._get_system_info()
        }

    def _get_system_info(self) -> Dict[str, Any]:
        """Collect system information for reproducibility"""
        return {
            'cpu_count': psutil.cpu_count(logical=False),
            'cpu_count_logical': psutil.cpu_count(logical=True),
            'cpu_freq': psutil.cpu_freq().max if psutil.cpu_freq() else 'N/A',
            'ram_total_gb': psutil.virtual_memory().total / (1024**3),
            'python_version': sys.version.split()[0],
            'platform': sys.platform
        }

    def measure_time_and_memory(self, func, *args, **kwargs) -> Tuple[Any, float, float]:
        """Measure execution time and memory usage"""
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024  # MB

        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time

        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        mem_delta = mem_after - mem_before

        return result, elapsed_time, mem_delta

    async def measure_async_time_and_memory(self, coro) -> Tuple[Any, float, float]:
        """Measure async execution time and memory usage"""
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024  # MB

        start_time = time.time()
        result = await coro
        elapsed_time = time.time() - start_time

        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        mem_delta = mem_after - mem_before

        return result, elapsed_time, mem_delta

    def run_multiple_trials(self, func, trials: int = 10, *args, **kwargs) -> Dict[str, float]:
        """Run multiple trials and compute statistics"""
        times = []
        memories = []

        for _ in range(trials):
            _, elapsed, mem_delta = self.measure_time_and_memory(
                func, *args, **kwargs)
            times.append(elapsed)
            memories.append(mem_delta)

        return {
            'mean_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'std_time': statistics.stdev(times) if len(times) > 1 else 0,
            'min_time': min(times),
            'max_time': max(times),
            'mean_memory_mb': statistics.mean(memories),
            'trials': trials
        }

    async def run_multiple_trials_async(self, coro_func, trials: int = 10, *args, **kwargs) -> Dict[str, float]:
        """Run multiple async trials and compute statistics"""
        times = []
        memories = []

        for _ in range(trials):
            _, elapsed, mem_delta = await self.measure_async_time_and_memory(coro_func(*args, **kwargs))
            times.append(elapsed)
            memories.append(mem_delta)

        return {
            'mean_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'std_time': statistics.stdev(times) if len(times) > 1 else 0,
            'min_time': min(times),
            'max_time': max(times),
            'mean_memory_mb': statistics.mean(memories),
            'trials': trials
        }

    async def benchmark_pq_crypto(self):
        """Benchmark post-quantum cryptography operations"""
        logger.info("=" * 80)
        logger.info("BENCHMARKING POST-QUANTUM CRYPTOGRAPHY")
        logger.info("=" * 80)

        pq_system = PostQuantumCryptoSystem(use_hsm=False)
        await pq_system.initialize()

        # 1. Key Generation (ML-KEM-768)
        logger.info("\n[1] ML-KEM-768 Key Generation")
        stats = self.run_multiple_trials(
            lambda: pq_system.kem.generate(), trials=100)
        self.results['pq_crypto']['kem_keygen'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 2. Encapsulation
        logger.info("\n[2] ML-KEM-768 Encapsulation")
        public_key, _ = pq_system.kem.generate()
        stats = self.run_multiple_trials(
            lambda: pq_system.kem.encapsulate(public_key), trials=100)
        self.results['pq_crypto']['kem_encaps'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 3. Decapsulation
        logger.info("\n[3] ML-KEM-768 Decapsulation")
        public_key, private_key = pq_system.kem.generate()
        ciphertext, _ = pq_system.kem.encapsulate(public_key)
        stats = self.run_multiple_trials(
            lambda: pq_system.kem.decapsulate(private_key, ciphertext), trials=100)
        self.results['pq_crypto']['kem_decaps'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 4. Signature Generation (ML-DSA-65)
        logger.info("\n[4] ML-DSA-65 Signature Generation")
        sig_pk, sig_sk = pq_system.signature.generate()
        message = b"test message for signing" * 10
        stats = self.run_multiple_trials(
            lambda: pq_system.signature.sign(sig_sk, message), trials=100)
        self.results['pq_crypto']['sig_sign'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 5. Signature Verification
        logger.info("\n[5] ML-DSA-65 Signature Verification")
        signature = pq_system.signature.sign(sig_sk, message)
        stats = self.run_multiple_trials(lambda: pq_system.signature.verify(
            sig_pk, message, signature), trials=100)
        self.results['pq_crypto']['sig_verify'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 6. Session Establishment
        logger.info("\n[6] Secure Session Establishment")
        cert_alice = pq_system.generate_certificate("alice@example.com")
        cert_bob = pq_system.generate_certificate("bob@example.com")

        async def establish_session():
            return await pq_system.establish_secure_session(cert_alice, cert_bob, "alice@example.com")

        stats = await self.run_multiple_trials_async(establish_session, trials=50)
        self.results['pq_crypto']['session_establishment'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        logger.info("\n Post-Quantum Crypto Benchmarking Complete")

    async def benchmark_zk_proofs(self):
        """Benchmark zero-knowledge proof operations"""
        logger.info("\n" + "=" * 80)
        logger.info("BENCHMARKING ZERO-KNOWLEDGE PROOFS")
        logger.info("=" * 80)

        zk_system = ZKProofSystem()
        await zk_system.initialize()

        # 1. Circuit Compilation
        logger.info("\n[1] Circuit Compilation (3 candidates)")
        circuit_config = CircuitConfig(num_candidates=3)

        start = time.time()
        await zk_system.compile_circuit(circuit_config)
        compile_time = time.time() - start
        self.results['zk_proofs']['circuit_compilation'] = {
            'time': compile_time,
            'num_candidates': 3
        }
        logger.info(f"   Time: {compile_time:.2f}s")

        # 2. Trusted Setup
        logger.info("\n[2] Trusted Setup Ceremony")
        start = time.time()
        await zk_system.run_trusted_setup(circuit_config)
        setup_time = time.time() - start
        self.results['zk_proofs']['trusted_setup'] = {
            'time': setup_time,
            'num_candidates': 3
        }
        logger.info(f"   Time: {setup_time:.2f}s")

        # 3. Proof Generation
        logger.info("\n[3] ZK Proof Generation")
        ballot = [1, 0, 0]
        voter_id = "benchmark_voter"
        election_id = "benchmark_election"

        async def generate_proof():
            return await zk_system.prove_ballot(ballot, voter_id, election_id)

        stats = await self.run_multiple_trials_async(generate_proof, trials=20)
        self.results['zk_proofs']['proof_generation'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 4. Proof Verification
        logger.info("\n[4] ZK Proof Verification")
        proof = await zk_system.prove_ballot(ballot, voter_id, election_id)

        async def verify_proof():
            return await zk_system.verify(proof)

        stats = await self.run_multiple_trials_async(verify_proof, trials=50)
        self.results['zk_proofs']['proof_verification'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 5. Proof Size
        proof_size = len(json.dumps(proof.proof_data))
        self.results['zk_proofs']['proof_size_bytes'] = proof_size
        logger.info(
            f"\n[5] Proof Size: {proof_size} bytes ({proof_size/1024:.2f} KB)")

        logger.info("\n Zero-Knowledge Proof Benchmarking Complete")

    async def benchmark_mpc(self):
        """Benchmark MPC operations"""
        logger.info("\n" + "=" * 80)
        logger.info("BENCHMARKING MULTI-PARTY COMPUTATION")
        logger.info("=" * 80)

        # 1. Secret Sharing
        logger.info("\n[1] Feldman VSS Secret Sharing (3 parties)")
        mpc_protocol = ProductionMPCProtocol(
            num_parties=3, threshold=2, num_candidates=3)

        def share_secret():
            party = mpc_protocol.parties[0]
            secret = 42
            return party._share_secret(secret)

        stats = self.run_multiple_trials(share_secret, trials=100)
        self.results['mpc']['secret_sharing'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 2. Share Verification
        logger.info("\n[2] Share Verification")
        party = mpc_protocol.parties[0]
        shares, commitments = party._share_secret(42)

        def verify_share():
            return party._verify_share(shares[0], 1, commitments)

        stats = self.run_multiple_trials(verify_share, trials=100)
        self.results['mpc']['share_verification'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 3. Threshold Reconstruction
        logger.info("\n[3] Threshold Secret Reconstruction")

        def reconstruct_secret():
            return party._reconstruct_secret(shares[:2])

        stats = self.run_multiple_trials(reconstruct_secret, trials=100)
        self.results['mpc']['secret_reconstruction'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        # 4. Ballot Distribution
        logger.info("\n[4] Secure Ballot Distribution")
        ballot = [1, 0, 0]
        voter_id = "benchmark_voter"

        async def distribute_ballot():
            return await mpc_protocol.secure_ballot_distribution(ballot, voter_id)

        stats = await self.run_multiple_trials_async(distribute_ballot, trials=20)
        self.results['mpc']['ballot_distribution'] = stats
        logger.info(
            f"   Mean: {stats['mean_time']*1000:.2f}ms (±{stats['std_time']*1000:.2f}ms)")

        logger.info("\n MPC Benchmarking Complete")

    async def benchmark_integrated_system(self):
        """Benchmark end-to-end integrated system performance"""
        logger.info("\n" + "=" * 80)
        logger.info("BENCHMARKING INTEGRATED SYSTEM (END-TO-END)")
        logger.info("=" * 80)

        # Test with different voter counts
        voter_counts = [10, 25, 50, 100]
        scalability_results = []

        for num_voters in voter_counts:
            logger.info(f"\n[Scaling Test] {num_voters} voters")

            system = IntegratedVotingSystem(
                num_mpc_parties=3,
                num_candidates=3,
                election_id=f"benchmark_{num_voters}"
            )

            # Initialization
            start = time.time()
            await system.initialize()
            init_time = time.time() - start
            logger.info(f"   Initialization: {init_time:.2f}s")

            # Registration
            start = time.time()
            for i in range(num_voters):
                await system.register_voter(f"voter_{i}@example.com")
            registration_time = time.time() - start
            logger.info(
                f"   Registration: {registration_time:.2f}s ({num_voters/registration_time:.2f} voters/s)")

            # Ballot Casting
            start = time.time()
            for i in range(num_voters):
                ballot = [1, 0, 0] if i % 2 == 0 else [0, 1, 0]
                await system.cast_ballot(f"voter_{i}@example.com", ballot)
            casting_time = time.time() - start
            logger.info(
                f"   Ballot Casting: {casting_time:.2f}s ({num_voters/casting_time:.2f} ballots/s)")

            # Tally Computation
            start = time.time()
            tally_result = await system.compute_tally()
            tally_time = time.time() - start
            logger.info(f"   Tally Computation: {tally_time:.2f}s")

            total_time = init_time + registration_time + casting_time + tally_time

            scalability_results.append({
                'num_voters': num_voters,
                'init_time': init_time,
                'registration_time': registration_time,
                'registration_throughput': num_voters / registration_time,
                'casting_time': casting_time,
                'casting_throughput': num_voters / casting_time,
                'tally_time': tally_time,
                'total_time': total_time,
                'avg_time_per_voter': (registration_time + casting_time) / num_voters
            })

        self.results['integrated_system']['scalability'] = scalability_results

        logger.info("\n Integrated System Benchmarking Complete")

    async def run_all_benchmarks(self):
        """Run complete benchmark suite"""
        logger.info("\n" + "=" * 80)
        logger.info("COMPREHENSIVE BENCHMARK SUITE FOR ACADEMIC PUBLICATION")
        logger.info("=" * 80)
        logger.info(f"\nSystem: {self.results['system_info']['cpu_count']} CPU cores, "
                    f"{self.results['system_info']['ram_total_gb']:.1f} GB RAM")
        logger.info("=" * 80 + "\n")

        total_start = time.time()

        # Run all benchmark categories
        await self.benchmark_pq_crypto()
        await self.benchmark_zk_proofs()
        await self.benchmark_mpc()
        await self.benchmark_integrated_system()

        total_time = time.time() - total_start

        logger.info("\n" + "=" * 80)
        logger.info(f"BENCHMARKING COMPLETE - Total time: {total_time:.2f}s")
        logger.info("=" * 80)

        # Save results
        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save benchmark results to JSON"""
        results_dir = Path(__file__).parent / 'results'
        results_dir.mkdir(exist_ok=True)

        results_file = results_dir / 'benchmark_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"\n Results saved to: {results_file}")

    def print_summary(self):
        """Print publication-ready summary"""
        logger.info("\n" + "=" * 80)
        logger.info("PERFORMANCE SUMMARY FOR PUBLICATION")
        logger.info("=" * 80)

        # Post-Quantum Crypto
        logger.info("\n📈 Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65):")
        pq = self.results['pq_crypto']
        logger.info(
            f"   Key Generation:    {pq['kem_keygen']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Encapsulation:     {pq['kem_encaps']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Decapsulation:     {pq['kem_decaps']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Signature:         {pq['sig_sign']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Verification:      {pq['sig_verify']['mean_time']*1000:.2f} ms")

        # Zero-Knowledge Proofs
        logger.info("\n📈 Zero-Knowledge Proofs (Groth16, BN254):")
        zk = self.results['zk_proofs']
        logger.info(
            f"   Setup Time:        {zk['trusted_setup']['time']:.2f} s")
        logger.info(
            f"   Proof Generation:  {zk['proof_generation']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Proof Verification: {zk['proof_verification']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Proof Size:        {zk['proof_size_bytes']/1024:.2f} KB")

        # MPC
        logger.info("\n📈 Multi-Party Computation (Feldman VSS, PBFT):")
        mpc = self.results['mpc']
        logger.info(
            f"   Secret Sharing:    {mpc['secret_sharing']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Share Verification: {mpc['share_verification']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Reconstruction:    {mpc['secret_reconstruction']['mean_time']*1000:.2f} ms")
        logger.info(
            f"   Ballot Distribution: {mpc['ballot_distribution']['mean_time']*1000:.2f} ms")

        # Integrated System
        logger.info("\n📈 End-to-End System Performance:")
        scalability = self.results['integrated_system']['scalability']
        for result in scalability:
            logger.info(f"   {result['num_voters']} voters: "
                        f"{result['total_time']:.2f}s total, "
                        f"{result['casting_throughput']:.2f} ballots/s")

        logger.info("\n" + "=" * 80)


async def main():
    """Main benchmark execution"""
    benchmark = BenchmarkSuite()
    await benchmark.run_all_benchmarks()


if __name__ == "__main__":
    asyncio.run(main())
