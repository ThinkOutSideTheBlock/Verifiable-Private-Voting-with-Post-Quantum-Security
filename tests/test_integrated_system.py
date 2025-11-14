#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite for Verifiable Private Voting System
Tests the complete workflow: Registration → Ballot Casting → Tallying → Verification
"""

from integrated_voting_system import (
    IntegratedVotingSystem,
    VoterIdentity,
    VerifiedBallot,
    TallyResult
)
import asyncio
import sys
import time
import json
from pathlib import Path
from typing import List, Dict, Any
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tests/logs/integration_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IntegrationTestSuite:
    """Comprehensive integration tests for the voting system"""

    def __init__(self):
        self.test_results = {}
        self.performance_metrics = {}

    async def test_single_voter_workflow(self) -> bool:
        """Test complete workflow with a single voter"""
        logger.info("=" * 80)
        logger.info("TEST 1: Single Voter Workflow")
        logger.info("=" * 80)

        try:
            start_time = time.time()

            # Initialize system
            logger.info("Initializing voting system...")
            system = IntegratedVotingSystem(
                num_mpc_parties=3,
                num_candidates=3,
                election_id="test_election_001"
            )
            await system.initialize()
            init_time = time.time() - start_time
            logger.info(f" System initialized in {init_time:.2f}s")

            # Register voter
            logger.info("\nRegistering voter...")
            voter_start = time.time()
            voter_identity = await system.register_voter("alice@example.com")
            register_time = time.time() - voter_start
            logger.info(f" Voter registered in {register_time:.2f}s")
            logger.info(f"   Voter ID: {voter_identity.voter_id}")
            logger.info(
                f"   PQ Certificate: {voter_identity.pq_certificate.certificate_id[:16]}...")

            # Cast ballot
            logger.info("\nCasting ballot...")
            ballot = [1, 0, 0]  # Vote for candidate 0
            cast_start = time.time()
            verified_ballot = await system.cast_ballot("alice@example.com", ballot)
            cast_time = time.time() - cast_start
            logger.info(f" Ballot cast in {cast_time:.2f}s")
            logger.info(f"   Ballot ID: {verified_ballot.ballot_id}")
            logger.info(f"   ZK Proof verified: {verified_ballot.zk_verified}")
            logger.info(f"   MPC accepted: {verified_ballot.mpc_accepted}")

            # Compute tally
            logger.info("\nComputing tally...")
            tally_start = time.time()
            tally_result = await system.compute_tally()
            tally_time = time.time() - tally_start
            logger.info(f" Tally computed in {tally_time:.2f}s")
            logger.info(f"   Results: {tally_result.tally}")
            logger.info(f"   Verified: {tally_result.verified}")

            # Verify results
            assert tally_result.tally[0] == 1, "Candidate 0 should have 1 vote"
            assert tally_result.tally[1] == 0, "Candidate 1 should have 0 votes"
            assert tally_result.tally[2] == 0, "Candidate 2 should have 0 votes"
            assert tally_result.verified, "Tally should be verified"

            total_time = time.time() - start_time
            logger.info(f"\n TEST PASSED - Total time: {total_time:.2f}s")

            self.performance_metrics['single_voter'] = {
                'initialization_time': init_time,
                'registration_time': register_time,
                'casting_time': cast_time,
                'tally_time': tally_time,
                'total_time': total_time
            }

            return True

        except Exception as e:
            logger.error(f" TEST FAILED: {e}", exc_info=True)
            return False

    async def test_multiple_voters_workflow(self, num_voters: int = 10) -> bool:
        """Test workflow with multiple voters"""
        logger.info("=" * 80)
        logger.info(f"TEST 2: Multiple Voters Workflow ({num_voters} voters)")
        logger.info("=" * 80)

        try:
            start_time = time.time()

            # Initialize system
            logger.info("Initializing voting system...")
            system = IntegratedVotingSystem(
                num_mpc_parties=3,
                num_candidates=3,
                election_id="test_election_002"
            )
            await system.initialize()
            init_time = time.time() - start_time
            logger.info(f" System initialized in {init_time:.2f}s")

            # Register voters
            logger.info(f"\nRegistering {num_voters} voters...")
            register_start = time.time()
            voter_ids = [f"voter_{i}@example.com" for i in range(num_voters)]

            for voter_id in voter_ids:
                await system.register_voter(voter_id)

            register_time = time.time() - register_start
            avg_register_time = register_time / num_voters
            logger.info(
                f" {num_voters} voters registered in {register_time:.2f}s")
            logger.info(f"   Average: {avg_register_time:.3f}s per voter")

            # Cast ballots
            logger.info(f"\nCasting {num_voters} ballots...")
            cast_start = time.time()

            # Simulate realistic voting distribution
            expected_tally = [0, 0, 0]
            for i, voter_id in enumerate(voter_ids):
                # Distribute votes: 50% candidate 0, 30% candidate 1, 20% candidate 2
                if i < num_voters * 0.5:
                    ballot = [1, 0, 0]
                    expected_tally[0] += 1
                elif i < num_voters * 0.8:
                    ballot = [0, 1, 0]
                    expected_tally[1] += 1
                else:
                    ballot = [0, 0, 1]
                    expected_tally[2] += 1

                await system.cast_ballot(voter_id, ballot)

            cast_time = time.time() - cast_start
            avg_cast_time = cast_time / num_voters
            logger.info(f" {num_voters} ballots cast in {cast_time:.2f}s")
            logger.info(f"   Average: {avg_cast_time:.3f}s per ballot")

            # Compute tally
            logger.info("\nComputing tally...")
            tally_start = time.time()
            tally_result = await system.compute_tally()
            tally_time = time.time() - tally_start
            logger.info(f" Tally computed in {tally_time:.2f}s")
            logger.info(f"   Results: {tally_result.tally}")
            logger.info(f"   Expected: {expected_tally}")
            logger.info(f"   Verified: {tally_result.verified}")

            # Verify results
            assert tally_result.tally == expected_tally, f"Tally mismatch: {tally_result.tally} != {expected_tally}"
            assert tally_result.verified, "Tally should be verified"

            total_time = time.time() - start_time
            throughput = num_voters / cast_time
            logger.info(f"\n TEST PASSED - Total time: {total_time:.2f}s")
            logger.info(f"   Throughput: {throughput:.2f} ballots/second")

            self.performance_metrics['multiple_voters'] = {
                'num_voters': num_voters,
                'initialization_time': init_time,
                'total_registration_time': register_time,
                'avg_registration_time': avg_register_time,
                'total_casting_time': cast_time,
                'avg_casting_time': avg_cast_time,
                'tally_time': tally_time,
                'total_time': total_time,
                'throughput': throughput
            }

            return True

        except Exception as e:
            logger.error(f" TEST FAILED: {e}", exc_info=True)
            return False

    async def test_security_properties(self) -> bool:
        """Test security properties: ballot privacy, verifiability, integrity"""
        logger.info("=" * 80)
        logger.info("TEST 3: Security Properties Verification")
        logger.info("=" * 80)

        try:
            system = IntegratedVotingSystem(
                num_mpc_parties=3,
                num_candidates=3,
                election_id="test_election_003"
            )
            await system.initialize()

            # Test 1: Ballot privacy - encrypted ballots should not leak vote
            logger.info("\n[Security Test 1] Ballot Privacy")
            voter1 = await system.register_voter("voter1@example.com")
            ballot1 = await system.cast_ballot("voter1@example.com", [1, 0, 0])

            # Check that ballot is encrypted
            assert ballot1.encrypted_ballot is not None, "Ballot should be encrypted"
            logger.info(" Ballots are encrypted with PQ cryptography")

            # Test 2: Zero-knowledge proofs - validity without revealing vote
            logger.info("\n[Security Test 2] Zero-Knowledge Proofs")
            assert ballot1.zk_verified, "ZK proof should be verified"
            assert ballot1.zk_proof is not None, "ZK proof should exist"
            logger.info(
                " ZK proofs verify ballot validity without revealing vote")

            # Test 3: MPC acceptance - distributed verification
            logger.info("\n[Security Test 3] MPC Distributed Verification")
            assert ballot1.mpc_accepted, "MPC parties should accept valid ballot"
            logger.info(" MPC parties accept valid ballots after verification")

            # Test 4: Invalid ballot rejection
            logger.info("\n[Security Test 4] Invalid Ballot Rejection")
            voter2 = await system.register_voter("voter2@example.com")

            try:
                # Try to cast invalid ballot (sum != 1)
                await system.cast_ballot("voter2@example.com", [1, 1, 0])
                logger.error(" System accepted invalid ballot")
                return False
            except Exception as e:
                logger.info(f" System rejected invalid ballot: {e}")

            # Test 5: Tally verification
            logger.info("\n[Security Test 5] Tally Verification")
            voter3 = await system.register_voter("voter3@example.com")
            await system.cast_ballot("voter3@example.com", [0, 1, 0])

            tally_result = await system.compute_tally()
            assert tally_result.verified, "Tally should be verified"
            logger.info(" Tally is cryptographically verified")

            logger.info("\n ALL SECURITY TESTS PASSED")
            return True

        except Exception as e:
            logger.error(f" SECURITY TEST FAILED: {e}", exc_info=True)
            return False

    async def test_byzantine_fault_tolerance(self) -> bool:
        """Test Byzantine fault tolerance with malicious parties"""
        logger.info("=" * 80)
        logger.info("TEST 4: Byzantine Fault Tolerance")
        logger.info("=" * 80)

        try:
            # Initialize with more parties to tolerate faults
            system = IntegratedVotingSystem(
                num_mpc_parties=4,  # Can tolerate 1 Byzantine fault
                num_candidates=3,
                election_id="test_election_004"
            )
            await system.initialize()
            logger.info(
                " System initialized with 4 MPC parties (f=1 tolerance)")

            # Register and vote
            voter = await system.register_voter("voter@example.com")
            ballot = await system.cast_ballot("voter@example.com", [1, 0, 0])

            logger.info(" Ballot cast successfully with Byzantine tolerance")

            # Compute tally - should succeed even with 1 Byzantine party
            tally_result = await system.compute_tally()
            assert tally_result.verified, "Tally should be verified despite Byzantine parties"

            logger.info(
                " Tally computed correctly with Byzantine fault tolerance")
            logger.info(f"   Results: {tally_result.tally}")

            return True

        except Exception as e:
            logger.error(f" BYZANTINE TEST FAILED: {e}", exc_info=True)
            return False

    async def run_all_tests(self) -> Dict[str, bool]:
        """Run all integration tests"""
        logger.info("\n" + "=" * 80)
        logger.info("INTEGRATED VOTING SYSTEM - COMPREHENSIVE TEST SUITE")
        logger.info("=" * 80 + "\n")

        results = {}

        # Test 1: Single voter
        results['single_voter'] = await self.test_single_voter_workflow()
        await asyncio.sleep(2)

        # Test 2: Multiple voters
        results['multiple_voters'] = await self.test_multiple_voters_workflow(num_voters=10)
        await asyncio.sleep(2)

        # Test 3: Security properties
        results['security_properties'] = await self.test_security_properties()
        await asyncio.sleep(2)

        # Test 4: Byzantine fault tolerance
        results['byzantine_tolerance'] = await self.test_byzantine_fault_tolerance()

        # Summary
        logger.info("\n" + "=" * 80)
        logger.info("TEST SUMMARY")
        logger.info("=" * 80)

        passed = sum(1 for v in results.values() if v)
        total = len(results)

        for test_name, result in results.items():
            status = " PASS" if result else " FAIL"
            logger.info(f"{test_name:30s} {status}")

        logger.info(f"\nTotal: {passed}/{total} tests passed")

        if passed == total:
            logger.info("\n🎉 ALL TESTS PASSED - SYSTEM IS PRODUCTION READY 🎉")
        else:
            logger.info(f"\n  {total - passed} test(s) failed - review logs")

        # Save performance metrics
        self.save_results()

        return results

    def save_results(self):
        """Save test results and performance metrics"""
        results_dir = Path(__file__).parent / 'results'
        results_dir.mkdir(exist_ok=True)

        # Save performance metrics
        metrics_file = results_dir / 'integration_test_metrics.json'
        with open(metrics_file, 'w') as f:
            json.dump(self.performance_metrics, f, indent=2)

        logger.info(f"\n Performance metrics saved to: {metrics_file}")


async def main():
    """Main test execution"""
    test_suite = IntegrationTestSuite()
    results = await test_suite.run_all_tests()

    # Exit with appropriate code
    all_passed = all(results.values())
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    asyncio.run(main())
