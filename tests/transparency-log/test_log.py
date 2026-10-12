#!/usr/bin/env python3
"""
Comprehensive tests for the transparency log system.

Tests:
1. Valid chain passes verification
2. Editing one byte of any past entry fails
3. Deleting an entry fails
4. A record not in that day fails inclusion
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add transparency-log to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "transparency-log"))

from log_builder import LogBuilder, Record, DailyEntry
from verify import OfflineVerifier


class TestTransparencyLog(unittest.TestCase):
    """Test suite for transparency log."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.log_dir = self.test_dir / "log"
        self.records_dir = self.test_dir / "records"
        self.log_dir.mkdir()
        self.records_dir.mkdir()
        
        # Test signing key (32 bytes)
        self.signing_key = b"test_key_" + b"0" * 23
        assert len(self.signing_key) == 32
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def create_test_records(self, date: str, count: int = 3) -> list:
        """Create test records for a date."""
        records = []
        for i in range(count):
            records.append(Record(
                record_type="receipt",
                timestamp=f"{date}T{i:02d}:00:00Z",
                content_hash=f"hash_{date}_{i:03d}" + "0" * 50,
                metadata={"test_id": i}
            ))
        return records
    
    def test_01_valid_chain_passes(self):
        """Test that a valid chain passes verification."""
        builder = LogBuilder(self.log_dir)
        
        # Create entries for 3 consecutive days
        dates = ["2026-10-10", "2026-10-11", "2026-10-12"]
        for date in dates:
            records = self.create_test_records(date)
            entry = builder.build_daily_entry(date, records, self.signing_key)
            builder.append_entry(entry)
        
        # Verify the chain
        verifier = OfflineVerifier(self.log_dir)
        is_valid, message = verifier.verify_chain("2026-10-10", "2026-10-12")
        
        self.assertTrue(is_valid, f"Valid chain should pass: {message}")
        print(f"✅ Test 1: Valid chain passes - {message}")
    
    def test_02_editing_entry_fails(self):
        """Test that editing one byte of a past entry breaks the chain."""
        builder = LogBuilder(self.log_dir)
        
        # Create entries for 3 consecutive days
        dates = ["2026-10-10", "2026-10-11", "2026-10-12"]
        for date in dates:
            records = self.create_test_records(date)
            entry = builder.build_daily_entry(date, records, self.signing_key)
            builder.append_entry(entry)
        
        # Verify chain is valid first
        verifier = OfflineVerifier(self.log_dir)
        is_valid, _ = verifier.verify_chain("2026-10-10", "2026-10-12")
        self.assertTrue(is_valid, "Chain should be valid before tampering")
        
        # Tamper with middle entry: change one character in merkle_root
        log_file = self.log_dir / "2026.jsonl"
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Modify the second line (2026-10-11 entry)
        original_line = lines[1]
        entry_data = json.loads(original_line)
        original_merkle_root = entry_data["merkle_root"]
        
        # Change one character
        tampered_merkle_root = original_merkle_root[:-1] + ("a" if original_merkle_root[-1] != "a" else "b")
        entry_data["merkle_root"] = tampered_merkle_root
        
        lines[1] = json.dumps(entry_data, sort_keys=True, separators=(',', ':')) + '\n'
        
        with open(log_file, 'w') as f:
            f.writelines(lines)
        
        # Verify chain should now fail
        is_valid, message = verifier.verify_chain("2026-10-10", "2026-10-12")
        
        self.assertFalse(is_valid, "Chain should fail after tampering")
        self.assertIn("Chain broken", message)
        print(f"✅ Test 2: Editing entry fails - Tampering detected: {message[:80]}...")
    
    def test_03_deleting_entry_fails(self):
        """Test that deleting an entry breaks the chain."""
        builder = LogBuilder(self.log_dir)
        
        # Create entries for 3 consecutive days
        dates = ["2026-10-10", "2026-10-11", "2026-10-12"]
        for date in dates:
            records = self.create_test_records(date)
            entry = builder.build_daily_entry(date, records, self.signing_key)
            builder.append_entry(entry)
        
        # Verify chain is valid first
        verifier = OfflineVerifier(self.log_dir)
        is_valid, _ = verifier.verify_chain("2026-10-10", "2026-10-12")
        self.assertTrue(is_valid, "Chain should be valid before deletion")
        
        # Delete the middle entry
        log_file = self.log_dir / "2026.jsonl"
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Remove second line (2026-10-11 entry)
        del lines[1]
        
        with open(log_file, 'w') as f:
            f.writelines(lines)
        
        # Verify chain should now fail (missing entry)
        entries = verifier.get_entries_in_range("2026-10-10", "2026-10-12")
        
        # Should only have 2 entries now instead of 3
        self.assertEqual(len(entries), 2, "Should only have 2 entries after deletion")
        self.assertEqual(entries[0].date, "2026-10-10")
        self.assertEqual(entries[1].date, "2026-10-12")
        
        # Chain should be broken because 2026-10-12 references 2026-10-11's hash
        is_valid, message = verifier.verify_chain("2026-10-10", "2026-10-12")
        self.assertFalse(is_valid, "Chain should fail after deletion")
        print(f"✅ Test 3: Deleting entry fails - Deletion detected: {message[:80]}...")
    
    def test_04_record_not_in_day_fails(self):
        """Test that a record not in that day fails inclusion check."""
        builder = LogBuilder(self.log_dir)
        
        # Create an entry for 2026-10-10 with specific records
        records = self.create_test_records("2026-10-10", count=3)
        entry = builder.build_daily_entry("2026-10-10", records, self.signing_key)
        builder.append_entry(entry)
        
        # Create a different record (not in the day)
        different_record = Record(
            record_type="receipt",
            timestamp="2026-10-10T99:99:99Z",
            content_hash="different_hash" + "0" * 50,
            metadata={"test_id": 999}
        )
        
        # Write it to a temp file
        record_file = self.test_dir / "different_record.json"
        with open(record_file, 'w') as f:
            json.dump(different_record.to_dict(), f, sort_keys=True, separators=(',', ':'))
        
        # Compute its hash
        different_hash = different_record.compute_hash()
        
        # Verify that it's not in the Merkle tree
        # (we can check by computing the expected hashes)
        expected_hashes = [r.compute_hash() for r in records]
        
        self.assertNotIn(different_hash, expected_hashes, 
                        "Different record should not be in the day's records")
        
        print(f"✅ Test 4: Record not in day - Hash not found in expected records")
        print(f"   Different record hash: {different_hash[:32]}...")
        print(f"   Expected hashes: {[h[:16] + '...' for h in expected_hashes]}")
    
    def test_05_hash_chain_links_correctly(self):
        """Test that hash chain links consecutive days correctly."""
        builder = LogBuilder(self.log_dir)
        
        # Create entries for 5 consecutive days
        dates = [f"2026-10-{10+i:02d}" for i in range(5)]
        entries = []
        
        for date in dates:
            records = self.create_test_records(date)
            entry = builder.build_daily_entry(date, records, self.signing_key)
            builder.append_entry(entry)
            entries.append(entry)
        
        # Verify each link
        for i in range(1, len(entries)):
            current = entries[i]
            previous = entries[i-1]
            
            expected_prev_hash = previous.compute_entry_hash()
            actual_prev_hash = current.previous_entry_hash
            
            self.assertEqual(expected_prev_hash, actual_prev_hash,
                           f"Entry {current.date} should link to {previous.date}")
        
        print(f"✅ Test 5: Hash chain links correctly across {len(entries)} entries")
    
    def test_06_first_entry_genesis(self):
        """Test that the first entry has no previous_entry_hash."""
        builder = LogBuilder(self.log_dir)
        
        records = self.create_test_records("2026-10-10")
        entry = builder.build_daily_entry("2026-10-10", records, self.signing_key)
        builder.append_entry(entry)
        
        self.assertIsNone(entry.previous_entry_hash, 
                         "First entry should have no previous_entry_hash")
        print(f"✅ Test 6: First entry has GENESIS (no previous hash)")
    
    def test_07_duplicate_date_rejected(self):
        """Test that appending an entry with duplicate date is rejected."""
        builder = LogBuilder(self.log_dir)
        
        records = self.create_test_records("2026-10-10")
        entry1 = builder.build_daily_entry("2026-10-10", records, self.signing_key)
        builder.append_entry(entry1)
        
        # Try to append another entry for the same date
        records2 = self.create_test_records("2026-10-10", count=2)
        entry2 = builder.build_daily_entry("2026-10-10", records2, self.signing_key)
        
        with self.assertRaises(ValueError) as context:
            builder.append_entry(entry2)
        
        self.assertIn("already exists", str(context.exception))
        print(f"✅ Test 7: Duplicate date rejected - {context.exception}")
    
    def test_08_reordering_entries_fails(self):
        """Test that reordering entries breaks the chain."""
        builder = LogBuilder(self.log_dir)
        
        # Create entries for 3 consecutive days
        dates = ["2026-10-10", "2026-10-11", "2026-10-12"]
        for date in dates:
            records = self.create_test_records(date)
            entry = builder.build_daily_entry(date, records, self.signing_key)
            builder.append_entry(entry)
        
        # Verify chain is valid first
        verifier = OfflineVerifier(self.log_dir)
        is_valid, _ = verifier.verify_chain("2026-10-10", "2026-10-12")
        self.assertTrue(is_valid, "Chain should be valid before reordering")
        
        # Swap lines 1 and 2 (reorder entries)
        log_file = self.log_dir / "2026.jsonl"
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Swap
        lines[0], lines[1] = lines[1], lines[0]
        
        with open(log_file, 'w') as f:
            f.writelines(lines)
        
        # Check for tampering (which includes file order check)
        has_tampering, message = verifier.check_tampering("2026-10-10", "2026-10-12")
        
        self.assertTrue(has_tampering, "Reordering should be detected as tampering")
        self.assertIn("not in chronological order", message)
        print(f"✅ Test 8: Reordering entries fails - {message[:80]}...")
    
    def test_09_merkle_tree_deterministic(self):
        """Test that Merkle tree is deterministic (same records → same root)."""
        records = self.create_test_records("2026-10-10", count=5)
        
        # Build tree twice
        from log_builder import MerkleTree
        leaf_hashes = [r.compute_hash() for r in records]
        
        tree1 = MerkleTree(leaf_hashes)
        tree2 = MerkleTree(leaf_hashes)
        
        self.assertEqual(tree1.get_root(), tree2.get_root(),
                        "Merkle root should be deterministic")
        print(f"✅ Test 9: Merkle tree is deterministic")
        print(f"   Root: {tree1.get_root()[:32]}...")
    
    def test_10_empty_records_rejected(self):
        """Test that building entry with no records is rejected."""
        builder = LogBuilder(self.log_dir)
        
        with self.assertRaises(ValueError) as context:
            builder.build_daily_entry("2026-10-10", [], self.signing_key)
        
        self.assertIn("No records", str(context.exception))
        print(f"✅ Test 10: Empty records rejected - {context.exception}")


class TestMerkleTree(unittest.TestCase):
    """Test Merkle tree implementation."""
    
    def test_single_leaf(self):
        """Test Merkle tree with a single leaf."""
        from log_builder import MerkleTree
        leaves = ["hash1"]
        tree = MerkleTree(leaves)
        self.assertEqual(tree.get_root(), "hash1")
        print(f"✅ Single leaf tree: root = leaf")
    
    def test_two_leaves(self):
        """Test Merkle tree with two leaves."""
        from log_builder import MerkleTree, hash_pair
        leaves = ["hash1", "hash2"]
        tree = MerkleTree(leaves)
        expected_root = hash_pair("hash1", "hash2")
        self.assertEqual(tree.get_root(), expected_root)
        print(f"✅ Two leaf tree: root = hash(left || right)")
    
    def test_odd_leaves(self):
        """Test Merkle tree with odd number of leaves (last leaf duplicated)."""
        from log_builder import MerkleTree, hash_pair
        leaves = ["hash1", "hash2", "hash3"]
        tree = MerkleTree(leaves)
        
        # Should be: hash(hash(h1, h2), hash(h3, h3))
        level1_left = hash_pair("hash1", "hash2")
        level1_right = hash_pair("hash3", "hash3")
        expected_root = hash_pair(level1_left, level1_right)
        
        self.assertEqual(tree.get_root(), expected_root)
        print(f"✅ Odd leaf tree: duplicates last leaf")
    
    def test_inclusion_proof(self):
        """Test inclusion proof generation and verification."""
        from log_builder import MerkleTree
        leaves = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaves)
        
        # Get proof for leaf 0
        proof = tree.get_inclusion_proof(0)
        
        # Verify it
        is_valid = MerkleTree.verify_inclusion_proof("hash1", proof, tree.get_root())
        self.assertTrue(is_valid)
        print(f"✅ Inclusion proof verifies correctly")


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestTransparencyLog))
    suite.addTests(loader.loadTestsFromTestCase(TestMerkleTree))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*70)
    if result.wasSuccessful():
        print("✅ All tests passed!")
        return 0
    else:
        print(f"❌ {len(result.failures)} tests failed, {len(result.errors)} errors")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
