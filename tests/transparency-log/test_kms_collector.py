#!/usr/bin/env python3
"""
Tests for KMS event collector

Tests:
1. Events are normalized correctly
2. No IPs or personal usernames leak
3. Account-specific identifiers are hashed
4. Zero-event day produces summary record
5. Missing credentials produces 'not connected' record
6. PutKeyPolicy stores policy document
"""

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add transparency-log to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "transparency-log"))

from collect_kms_events import (
    collect_cloudtrail_events,
    extract_actor_info,
    hash_identifier,
    normalize_event,
    write_not_connected_record,
    write_records,
)


class TestKMSCollector(unittest.TestCase):
    """Test suite for KMS event collector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.records_dir = self.test_dir / "records"
        self.records_dir.mkdir()
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_01_hash_identifier(self):
        """Test that identifiers are hashed consistently."""
        identifier1 = "AROAI1234567890ABCDEF:session-name"
        identifier2 = "AROAI1234567890ABCDEF:session-name"
        identifier3 = "AROAIXXXXXXXXXXXXXXXXXXX:different"
        
        hash1 = hash_identifier(identifier1)
        hash2 = hash_identifier(identifier2)
        hash3 = hash_identifier(identifier3)
        
        # Same identifier should produce same hash
        self.assertEqual(hash1, hash2)
        
        # Different identifier should produce different hash
        self.assertNotEqual(hash1, hash3)
        
        # Hash should be 8 characters
        self.assertEqual(len(hash1), 8)
        
        print(f"✅ Test 1: Identifiers hashed consistently (8 chars)")
        print(f"   {identifier1[:20]}... → {hash1}")
    
    def test_02_extract_actor_info_no_pii(self):
        """Test that actor extraction does not leak PII."""
        event = {
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAI1234567890ABCDEF:admin-session",
                "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/admin-session",
                "accountId": "123456789012"
            },
            "sourceIPAddress": "203.0.113.42"
        }
        
        actor_info = extract_actor_info(event)
        
        # Should have actor type and hashed ID
        self.assertIn("actor_type", actor_info)
        self.assertIn("actor_id_hash", actor_info)
        
        # Should normalize type
        self.assertEqual(actor_info["actor_type"], "assumed-role")
        
        # Should not contain raw principal ID, ARN, or account ID
        actor_json = json.dumps(actor_info)
        self.assertNotIn("123456789012", actor_json)
        self.assertNotIn("AROAI1234567890ABCDEF", actor_json)
        self.assertNotIn("admin-session", actor_json)
        
        print(f"✅ Test 2: No PII leaked in actor info")
        print(f"   Actor type: {actor_info['actor_type']}")
        print(f"   Actor hash: {actor_info['actor_id_hash']}")
    
    def test_03_normalize_event_removes_ip(self):
        """Test that normalized events do not contain IP addresses."""
        event = {
            "eventTime": "2026-10-13T12:34:56Z",
            "eventName": "PutKeyPolicy",
            "eventID": "abc-123-def-456",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAI1234567890ABCDEF",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "userName": "admin"
            },
            "sourceIPAddress": "198.51.100.42",
            "requestParameters": {
                "keyId": "arn:aws:kms:eu-north-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                "policyName": "default",
                "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
            },
            "resources": [
                {
                    "type": "AWS::KMS::Key",
                    "ARN": "arn:aws:kms:eu-north-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                }
            ]
        }
        
        normalized = normalize_event(event, "kms")
        
        # Should not contain source IP
        normalized_json = json.dumps(normalized)
        self.assertNotIn("198.51.100.42", normalized_json)
        self.assertNotIn("sourceIPAddress", normalized_json)
        
        # Should not contain username
        self.assertNotIn("admin", normalized_json)
        self.assertNotIn("userName", normalized_json)
        
        # Should not contain full ARN (which includes account ID)
        self.assertNotIn("arn:aws:kms:eu-north-1:123456789012", normalized_json)
        self.assertNotIn("arn:aws:iam::123456789012", normalized_json)
        
        # Resource ID should be just the key UUID, not the full ARN
        self.assertEqual(normalized["resource_id"], "12345678-1234-1234-1234-123456789012")
        
        # Should have policy document (for PutKeyPolicy)
        self.assertIn("policy_document", normalized)
        
        print(f"✅ Test 3: No IP addresses or usernames in normalized event")
    
    def test_04_putkkeypolicy_stores_policy(self):
        """Test that PutKeyPolicy events store the policy document."""
        event = {
            "eventTime": "2026-10-13T12:34:56Z",
            "eventName": "PutKeyPolicy",
            "eventID": "abc-123",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root"
            },
            "requestParameters": {
                "keyId": "12345678-1234-1234-1234-123456789012",
                "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
            },
            "resources": [
                {
                    "type": "AWS::KMS::Key",
                    "ARN": "arn:aws:kms:eu-north-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                }
            ]
        }
        
        normalized = normalize_event(event, "kms")
        
        # Should have policy document
        self.assertIn("policy_document", normalized)
        
        # Policy should be valid JSON
        policy = json.loads(normalized["policy_document"])
        self.assertEqual(policy["Version"], "2012-10-17")
        self.assertIn("Statement", policy)
        
        print(f"✅ Test 4: PutKeyPolicy stores policy document")
        print(f"   Policy: {normalized['policy_document'][:60]}...")
    
    def test_05_zero_events_produces_summary(self):
        """Test that zero events still produces a summary record."""
        date = "2026-10-13"
        
        # Write records with zero events
        write_records(date, [], [], self.records_dir)
        
        # Should have date directory
        date_dir = self.records_dir / date
        self.assertTrue(date_dir.exists())
        
        # Should have summary file
        summary_file = date_dir / "summary.json"
        self.assertTrue(summary_file.exists())
        
        # Summary should show zero events
        with open(summary_file, 'r') as f:
            summary = json.load(f)
        
        self.assertEqual(summary["kms_event_count"], 0)
        self.assertEqual(summary["iam_event_count"], 0)
        self.assertEqual(summary["total_event_count"], 0)
        self.assertEqual(summary["date"], date)
        
        print(f"✅ Test 5: Zero events produces summary record")
        print(f"   Summary: {summary}")
    
    def test_06_not_connected_record(self):
        """Test that 'not connected' record is written when credentials unavailable."""
        date = "2026-10-13"
        
        write_not_connected_record(date, self.records_dir)
        
        # Should have date directory
        date_dir = self.records_dir / date
        self.assertTrue(date_dir.exists())
        
        # Should have not_connected file
        not_connected_file = date_dir / "not_connected.json"
        self.assertTrue(not_connected_file.exists())
        
        # Should have correct content
        with open(not_connected_file, 'r') as f:
            not_connected = json.load(f)
        
        self.assertEqual(not_connected["status"], "kms_feed_not_connected")
        self.assertEqual(not_connected["date"], date)
        self.assertIn("message", not_connected)
        self.assertIn("collected_at", not_connected)
        
        print(f"✅ Test 6: 'Not connected' record written")
        print(f"   Status: {not_connected['status']}")
    
    def test_07_collect_events_with_mock(self):
        """Test event collection with mocked CloudTrail responses."""
        try:
            import boto3
        except ImportError:
            self.skipTest("boto3 not available for testing")
        
        with patch('boto3.client') as mock_boto3_client:
            # Mock CloudTrail client
            mock_client = MagicMock()
            mock_boto3_client.return_value = mock_client
            
            # Mock paginator
            mock_paginator = MagicMock()
            mock_client.get_paginator.return_value = mock_paginator
            
            # Mock CloudTrail event
            mock_event_json = json.dumps({
                "eventTime": "2026-10-13T12:00:00Z",
                "eventName": "PutKeyPolicy",
                "eventID": "test-event-123",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AROATEST123:session",
                    "arn": "arn:aws:sts::123456789012:assumed-role/TestRole/session"
                },
                "requestParameters": {
                    "keyId": "test-key-123"
                },
                "resources": [
                    {
                        "type": "AWS::KMS::Key",
                        "ARN": "arn:aws:kms:eu-north-1:123456789012:key/test-key-123"
                    }
                ]
            })
            
            mock_page = {
                'Events': [
                    {'CloudTrailEvent': mock_event_json}
                ]
            }
            
            mock_paginator.paginate.return_value = [mock_page]
            
            # Collect events
            result = collect_cloudtrail_events("2026-10-13")
            
            # Should have KMS events
            self.assertIn("kms_events", result)
            self.assertGreater(len(result["kms_events"]), 0)
            
            # Should have called boto3.client
            mock_boto3_client.assert_called()
            
            print(f"✅ Test 7: Events collected with mocked CloudTrail")
            print(f"   KMS events: {len(result['kms_events'])}")
    
    def test_08_write_records_creates_files(self):
        """Test that write_records creates all expected files."""
        date = "2026-10-13"
        
        # Mock KMS event
        kms_event = {
            "eventTime": "2026-10-13T12:00:00Z",
            "eventName": "DisableKey",
            "eventID": "kms-event-123",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012"
            },
            "requestParameters": {"keyId": "test-key"},
            "resources": []
        }
        
        # Mock IAM event
        iam_event = {
            "eventTime": "2026-10-13T12:30:00Z",
            "eventName": "PutRolePolicy",
            "eventID": "iam-event-456",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDATEST"
            },
            "requestParameters": {"roleName": "TestRole"},
            "resources": []
        }
        
        write_records(date, [kms_event], [iam_event], self.records_dir)
        
        date_dir = self.records_dir / date
        
        # Should have KMS file
        kms_files = list(date_dir.glob("kms_*.json"))
        self.assertEqual(len(kms_files), 1)
        
        # Should have IAM file
        iam_files = list(date_dir.glob("iam_*.json"))
        self.assertEqual(len(iam_files), 1)
        
        # Should have summary
        summary_file = date_dir / "summary.json"
        self.assertTrue(summary_file.exists())
        
        with open(summary_file, 'r') as f:
            summary = json.load(f)
        self.assertEqual(summary["kms_event_count"], 1)
        self.assertEqual(summary["iam_event_count"], 1)
        self.assertEqual(summary["total_event_count"], 2)
        
        print(f"✅ Test 8: All record files created")
        print(f"   KMS: {kms_files[0].name}")
        print(f"   IAM: {iam_files[0].name}")
        print(f"   Summary: {summary['total_event_count']} events")
    
    def test_09_resource_id_extraction(self):
        """Test that resource IDs are extracted correctly."""
        # KMS event with key ARN
        kms_event = {
            "eventTime": "2026-10-13T12:00:00Z",
            "eventName": "EnableKey",
            "eventID": "test-123",
            "userIdentity": {"type": "Root", "principalId": "123456789012"},
            "requestParameters": {},
            "resources": [
                {
                    "type": "AWS::KMS::Key",
                    "ARN": "arn:aws:kms:eu-north-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
                }
            ]
        }
        
        normalized = normalize_event(kms_event, "kms")
        self.assertEqual(normalized["resource_id"], "abcd1234-5678-90ef-ghij-klmnopqrstuv")
        
        # IAM event with role name
        iam_event = {
            "eventTime": "2026-10-13T12:00:00Z",
            "eventName": "PutRolePolicy",
            "eventID": "test-456",
            "userIdentity": {"type": "Root", "principalId": "123456789012"},
            "requestParameters": {"roleName": "TestRole"},
            "resources": []
        }
        
        normalized = normalize_event(iam_event, "iam")
        self.assertEqual(normalized["resource_id"], "TestRole")
        
        print(f"✅ Test 9: Resource IDs extracted correctly")


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestKMSCollector)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*70)
    if result.wasSuccessful():
        print("✅ All KMS collector tests passed!")
        return 0
    else:
        print(f"❌ {len(result.failures)} tests failed, {len(result.errors)} errors")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
