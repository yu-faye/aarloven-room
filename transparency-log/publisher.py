#!/usr/bin/env python3
"""
Daily Publisher Script

Collects operation records for the current date (or a specified date),
builds a daily log entry with Merkle root and hash chain, signs it,
and appends to the public log.

Usage:
    python3 publisher.py [--date YYYY-MM-DD] [--records-dir PATH] [--log-dir PATH] [--key KEY_HEX]
    
Environment variables:
    SIGNING_KEY: Hex-encoded Ed25519 signing key (32 bytes, 64 hex chars)
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent dir to path to import log_builder
sys.path.insert(0, str(Path(__file__).parent))
from log_builder import LogBuilder, Record


def get_signing_key(key_arg: str = None) -> bytes:
    """
    Get signing key from argument or environment.
    
    Priority:
    1. --key argument
    2. SIGNING_KEY environment variable
    3. Generate a test key and warn
    """
    key_hex = key_arg or os.environ.get("SIGNING_KEY")
    
    if key_hex:
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                raise ValueError("Signing key must be exactly 32 bytes (64 hex chars)")
            return key_bytes
        except ValueError as e:
            print(f"Error: Invalid signing key: {e}", file=sys.stderr)
            sys.exit(1)
    
    # No key provided - generate test key and warn
    print("WARNING: No signing key provided. Using a test key.", file=sys.stderr)
    print("For production, set SIGNING_KEY environment variable (see GitHub secrets docs).", file=sys.stderr)
    test_key = b"test_key_" + b"0" * 23  # 32 bytes
    return test_key


def main():
    parser = argparse.ArgumentParser(
        description="Publish daily transparency log entry"
    )
    parser.add_argument(
        "--date",
        help="Date to publish (YYYY-MM-DD). Default: today",
        default=datetime.now().strftime("%Y-%m-%d")
    )
    parser.add_argument(
        "--records-dir",
        help="Directory containing operation records. Default: ./records",
        default="records"
    )
    parser.add_argument(
        "--log-dir",
        help="Directory for public log files. Default: ./public-log",
        default="public-log"
    )
    parser.add_argument(
        "--key",
        help="Hex-encoded Ed25519 signing key (32 bytes). Overrides SIGNING_KEY env var."
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow publishing with zero records (for testing)"
    )
    
    args = parser.parse_args()
    
    # Get signing key
    signing_key = get_signing_key(args.key)
    
    # Initialize builder
    builder = LogBuilder(Path(args.log_dir))
    
    # Collect records
    print(f"Collecting records for {args.date} from {args.records_dir}...")
    records = builder.collect_records(Path(args.records_dir), args.date)
    
    if not records:
        if args.allow_empty:
            print("No records found, but --allow-empty specified. Creating dummy record.")
            # Create a dummy record for testing
            records = [Record(
                record_type="test",
                timestamp=f"{args.date}T00:00:00Z",
                content_hash="0" * 64,
                metadata={"note": "test entry"}
            )]
        else:
            print(f"No records found for {args.date}. Nothing to publish.", file=sys.stderr)
            print("Use --allow-empty to publish with zero records (testing only).", file=sys.stderr)
            sys.exit(1)
    
    print(f"Found {len(records)} records:")
    for r in records:
        print(f"  - {r.record_type}: {r.content_hash[:16]}... ({r.timestamp})")
    
    # Build daily entry
    print(f"Building daily entry for {args.date}...")
    entry = builder.build_daily_entry(args.date, records, signing_key)
    
    print(f"Daily entry:")
    print(f"  Date: {entry.date}")
    print(f"  Record count: {entry.record_count}")
    print(f"  Merkle root: {entry.merkle_root}")
    print(f"  Previous entry hash: {entry.previous_entry_hash or 'GENESIS'}")
    print(f"  Entry hash: {entry.compute_entry_hash()}")
    print(f"  Signature: {entry.signature[:32]}...")
    
    # Append to log
    print(f"Appending entry to {args.log_dir}/{args.date[:4]}.jsonl...")
    try:
        builder.append_entry(entry)
        print(f"✅ Successfully published entry for {args.date}")
        
        # Verify chain integrity
        print("Verifying chain integrity...")
        is_valid, message = builder.verify_chain_integrity(args.date, args.date)
        if is_valid:
            print(f"✅ {message}")
        else:
            print(f"❌ Chain verification failed: {message}", file=sys.stderr)
            sys.exit(1)
            
    except ValueError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
