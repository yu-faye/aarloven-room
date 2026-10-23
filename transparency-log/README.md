# Transparency Log Implementation (D-020)

Production implementation of the public audit log for Aarloven.

## Overview

This directory contains the implementation of the daily transparency log that publishes fingerprints (hash chain entries) of key operation records to a public, append-only place. This makes tampering detectable even by the operator or AWS account owner.

## Components

### Core Implementation

- **`log_builder.py`** — Core module for building log entries
  - Merkle tree construction for daily record batches
  - Hash chain linking consecutive days
  - Record hashing and entry signing
  - Chain integrity verification

- **`publisher.py`** — Daily publishing script
  - Collects records from `records/` directory
  - Builds daily entry with Merkle root
  - Signs entry with Ed25519 key
  - Appends to append-only log files in `public-log/`
  
- **`verify.py`** — Offline verification tool for buyers and auditors
  - Verify hash chain integrity
  - Verify entry signatures
  - Verify record inclusion
  - Detect tampering (edits, deletions, reordering)

### Automation

- **`.github/workflows/daily-transparency-log.yml`** — GitHub Actions workflow
  - Runs daily at 23:00 UTC
  - Collects records, builds entry, signs, and commits
  - Verifies no past entries have been modified
  - Ensures entries are in chronological order
  - Fails if chain is broken

### Tests

- **`tests/transparency-log/test_log.py`** — Comprehensive test suite
  - Valid chain passes
  - Editing entry fails
  - Deleting entry fails
  - Reordering entries fails
  - Record not in day fails
  - Hash chain links correctly
  - And more...

## Usage

### Publishing (Automated)

The GitHub Actions workflow automatically publishes daily. To manually publish:

```bash
# Set signing key (in production, use GitHub secret)
export SIGNING_KEY="your_64_char_hex_key"

# Publish for today
python3 transparency-log/publisher.py \
  --records-dir records \
  --log-dir public-log

# Publish for a specific date
python3 transparency-log/publisher.py \
  --date 2026-10-12 \
  --records-dir records \
  --log-dir public-log
```

### Verification (Buyer/Auditor)

```bash
# Verify hash chain
python3 transparency-log/verify.py chain \
  --log-dir public-log \
  --start 2026-10-01 \
  --end 2026-10-31

# Verify a record is logged
python3 transparency-log/verify.py inclusion \
  --log-dir public-log \
  --date 2026-10-12 \
  --record /path/to/receipt.json

# Check for tampering
python3 transparency-log/verify.py tampering \
  --log-dir public-log \
  --start 2026-10-01 \
  --end 2026-10-31

# Verify entry signature (requires public key)
python3 transparency-log/verify.py signature \
  --log-dir public-log \
  --date 2026-10-12 \
  --pubkey PUBLIC_KEY_HEX
```

### Testing

Run the full test suite:

```bash
python3 tests/transparency-log/test_log.py
```

All tests should pass. The trial-environment feed has its own tests:

```bash
python3 tests/transparency-log/test_trial_env.py
```

## Log Format

### Daily Entry

Each day produces one entry in `public-log/YYYY.jsonl`:

```json
{
  "date": "2026-10-12",
  "record_count": 42,
  "merkle_root": "a1b2c3d4e5f6...",
  "previous_entry_hash": "e5f6a7b8c9d0...",
  "signature": "9c0d1e2f3a4b..."
}
```

- **date**: The date (YYYY-MM-DD)
- **record_count**: Number of records logged that day
- **merkle_root**: Root of Merkle tree built from all records
- **previous_entry_hash**: Hash of previous day's entry (hash chain)
- **signature**: Ed25519 signature over the entry hash

### Entry Hash

The entry hash (used in the hash chain) is computed as:

```
entry_hash = SHA-256(date || record_count || merkle_root || previous_entry_hash)
```

Where `||` is concatenation with `||` as separator, and `previous_entry_hash` is `GENESIS` for the first entry.

### Record Types

Records collected for each day:

- **receipts**: Receipt v1 format (per D-016)
- **countersignatures**: Expert countersignatures (per D-019)
- **kms_policy**: KMS key policy changes
- **manifest**: Manifest/PCR0 releases (per D-006)
- **trial_env_day**: one per trial-environment day file (`trial-env/YYYY-MM-DD.json`, receipt hashes + per-buyer chain heads under salted pseudonyms). Optional; see `trial-env/README.md`. On days with such a record the publisher also writes `public-log/leaves/<date>.json` (leaf hashes in tree order + included trial files) so the root can be recomputed offline.

## Signing Key Management

### Production

The signing key is stored in **GitHub Secrets** as `TRANSPARENCY_LOG_SIGNING_KEY` (hex-encoded, 64 chars = 32 bytes).

To generate a key:

```python
import nacl.utils
import nacl.signing

# Generate key
signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key

print(f"SIGNING_KEY={signing_key.encode().hex()}")
print(f"PUBLIC_KEY={verify_key.encode().hex()}")
```

The public key fingerprint should be:
1. Written in contracts (per D-014)
2. Published on the website
3. Verified via second channel before first use

### Testing

For testing without PyNaCl, the implementation falls back to a mock signature (deterministic hash). Tests use a fixed test key.

## Dependencies

- Python 3.8+
- PyNaCl (optional, for real Ed25519 signatures; falls back to mock if not available)

Install:

```bash
pip install PyNaCl
```

## Security Properties

✅ **Deletion detection**: Deleting an entry breaks the hash chain.

✅ **Edit detection**: Changing any byte of an entry changes its hash, breaking the chain.

✅ **Reordering detection**: Entries must be in chronological order within files.

✅ **Backdating detection**: A backdated entry's `previous_entry_hash` will not match.

✅ **Append-only**: The GitHub Actions workflow fails if any past entry has been modified.

## Limitations

❌ **Assumes git integrity**: If an attacker can rewrite git history and convince all mirrors to update, tampering could be hidden. Mitigations: signed commits, multiple mirrors, published commit hashes in receipts/website.

❌ **Does not prevent stopping publication**: We could stop publishing new entries. Monitoring and community mirrors are encouraged.

❌ **Does not authenticate content**: The log only proves we have not modified logged records, not that the original records were correct.

## References

- **D-020** (DECISIONS.md): External append-only public log before handling customer data
- **Spike 04** (spikes/04-public-fingerprint-log/): Proof-of-concept that proved the approach
