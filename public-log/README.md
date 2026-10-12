# Transparency Log

This directory contains a daily signed transparency log. Each day at 23:00 UTC, an automated workflow publishes a new entry with a cryptographic signature.

## What is logged

Each entry records the date, a count of logged operations, and a Merkle root hash. The entry is signed with an Ed25519 key and linked to the previous day's entry in a hash chain.

Right now, the records feed is not connected, so current entries may contain zero operations or placeholder data. When the feed goes live, the log will include fingerprints of key-policy changes, receipts, countersignatures, and manifest releases.

## What it proves

Later tampering is detectable. If we edit, delete, or reorder past entries, the hash chain breaks. Anyone can verify the chain offline and detect tampering.

## How to verify offline

Two commands:

```bash
# 1. Verify hash chain integrity
python3 ../transparency-log/verify.py chain --log-dir . --start 2026-10-12 --end 2026-10-31

# 2. Verify entry signatures
python3 ../transparency-log/verify.py signature --log-dir . --date 2026-10-12
```

The verification tool reads the public key from `PUBLIC_KEY.txt` in this directory.
