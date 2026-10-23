# Transparency Log

This directory contains a daily signed transparency log. Each day at 23:00 UTC, an automated workflow publishes a new entry with a cryptographic signature.

## What is logged

Each entry records the date, a count of logged operations, and a Merkle root hash. The entry is signed with an Ed25519 key and linked to the previous day's entry in a hash chain.

### Current feeds

**KMS and IAM policy changes** (via AWS CloudTrail):
- KMS key policy changes: `PutKeyPolicy`, `CreateGrant`, `RetireGrant`, `RevokeGrant`
- Key lifecycle: `CreateKey`, `DisableKey`, `EnableKey`, `ScheduleKeyDeletion`, `CancelKeyDeletion`
- Key aliases: `CreateAlias`, `UpdateAlias`, `DeleteAlias`
- Key material: `ImportKeyMaterial`
- IAM role policy changes: `PutRolePolicy`, `AttachRolePolicy`, `DetachRolePolicy`, `DeleteRolePolicy`, `UpdateAssumeRolePolicy`

For `PutKeyPolicy` events, the full policy document is stored (so outsiders can see who can access the keys). Other events are recorded as fingerprints (event name, time, key/role ID, actor type, and a hash of the request parameters).

**Privacy**: No personal names, IP addresses, or account-specific identifiers appear in the log. Actor identifiers are reduced to short hashes.

**Trial-environment receipt fingerprints** (optional, see `trial-env/README.md`): receipt hashes and per-buyer chain heads under salted pseudonyms; no names, no receipt contents. On days that include such a file, `leaves/<date>.json` lists that day's leaf hashes so anyone can recompute the signed Merkle root.

**When the feed is not connected**: If AWS credentials are not configured, each day's entry includes a record stating "kms feed not connected" rather than claiming zero changes. This makes a missing credential distinguishable from a quiet day.

## What it proves

Later tampering is detectable. If we edit, delete, or reorder past entries, the hash chain breaks. Anyone can verify the chain offline and detect tampering.

## Limitations and trust model

**CloudTrail lives in our AWS account**: An AWS account owner could theoretically stop CloudTrail logging or delete the trail. However:
- CloudTrail **event history for management events cannot be edited or deleted** for 90 days after events occur (AWS limitation)
- If the trail is stopped, a gap in the transparency log would be visible (missing days)
- If AWS credentials are removed from GitHub, the log shows "kms feed not connected" each day, not zero changes
- The transparency log itself is append-only and cryptographically signed, so tampering with published entries is detectable

**The log does not authenticate original content**: The log proves we have not modified or deleted logged records after publication. It does not prove that the original CloudTrail events were accurate or that we collected all events.

**Trust anchors**:
- AWS CloudTrail's 90-day immutability guarantee
- GitHub's public git history (rewriting history would be visible)
- This repository's transparency log signing key (published in contracts and on the website)
- The hash chain linking all entries back to the first published entry

Outsiders should monitor the log for gaps, "not connected" days, or broken hash chains. Community mirrors and monitoring bots are encouraged.

## How to verify offline

Two commands:

```bash
# 1. Verify hash chain integrity
python3 ../transparency-log/verify.py chain --log-dir . --start 2026-10-12 --end 2026-10-31

# 2. Verify entry signatures
python3 ../transparency-log/verify.py signature --log-dir . --date 2026-10-12
```

The verification tool reads the public key from `PUBLIC_KEY.txt` in this directory.
