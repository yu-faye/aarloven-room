#!/usr/bin/env python3
"""
Transparency Log Builder

Production implementation of the public audit log (D-020).
Builds daily hash chain entries from key operation records.
"""

import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import sys


def hash_data(data: bytes) -> str:
    """SHA-256 hash, returned as hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Hash two hex strings together (left || right)."""
    return hash_data((left + right).encode('utf-8'))


@dataclass
class Record:
    """A record to be logged (receipt, countersignature, KMS policy change, etc.)"""
    record_type: str  # "receipt", "countersignature", "kms_policy", "manifest"
    timestamp: str  # ISO 8601
    content_hash: str  # Hash of the actual record content
    metadata: Dict[str, Any]  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def compute_hash(self) -> str:
        """Compute the hash of this record (deterministic JSON)."""
        json_str = json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))
        return hash_data(json_str.encode('utf-8'))


@dataclass
class InclusionProof:
    """Proof that a record is included in a Merkle tree."""
    record_hash: str
    record_index: int
    tree_size: int
    merkle_path: List[Tuple[str, str]]  # List of (hash, position) where position is "left" or "right"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MerkleTree:
    """Simple Merkle tree implementation."""
    
    def __init__(self, leaves: List[str]):
        """Build a Merkle tree from leaf hashes."""
        if not leaves:
            raise ValueError("Cannot build tree with no leaves")
        self.leaves = leaves
        self.tree = self._build_tree(leaves)
        self.root = self.tree[-1][0] if self.tree else ""
    
    def _build_tree(self, leaves: List[str]) -> List[List[str]]:
        """Build tree bottom-up. Returns list of levels, bottom to top."""
        if not leaves:
            return []
        
        levels = [leaves[:]]
        current_level = leaves[:]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hash_pair(left, right)
                next_level.append(parent)
            levels.append(next_level)
            current_level = next_level
        
        return levels
    
    def get_root(self) -> str:
        """Get the Merkle root."""
        return self.root
    
    def get_inclusion_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Get inclusion proof for leaf at index.
        Returns list of (hash, position) tuples where position is "left" or "right".
        """
        if index < 0 or index >= len(self.leaves):
            raise ValueError(f"Index {index} out of range [0, {len(self.leaves)})")
        
        proof = []
        current_index = index
        
        for level_idx in range(len(self.tree) - 1):
            level = self.tree[level_idx]
            sibling_index = current_index ^ 1  # Flip last bit to get sibling
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
                position = "left" if sibling_index < current_index else "right"
                proof.append((sibling_hash, position))
            
            current_index = current_index // 2
        
        return proof
    
    @staticmethod
    def verify_inclusion_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
        """Verify an inclusion proof."""
        current_hash = leaf_hash
        
        for sibling_hash, position in proof:
            if position == "left":
                current_hash = hash_pair(sibling_hash, current_hash)
            else:
                current_hash = hash_pair(current_hash, sibling_hash)
        
        return current_hash == root


@dataclass
class DailyEntry:
    """A daily log entry with Merkle root and hash chain."""
    date: str  # YYYY-MM-DD
    record_count: int
    merkle_root: str
    previous_entry_hash: Optional[str]  # Hash chain: links to previous day's entry
    signature: str  # Self-managed Ed25519 signature over the entry
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.date,
            "record_count": self.record_count,
            "merkle_root": self.merkle_root,
            "previous_entry_hash": self.previous_entry_hash,
            "signature": self.signature,
        }
    
    def compute_entry_hash(self) -> str:
        """
        Compute the hash for this entry (for hash chain).
        Hash = SHA-256(date || record_count || merkle_root || previous_entry_hash)
        Signature is excluded from the hash.
        """
        chain_input = (
            f"{self.date}||{self.record_count}||{self.merkle_root}||"
            f"{self.previous_entry_hash or 'GENESIS'}"
        )
        return hash_data(chain_input.encode('utf-8'))


TRIAL_ENV_FORMAT = "aarloven.trial-env-day.v1"


def anchored_trial_files(log_dir: Path) -> Dict[str, str]:
    """trial-env file name -> date of the log entry that already includes it (from public-log/leaves/*.json)."""
    out: Dict[str, str] = {}
    for lf in sorted((Path(log_dir) / "leaves").glob("*.json")):
        try:
            doc = json.loads(lf.read_text())
            for name in doc.get("trial_files", []):
                out.setdefault(name, doc.get("date", lf.stem))
        except (ValueError, AttributeError):
            print(f"WARNING: cannot read {lf}", file=sys.stderr)
    return out


def collect_trial_env_pending(trial_dir: Path, log_dir: Path, date: str) -> List[Record]:
    """
    Trial-environment receipt fingerprints (optional feed).

    The box exports trial-env/YYYY-MM-DD.json (receipt hashes + per-buyer chain heads,
    buyer ids replaced by salted pseudonyms, no receipt contents); Yufei commits it to main.
    Each daily run picks up every such file dated <= the run date that no earlier run has
    included yet (so it does not matter when GitHub actually starts the scheduled run),
    and turns each into ONE record whose content_hash is the SHA-256 of the file's exact bytes.
    A file is included at most once; editing it afterwards is visible to verifiers.
    Malformed files are skipped with a warning: they must never stop the daily log.
    """
    trial_dir = Path(trial_dir)
    if not trial_dir.is_dir():
        return []
    done = anchored_trial_files(log_dir)
    out: List[Record] = []
    for f in sorted(trial_dir.glob("????-??-??.json")):
        d = f.stem
        if d > date or f.name in done:
            continue
        raw = f.read_bytes()
        try:
            doc = json.loads(raw)
            ok = (isinstance(doc, dict) and doc.get("format") == TRIAL_ENV_FORMAT and doc.get("date") == d
                  and raw == json.dumps(doc, sort_keys=True, separators=(',', ':')).encode('utf-8') + b"\n")
        except ValueError:
            ok = False
        if not ok:
            print(f"WARNING: {f} is not a canonical {TRIAL_ENV_FORMAT} file; not logged", file=sys.stderr)
            continue
        out.append(Record(record_type="trial_env_day", timestamp=d, content_hash=hash_data(raw),
                          metadata={"file": f"trial-env/{f.name}"}))
    return out


def leaves_document(date: str, records: List[Record]) -> Dict[str, Any]:
    """The ordered leaf hashes of a day's Merkle tree, so anyone can recompute the root offline,
    plus which trial-env files this day includes. Only hashes are published; record contents stay private."""
    return {"date": date, "leaves": [r.compute_hash() for r in records],
            "trial_files": [r.metadata["file"].split("/", 1)[1] for r in records if r.record_type == "trial_env_day"]}


class LogBuilder:
    """Builder for the transparency log."""
    
    def __init__(self, log_dir: Path):
        """
        Initialize log builder.
        
        Args:
            log_dir: Directory containing the public log files (e.g., public-log/)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_records(self, record_dir: Path, date: str) -> List[Record]:
        """
        Collect all records for a given date.
        
        Args:
            record_dir: Directory containing the operation records
            date: Date in YYYY-MM-DD format
        
        Returns:
            List of records for that date
        """
        records = []
        record_path = Path(record_dir)
        
        if not record_path.exists():
            return records
        
        # Collect receipts
        receipts_dir = record_path / "receipts" / date.replace("-", "/")
        if receipts_dir.exists():
            for receipt_file in sorted(receipts_dir.glob("*.json")):
                with open(receipt_file, 'r') as f:
                    receipt_data = json.load(f)
                
                receipt_bytes = json.dumps(receipt_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(receipt_bytes)
                
                records.append(Record(
                    record_type="receipt",
                    timestamp=receipt_data.get("timestamp", ""),
                    content_hash=content_hash,
                    metadata={"file": receipt_file.name}
                ))
        
        # Collect countersignatures
        countersign_dir = record_path / "countersignatures" / date.replace("-", "/")
        if countersign_dir.exists():
            for countersign_file in sorted(countersign_dir.glob("*.json")):
                with open(countersign_file, 'r') as f:
                    countersign_data = json.load(f)
                
                countersign_bytes = json.dumps(countersign_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(countersign_bytes)
                
                records.append(Record(
                    record_type="countersignature",
                    timestamp=countersign_data.get("timestamp", ""),
                    content_hash=content_hash,
                    metadata={"file": countersign_file.name}
                ))
        
        # Collect KMS policy changes (legacy JSONL format)
        kms_log = record_path / "kms_policy_changes.jsonl"
        if kms_log.exists():
            with open(kms_log, 'r') as f:
                for line in f:
                    entry = json.loads(line.strip())
                    if entry.get("date") == date:
                        entry_bytes = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('utf-8')
                        content_hash = hash_data(entry_bytes)
                        
                        records.append(Record(
                            record_type="kms_policy",
                            timestamp=entry.get("timestamp", ""),
                            content_hash=content_hash,
                            metadata={"description": entry.get("description", "")}
                        ))
        
        # Collect KMS/IAM events from date-specific directory (new format)
        date_dir = record_path / date
        if date_dir.exists():
            # Collect all KMS event records
            for kms_file in sorted(date_dir.glob("kms_*.json")):
                with open(kms_file, 'r') as f:
                    kms_event = json.load(f)
                
                event_bytes = json.dumps(kms_event, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(event_bytes)
                
                records.append(Record(
                    record_type="kms_event",
                    timestamp=kms_event.get("event_time", ""),
                    content_hash=content_hash,
                    metadata={
                        "file": kms_file.name,
                        "event_name": kms_event.get("event_name", ""),
                        "resource_id": kms_event.get("resource_id", "")
                    }
                ))
            
            # Collect all IAM event records
            for iam_file in sorted(date_dir.glob("iam_*.json")):
                with open(iam_file, 'r') as f:
                    iam_event = json.load(f)
                
                event_bytes = json.dumps(iam_event, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(event_bytes)
                
                records.append(Record(
                    record_type="iam_event",
                    timestamp=iam_event.get("event_time", ""),
                    content_hash=content_hash,
                    metadata={
                        "file": iam_file.name,
                        "event_name": iam_event.get("event_name", ""),
                        "resource_id": iam_event.get("resource_id", "")
                    }
                ))
            
            # Collect 'not connected' record if present
            not_connected_file = date_dir / "not_connected.json"
            if not_connected_file.exists():
                with open(not_connected_file, 'r') as f:
                    not_connected = json.load(f)
                
                nc_bytes = json.dumps(not_connected, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(nc_bytes)
                
                records.append(Record(
                    record_type="kms_not_connected",
                    timestamp=not_connected.get("collected_at", ""),
                    content_hash=content_hash,
                    metadata={"status": not_connected.get("status", "")}
                ))
            
            # Collect summary record (always present)
            summary_file = date_dir / "summary.json"
            if summary_file.exists():
                with open(summary_file, 'r') as f:
                    summary = json.load(f)
                
                summary_bytes = json.dumps(summary, sort_keys=True, separators=(',', ':')).encode('utf-8')
                content_hash = hash_data(summary_bytes)
                
                records.append(Record(
                    record_type="kms_summary",
                    timestamp=summary.get("collected_at", ""),
                    content_hash=content_hash,
                    metadata={"total_events": summary.get("total_event_count", 0)}
                ))
        
        # Collect manifest/PCR0 releases
        manifest_log = record_path / "manifest_releases.jsonl"
        if manifest_log.exists():
            with open(manifest_log, 'r') as f:
                for line in f:
                    entry = json.loads(line.strip())
                    if entry.get("date") == date:
                        entry_bytes = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('utf-8')
                        content_hash = hash_data(entry_bytes)
                        
                        records.append(Record(
                            record_type="manifest",
                            timestamp=entry.get("timestamp", ""),
                            content_hash=content_hash,
                            metadata={"pcr0": entry.get("pcr0", "")}
                        ))
        
        return records
    
    def build_daily_entry(self, date: str, records: List[Record], signing_key: bytes) -> DailyEntry:
        """
        Build a daily log entry from records.
        
        Args:
            date: Date in YYYY-MM-DD format
            records: List of records for that date
            signing_key: Ed25519 signing key (32 bytes)
        
        Returns:
            DailyEntry with Merkle root and signature
        """
        if not records:
            raise ValueError(f"No records for {date}")
        
        # Build Merkle tree
        leaf_hashes = [record.compute_hash() for record in records]
        tree = MerkleTree(leaf_hashes)
        merkle_root = tree.get_root()
        
        # Get previous entry hash
        previous_entry_hash = self._get_previous_entry_hash(date)
        
        # Compute entry hash (without signature)
        chain_input = (
            f"{date}||{len(records)}||{merkle_root}||"
            f"{previous_entry_hash or 'GENESIS'}"
        )
        entry_hash = hash_data(chain_input.encode('utf-8'))
        
        # Sign with Ed25519
        signature = self._sign_entry(entry_hash, signing_key)
        
        return DailyEntry(
            date=date,
            record_count=len(records),
            merkle_root=merkle_root,
            previous_entry_hash=previous_entry_hash,
            signature=signature,
        )
    
    def _get_previous_entry_hash(self, current_date: str) -> Optional[str]:
        """Get the hash of the previous day's entry."""
        year = current_date[:4]
        log_file = self.log_dir / f"{year}.jsonl"
        
        if not log_file.exists():
            return None
        
        previous_entry = None
        with open(log_file, 'r') as f:
            for line in f:
                entry = json.loads(line.strip())
                if entry["date"] < current_date:
                    previous_entry = entry
        
        if previous_entry:
            # Recompute hash from previous entry
            chain_input = (
                f"{previous_entry['date']}||{previous_entry['record_count']}||"
                f"{previous_entry['merkle_root']}||"
                f"{previous_entry['previous_entry_hash'] or 'GENESIS'}"
            )
            return hash_data(chain_input.encode('utf-8'))
        
        return None
    
    def _sign_entry(self, entry_hash: str, signing_key: bytes) -> str:
        """Sign entry hash with Ed25519. Returns hex-encoded signature."""
        try:
            from nacl.signing import SigningKey
            key = SigningKey(signing_key)
            signature = key.sign(bytes.fromhex(entry_hash)).signature
            return signature.hex()
        except ImportError:
            # Fallback: mock signature for testing
            mock_sig = hash_data(f"MOCK_SIGNATURE_{entry_hash}_{signing_key.hex()}".encode('utf-8'))
            return mock_sig
    
    def append_entry(self, entry: DailyEntry) -> None:
        """
        Append entry to the log file.
        Entries are append-only; never modifies existing entries.
        """
        year = entry.date[:4]
        log_file = self.log_dir / f"{year}.jsonl"
        
        # Verify this date doesn't already exist
        if log_file.exists():
            with open(log_file, 'r') as f:
                for line in f:
                    existing = json.loads(line.strip())
                    if existing["date"] == entry.date:
                        raise ValueError(f"Entry for {entry.date} already exists")
        
        # Append entry
        with open(log_file, 'a') as f:
            json.dump(entry.to_dict(), f, sort_keys=True, separators=(',', ':'))
            f.write('\n')
    
    def get_entry(self, date: str) -> Optional[DailyEntry]:
        """Get entry for a specific date."""
        year = date[:4]
        log_file = self.log_dir / f"{year}.jsonl"
        
        if not log_file.exists():
            return None
        
        with open(log_file, 'r') as f:
            for line in f:
                entry_dict = json.loads(line.strip())
                if entry_dict["date"] == date:
                    return DailyEntry(**entry_dict)
        
        return None
    
    def get_inclusion_proof(self, date: str, record: Record) -> Optional[InclusionProof]:
        """Get inclusion proof for a record on a specific date."""
        # This would need to reconstruct the records and tree
        # For now, return None (proof generation would be done separately)
        return None
    
    def verify_chain_integrity(self, start_date: str, end_date: str) -> Tuple[bool, str]:
        """
        Verify the hash chain from start_date to end_date.
        
        Returns:
            (is_valid, message)
        """
        entries = []
        
        # Collect all entries in range
        start_year = int(start_date[:4])
        end_year = int(end_date[:4])
        
        for year in range(start_year, end_year + 1):
            log_file = self.log_dir / f"{year}.jsonl"
            if log_file.exists():
                with open(log_file, 'r') as f:
                    for line in f:
                        entry_dict = json.loads(line.strip())
                        if start_date <= entry_dict["date"] <= end_date:
                            entries.append(DailyEntry(**entry_dict))
        
        if not entries:
            return False, "No entries found in range"
        
        # Sort by date
        entries.sort(key=lambda e: e.date)
        
        # Verify chain
        for i in range(1, len(entries)):
            current = entries[i]
            previous = entries[i - 1]
            
            expected_prev_hash = previous.compute_entry_hash()
            if current.previous_entry_hash != expected_prev_hash:
                return False, f"Chain broken at {current.date}: expected {expected_prev_hash}, got {current.previous_entry_hash}"
        
        return True, f"Chain valid from {start_date} to {end_date}"
