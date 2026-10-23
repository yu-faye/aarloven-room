#!/usr/bin/env python3
"""
Tests for the optional trial-environment feed (each not-yet-logged trial-env/YYYY-MM-DD.json -> one
log record, plus public-log/leaves/<run date>.json so anyone can recompute that day's Merkle root).

Uses temp dirs and a test signing key only; never touches public-log/.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "transparency-log"))

from log_builder import (LogBuilder, MerkleTree, Record, collect_trial_env_pending,  # noqa: E402
                         leaves_document, hash_pair, TRIAL_ENV_FORMAT)

TEST_KEY_HEX = "22" * 32


def canon(doc):
    return json.dumps(doc, sort_keys=True, separators=(',', ':')).encode() + b"\n"


def day_doc(date, n=2):
    p = "a" * 32
    rec = [{"buyer": p, "seq": i, "receipt_sha256": f"{i:064x}"} for i in range(1, n + 1)]
    return {"format": TRIAL_ENV_FORMAT, "date": date, "receipts": rec, "heads": [rec[-1]],
            "trial_signing_key_sha256": "b" * 64}


def root_from_leaves(leaves):
    """Independent recomputation (same rule as MerkleTree: odd last node paired with itself)."""
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


class TestTrialEnvFeed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.trial = self.tmp / "trial-env"
        self.trial.mkdir()
        self.date = "2026-10-24"
        self.log = self.tmp / "public-log"

    def collect(self, date=None):
        return collect_trial_env_pending(self.trial, self.log, date or self.date)

    def write(self, raw, date=None):
        (self.trial / f"{date or self.date}.json").write_bytes(raw)

    def test_no_file_no_record(self):
        self.assertEqual(self.collect(), [])

    def test_canonical_file_becomes_one_record(self):
        raw = canon(day_doc(self.date))
        self.write(raw)
        [r] = self.collect()
        self.assertEqual(r.record_type, "trial_env_day")
        self.assertEqual(r.timestamp, self.date)
        self.assertEqual(r.metadata, {"file": f"trial-env/{self.date}.json"})
        self.assertEqual(r.content_hash, hashlib.sha256(raw).hexdigest())

    def test_bad_files_are_skipped_not_fatal(self):
        bad = [
            b"not json",
            json.dumps(day_doc(self.date), indent=1).encode() + b"\n",          # not canonical
            canon(day_doc(self.date))[:-1],                                       # missing newline
            canon(dict(day_doc(self.date), format="other")),                     # wrong format
            canon(day_doc("2026-10-25")),                                         # wrong date inside
            canon([1, 2]),
        ]
        for raw in bad:
            self.write(raw)
            self.assertEqual(self.collect(), [], raw[:40])

    def publish(self, date, with_kms=True):
        records = self.tmp / "records"
        d = records / date
        d.mkdir(parents=True, exist_ok=True)
        if with_kms:
            (d / "not_connected.json").write_text(json.dumps({"status": "not_connected", "collected_at": "x"}))
            (d / "summary.json").write_text(json.dumps({"collected_at": "x", "total_event_count": 0}))
        log = self.tmp / "public-log"
        p = subprocess.run([sys.executable, str(ROOT / "transparency-log/publisher.py"), "--date", date,
                            "--records-dir", str(records), "--log-dir", str(log), "--trial-env-dir", str(self.trial),
                            "--key", TEST_KEY_HEX, "--allow-empty"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return log

    def entry(self, log, date):
        e = LogBuilder(log).get_entry(date)
        self.assertIsNotNone(e)
        return e

    def test_publisher_without_trial_file_is_unchanged(self):
        log = self.publish(self.date)
        self.assertFalse((log / "leaves").exists())
        self.assertEqual(self.entry(log, self.date).record_count, 2)

    def test_publisher_writes_leaves_and_root_recomputes(self):
        for n_kms, expected in ((True, 3), (False, 1)):   # 3 leaves (odd, trial leaf last) and 1 leaf
            with self.subTest(kms=n_kms):
                self.setUp()
                raw = canon(day_doc(self.date))
                self.write(raw)
                log = self.publish(self.date, with_kms=n_kms)
                e = self.entry(log, self.date)
                lv = json.loads((log / "leaves" / f"{self.date}.json").read_text())
                self.assertEqual(lv["date"], self.date)
                self.assertEqual(len(lv["leaves"]), e.record_count)
                self.assertEqual(e.record_count, expected)
                self.assertEqual(root_from_leaves(lv["leaves"]), e.merkle_root)
                self.assertEqual(lv["leaves"][-1], Record("trial_env_day", self.date, hashlib.sha256(raw).hexdigest(),
                                                             {"file": f"trial-env/{self.date}.json"}).compute_hash())
                self.assertEqual(lv["trial_files"], [f"{self.date}.json"])
                self.assertEqual(LogBuilder(log).verify_chain_integrity(self.date, self.date)[0], True)

    def test_file_merged_after_run_is_picked_up_next_run_once(self):
        self.publish("2026-10-24")
        self.write(canon(day_doc("2026-10-24")), "2026-10-24")      # merged after that day's run
        self.write(canon(day_doc("2026-10-26")), "2026-10-26")      # future-dated: not yet
        self.publish("2026-10-25")
        lv = json.loads((self.log / "leaves" / "2026-10-25.json").read_text())
        self.assertEqual(lv["trial_files"], ["2026-10-24.json"])
        self.publish("2026-10-26")
        lv = json.loads((self.log / "leaves" / "2026-10-26.json").read_text())
        self.assertEqual(lv["trial_files"], ["2026-10-26.json"])   # 10-24 is not included a second time
        # editing an already-logged file does not get it re-logged
        self.write(canon(day_doc("2026-10-24", 5)), "2026-10-24")
        self.assertEqual(self.collect("2026-10-27"), [])
        ok, msg = LogBuilder(self.log).verify_chain_integrity("2026-10-24", "2026-10-26")
        self.assertTrue(ok, msg)

    def test_two_pending_files_in_one_run(self):
        self.write(canon(day_doc("2026-10-23")), "2026-10-23")
        self.write(canon(day_doc("2026-10-24", 3)), "2026-10-24")
        self.publish("2026-10-24")
        e = self.entry(self.log, "2026-10-24")
        lv = json.loads((self.log / "leaves" / "2026-10-24.json").read_text())
        self.assertEqual(lv["trial_files"], ["2026-10-23.json", "2026-10-24.json"])
        self.assertEqual(e.record_count, 4)
        self.assertEqual(root_from_leaves(lv["leaves"]), e.merkle_root)

    def test_bad_leaves_file_does_not_stop_the_log(self):
        (self.log / "leaves").mkdir(parents=True)
        (self.log / "leaves" / "2026-10-20.json").write_text('{"trial_files": null}')
        self.write(canon(day_doc(self.date)))
        self.publish(self.date)
        self.assertEqual(self.entry(self.log, self.date).record_count, 3)

    def test_existing_leaves_file_blocks_before_appending(self):
        self.write(canon(day_doc(self.date)))
        (self.log / "leaves").mkdir(parents=True)
        (self.log / "leaves" / f"{self.date}.json").write_text("{}")
        records = self.tmp / "records"; records.mkdir(exist_ok=True)
        p = subprocess.run([sys.executable, str(ROOT / "transparency-log/publisher.py"), "--date", self.date,
                            "--records-dir", str(records), "--log-dir", str(self.log), "--trial-env-dir", str(self.trial),
                            "--key", TEST_KEY_HEX, "--allow-empty"], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIsNone(LogBuilder(self.log).get_entry(self.date))
        self.assertEqual(sorted(x.name for x in (self.log / "leaves").iterdir()), [f"{self.date}.json"])

    def test_leaves_document_order_matches_tree(self):
        recs = [Record("x", "t", f"{i:064x}", {}) for i in range(5)]
        doc = leaves_document("d", recs)
        self.assertEqual(root_from_leaves(doc["leaves"]), MerkleTree(doc["leaves"]).get_root())

    def test_known_odd_size_proof_bug_is_not_used(self):
        """Documents the parked bug: inclusion proofs for the LAST leaf of an odd-sized level are wrong.
        The trial-env path does not use inclusion proofs (buyers recompute the whole root from the
        published leaves), so the bug does not affect it."""
        leaves = [f"{i:064x}" for i in range(3)]
        t = MerkleTree(leaves)
        last_ok = MerkleTree.verify_inclusion_proof(leaves[-1], t.get_inclusion_proof(2), t.get_root())
        print(f"\n  [info] existing get_inclusion_proof for last leaf of 3: {'OK' if last_ok else 'BROKEN (parked bug)'}")
        self.assertEqual(root_from_leaves(leaves), t.get_root())


if __name__ == "__main__":
    unittest.main(verbosity=2)
