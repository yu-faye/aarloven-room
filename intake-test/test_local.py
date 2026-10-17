#!/usr/bin/env python3
"""Local tests for the intake TEST room: a fake kmstool (RSA-OAEP with a local private key) and a stubbed NSM.
Real kmstool and NSM are only used inside the enclave.   python3 intake-test/test_local.py
"""
import atexit
import base64
import copy
import datetime
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TMP = tempfile.TemporaryDirectory()
atexit.register(TMP.cleanup)
KEY_ID = "arn:aws:kms:eu-north-1:123456789012:key/11111111-2222-3333-4444-555555555555"
RSA_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV_PATH = os.path.join(TMP.name, "kms_priv.pem")
PUB_PATH = os.path.join(TMP.name, "kms_pub.der")

with open(PRIV_PATH, "wb") as f:
    f.write(RSA_PRIV.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
with open(PUB_PATH, "wb") as f:
    f.write(RSA_PRIV.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
import local_stubs  # noqa: E402
FAKE_KMSTOOL = local_stubs.install_fake_kmstool(TMP.name, KEY_ID, PRIV_PATH)

import buyer_seal  # noqa: E402
import buyer_seal_canon2  # noqa: E402
import intake_loop  # noqa: E402
import verify_receipt  # noqa: E402

PCR0 = local_stubs.STUB_PCR0


# ---------- a stubbed NSM (local_stubs.py): throwaway P-384 chain, module_id marks it as a STUB ----------
fake_nsm_attest = local_stubs.fake_nsm_attest
ROOT_CERT, DER = local_stubs.ROOT_CERT, local_stubs.DER
intake_loop.nsm_attest = fake_nsm_attest


# ---------- a buyer export ----------
def jsonl(rows):
    return "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in rows).encode()


def make_export(mutate=None, episodes=4, length=3, winners=3):
    eps = [{"episode_index": e, "length": length, "task_index": 0} for e in range(episodes)]
    frames, idx = [], 0
    for e in range(episodes):
        for f in range(length):
            frames.append({"idx": idx, "episode_index": e, "frame_index": f, "ts": f / 10, "state_x": 10.0, "state_y": 20.0,
                           "action_x": 100 + f, "action_y": 200, "reward": 0.0, "done": f == length - 1,
                           "success": e < winners and f == length - 1, "task_index": 0})
            idx += 1
    if mutate:
        mutate(frames, eps)
    return {"frames": (jsonl(frames), FRAMES_COLS), "episodes": (jsonl(eps), ["episode_index", "length", "task_index"])}


FRAMES_COLS = intake_loop.FRAMES_COLUMNS
BUYER = Ed25519PrivateKey.generate()
BUYER_PUB = BUYER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
BUYER_FP = hashlib.sha256(BUYER_PUB).hexdigest()
CREDS = {"AccessKeyId": "AKIATEST", "SecretAccessKey": "secret", "Token": "token"}
NONCE = "ab" * 16


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def make_request(export, signer=BUYER, expected_fp=BUYER_FP, kms_key=KEY_ID):
    manifest = json.dumps({"tables": {n: {"sha256": hashlib.sha256(d).hexdigest(), "rows": d.count(b"\n"), "columns": cols}
                                      for n, (d, cols) in export.items()}}, sort_keys=True)
    folder = tempfile.mkdtemp(dir=TMP.name)  # seal through buyer_seal, from a connector-style folder
    write(os.path.join(folder, "manifest.json"), manifest.encode())
    for n, (d, _) in export.items():
        write(os.path.join(folder, n + ".jsonl"), d)
    tables = buyer_seal.seal_export(folder, buyer_seal.load_public_key(PUB_PATH))
    return {"creds": CREDS, "nonce": NONCE, "expected_buyer_fp": expected_fp, "manifest": manifest,
            "buyer_sig": signer.sign(manifest.encode()).hex(), "buyer_pubkey": BUYER_PUB.hex(), "tables": tables, "kms_key": kms_key}


class IntakeTests(unittest.TestCase):
    def check_signed(self, reply):
        """Every reply, whatever the verdict, carries a receipt that verifies offline against the stub chain."""
        res = verify_receipt.verify_reply(reply, verify_receipt.x509.load_der_x509_certificate(DER(ROOT_CERT)).public_bytes(serialization.Encoding.PEM))
        self.assertEqual(res["pcr0"], PCR0.hex())
        self.assertTrue(res["chain_validated"])
        self.assertEqual(reply["receipt"]["code_sha256"], hashlib.sha256(read(intake_loop.__file__)).hexdigest())

    def run_req(self, req):
        reply = intake_loop.process_request(req)
        self.check_signed(reply)
        return reply["receipt"], reply

    def void_detail(self, receipt):
        self.assertEqual(receipt["verdict"], "VOID")
        self.assertEqual(receipt["tests"][0]["result"], "VOID")
        return receipt["tests"][0]["detail"]

    def test_happy_path_pass(self):
        r, reply = self.run_req(make_request(make_export()))
        self.assertEqual(r["verdict"], "PASS", r["tests"])
        self.assertEqual([t["id"] for t in r["tests"]], ["T1", "T2", "T3", "T4"])
        self.assertIn("rate=0.7500", r["tests"][3]["detail"])
        self.assertEqual(r["tables"]["frames"]["rows"], 12)
        self.assertEqual((r["format"], r["mode"], r["measured_by"], r["kms_key"]), ("aarloven-intake-test-receipt/1", "test", "enclave", KEY_ID))
        self.assertEqual(r["buyer_pubkey_fp"], BUYER_FP)
        self.assertEqual(reply["receipt"]["nonce"], NONCE)

    def test_tampered_ciphertext_is_void(self):
        req = make_request(make_export())
        ct = bytearray(base64.b64decode(req["tables"]["frames"]["ciphertext_b64"]))
        ct[5] ^= 1
        req["tables"]["frames"]["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode()
        r, _ = self.run_req(req)
        self.assertIn("does not decrypt", self.void_detail(r))

    def test_tampered_row_is_void(self):
        # a validly encrypted table whose row differs from what the manifest (and the buyer's signature) covers
        req = make_request(make_export())
        evil = make_request(make_export(lambda frames, eps: frames[0].update(reward=9.0)))
        req["tables"]["frames"] = evil["tables"]["frames"]
        r, _ = self.run_req(req)
        self.assertIn("SHA-256 differs", self.void_detail(r))

    def test_bad_buyer_signature_is_void(self):
        r, _ = self.run_req(make_request(make_export(), signer=Ed25519PrivateKey.generate()))
        self.assertIn("signature", self.void_detail(r))

    def test_manifest_changed_after_signing_is_void(self):
        req = make_request(make_export())
        req["manifest"] = req["manifest"].replace('"rows"', '"rows" ')
        r, _ = self.run_req(req)
        self.assertIn("signature", self.void_detail(r))

    def test_wrong_expected_fingerprint_is_void(self):
        r, _ = self.run_req(make_request(make_export(), expected_fp="00" * 32))
        self.assertIn("fingerprint", self.void_detail(r))

    def test_kmstool_failure_is_void_with_its_error(self):
        other = KEY_ID.replace("11111111", "99999999")
        r, _ = self.run_req(make_request(make_export(), kms_key=other))
        self.assertIn("kmstool_decrypt_failed:AccessDeniedException", self.void_detail(r))
        self.assertEqual(r["kms_key"], other)

    def test_malformed_kms_key_is_void(self):
        for bad in (None, "", "TBD", KEY_ID.split("/")[1], KEY_ID.replace("eu-north-1", "us-east-1"),
                    KEY_ID.replace("123456789012", "12345"), KEY_ID + "x", "x" + KEY_ID, KEY_ID + "\n", KEY_ID.upper()):
            req = make_request(make_export())
            if bad is None:
                del req["kms_key"]
            else:
                req["kms_key"] = bad
            r, _ = self.run_req(req)
            self.assertEqual(r["verdict"], "VOID", bad)
            self.assertIn("kms_key", self.void_detail(r))
            self.assertEqual(r["kms_key"], "")

    def test_action_out_of_bounds_fails(self):
        r, _ = self.run_req(make_request(make_export(lambda frames, eps: frames[4].update(action_x=513))))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual({t["id"]: t["result"] for t in r["tests"]}, {"T1": "PASS", "T2": "PASS", "T3": "FAIL", "T4": "PASS"})

    def test_frame_count_and_success_rate_fail(self):
        r, _ = self.run_req(make_request(make_export(lambda frames, eps: eps[0].update(length=5), winners=1)))
        self.assertEqual({t["id"]: t["result"] for t in r["tests"]}, {"T1": "PASS", "T2": "FAIL", "T3": "PASS", "T4": "FAIL"})
        self.assertIn("rate=0.2500", r["tests"][3]["detail"])

    def test_schema_mismatch_fails(self):
        r, _ = self.run_req(make_request(make_export(lambda frames, eps: frames[2].pop("reward"))))
        self.assertEqual(r["tests"][0]["result"], "FAIL")
        self.assertEqual(r["verdict"], "FAIL")

    def test_bad_nonce_is_void(self):
        req = make_request(make_export())
        req["nonce"] = "zz"
        reply = intake_loop.process_request(req)
        self.assertEqual(reply["receipt"]["verdict"], "VOID")

    def test_verifier_rejects_altered_receipt(self):
        _, reply = self.run_req(make_request(make_export()))
        bad = copy.deepcopy(reply)
        bad["receipt"]["verdict"] = "FAIL"
        with self.assertRaises(ValueError):
            verify_receipt.verify_reply(bad)


# ---------- canon-2 (fourdb-canon-2): a sealed intake written the way the fourdb connector writes it ----------
def f32s(v):
    """canon-2 f32: the shortest decimal that round-trips float32, as d[.ddd]e+XX (here for simple test values)."""
    import struct
    if v == 0:
        return "0"
    for n in range(1, 10):
        s = "%.*e" % (n - 1, v)
        if struct.unpack("f", struct.pack("f", float(s)))[0] == struct.unpack("f", struct.pack("f", v))[0]:
            break
    m, e = s.split("e")
    if "." in m:
        m = m.rstrip("0").rstrip(".")
    return "%se%+03d" % (m, int(e))


def cline(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def c2_rows(episodes=4, length=3, winners=3):
    eps = [{"episode_index": e, "from_index": e * length, "length": length, "task": "Push T", "to_index": e * length + length} for e in range(episodes)]
    frames, idx = [], 0
    for e in range(episodes):
        for f in range(length):
            frames.append({"idx": idx, "episode_index": e, "frame_index": f, "ts": f32s(f / 10), "state_x": f32s(10.0), "state_y": f32s(20.0),
                           "action_x": f32s(100.0 + f), "action_y": f32s(200.0), "reward": f32s(0.0), "done": f == length - 1,
                           "success": e < winners and f == length - 1, "task_index": 0})
            idx += 1
    return frames, eps


FRAMES_TYPES = {"action_x": "f32", "action_y": "f32", "done": "bool", "episode_index": "int", "frame_index": "int", "idx": "int", "reward": "f32",
                "state_x": "f32", "state_y": "f32", "success": "bool", "task_index": "int", "ts": "f32"}
EPISODES_TYPES = {"episode_index": "int", "from_index": "int", "length": "int", "task": "text", "to_index": "int"}
KEK = os.urandom(32)


def build_canon2(frames=None, eps=None, aad_canon=None, aad_fp=None, lines_override=None, mutate_neutral=None, mode="sealed"):
    """Writes manifest.json + sealed/ like connector.py --mode sealed (one DEK, AAD fourdb-seal-1|canon|fp|table, DEK wrapped by a local KEK)."""
    import hashlib as _h
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if frames is None:
        frames, eps = c2_rows()
    lines = {"episodes": [cline(r) for r in sorted(eps, key=lambda r: r["episode_index"])],
             "frames": [cline(r) for r in sorted(frames, key=lambda r: r["idx"])]}
    lines.update(lines_override or {})
    digest = lambda ls: _h.sha256(b"".join(l.encode() + b"\n" for l in ls)).hexdigest()
    neutral = {"canon": "fourdb-canon-2", "source_tz": "Europe/Copenhagen", "tables": {
        "episodes": {"pk": "episode_index", "rows": len(lines["episodes"]), "sha256": digest(lines["episodes"]), "columns": EPISODES_TYPES, "timestamp_columns": {}},
        "frames": {"pk": "idx", "rows": len(lines["frames"]), "sha256": digest(lines["frames"]), "columns": FRAMES_TYPES, "timestamp_columns": {}}}}
    if mutate_neutral:
        mutate_neutral(neutral)
    fp = _h.sha256(json.dumps(neutral, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ac, af = aad_canon or neutral["canon"], aad_fp or fp
    dek = AESGCM.generate_key(256)
    folder = tempfile.mkdtemp(dir=TMP.name)
    os.mkdir(os.path.join(folder, "sealed"))
    tabs = {}
    for t, ls in lines.items():
        n = os.urandom(12)
        blob = n + AESGCM(dek).encrypt(n, "".join(l + "\n" for l in ls).encode(), f"fourdb-seal-1|{ac}|{af}|{t}".encode())
        write(os.path.join(folder, "sealed", t + ".jsonl.sealed"), blob)
        tabs[t] = {"file": f"sealed/{t}.jsonl.sealed", "sealed_sha256": _h.sha256(blob).hexdigest(), "plaintext_bytes": 0}
    n = os.urandom(12)
    write(os.path.join(folder, "sealed", "dek.wrapped"), n + AESGCM(KEK).encrypt(n, dek, f"fourdb-seal-1-dek|{neutral['canon']}|{fp}".encode()))
    man = {"engine": "sqlite", "exported_at": "2026-10-17T00:00:00+00:00", "mode": mode, "dataset_fingerprint": fp, "neutral_manifest": neutral,
           "informational_not_fingerprinted": {}, "sealed": {"alg": "AES-256-GCM", "key_wrapper": "local-test-kek-v1", "tables": tabs}}
    write(os.path.join(folder, "manifest.json"), json.dumps(man, sort_keys=True, indent=1).encode())
    return folder, fp


def sign_request(part, signer=BUYER, expected_fp=BUYER_FP, kms_key=KEY_ID):
    return dict(part, creds=CREDS, nonce=NONCE, expected_buyer_fp=expected_fp, kms_key=kms_key,
                buyer_sig=signer.sign(part["manifest"].encode()).hex(), buyer_pubkey=BUYER_PUB.hex())


def make_request2(folder=None, **kw):
    if folder is None:
        folder, _ = build_canon2()
    return sign_request(buyer_seal_canon2.bridge(folder, KEK, buyer_seal.load_public_key(PUB_PATH)), **kw)


def resign_manifest(req, mutate):
    man = json.loads(req["manifest"])
    mutate(man)
    req["manifest"] = json.dumps(man, sort_keys=True, indent=1)
    req["buyer_sig"] = BUYER.sign(req["manifest"].encode()).hex()
    return req


class Canon2Tests(unittest.TestCase):
    def run_req(self, req):
        reply = intake_loop.process_request(req)
        res = verify_receipt.verify_reply(reply, local_stubs.ROOT_PEM)
        self.assertEqual((res["format"], res["stub"], res["chain_validated"]), ("aarloven-intake-test-receipt/2", True, True))
        self.assertEqual(reply["receipt"]["code_sha256"], hashlib.sha256(read(intake_loop.__file__)).hexdigest())
        return reply["receipt"], reply

    def void(self, req, needle):
        r, _ = self.run_req(req)
        self.assertEqual(r["verdict"], "VOID")
        self.assertEqual((r["tests"][0]["result"], r["tests"][0]["verdict"], r["dataset_fingerprint"]), ("VOID", "VOID", ""))
        self.assertIn(needle, r["tests"][0]["detail"])
        return r

    def test_happy_path_pass_with_fingerprint(self):
        folder, fp = build_canon2()
        r, reply = self.run_req(make_request2(folder))
        self.assertEqual(r["verdict"], "PASS", r["tests"])
        self.assertEqual((r["format"], r["canon"], r["dataset_fingerprint"], r["mode"], r["kms_key"]), ("aarloven-intake-test-receipt/2", "fourdb-canon-2", fp, "test", KEY_ID))
        man = json.loads(read(os.path.join(folder, "manifest.json")))
        self.assertEqual(r["manifest_sha256"], hashlib.sha256(read(os.path.join(folder, "manifest.json"))).hexdigest())
        self.assertEqual(r["tables"], {t: {"rows": m["rows"], "sha256": m["sha256"]} for t, m in man["neutral_manifest"]["tables"].items()})
        self.assertEqual([(t["id"], t["result"], t["verdict"]) for t in r["tests"]], [(i, "PASS", "PASS") for i in ("T1", "T2", "T3", "T4")])
        self.assertIn("rate=0.7500", r["tests"][3]["detail"])
        self.assertEqual(r["buyer_pubkey_fp"], BUYER_FP)
        res = verify_receipt.verify_reply(reply, local_stubs.ROOT_PEM)
        self.assertEqual((res["canon"], res["dataset_fingerprint"], res["stub"]), ("fourdb-canon-2", fp, True))

    def test_format1_request_still_gets_format1_receipt(self):
        reply = intake_loop.process_request(make_request(make_export()))
        verify_receipt.verify_reply(reply, local_stubs.ROOT_PEM)
        r = reply["receipt"]
        self.assertEqual(r["format"], "aarloven-intake-test-receipt/1")
        self.assertNotIn("canon", r)
        self.assertNotIn("verdict", r["tests"][0])

    def test_t3_t4_fail_honestly_on_canon2_rows(self):
        frames, eps = c2_rows(winners=1)
        frames[4]["action_x"] = f32s(513.0)
        r, _ = self.run_req(make_request2(build_canon2(frames, eps)[0]))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual({t["id"]: t["verdict"] for t in r["tests"]}, {"T1": "PASS", "T2": "PASS", "T3": "FAIL", "T4": "FAIL"})
        self.assertRegex(r["dataset_fingerprint"], "^[0-9a-f]{64}$")  # a FAIL is still a measured dataset

    def test_t1_t2_fail_on_canon2_rows(self):
        frames, eps = c2_rows()
        eps[0]["length"] = 5
        r, _ = self.run_req(make_request2(build_canon2(frames, eps)[0]))
        self.assertEqual({t["id"]: t["verdict"] for t in r["tests"]}, {"T1": "PASS", "T2": "FAIL", "T3": "PASS", "T4": "PASS"})
        frames, eps = c2_rows()
        del frames[3]["reward"]
        r, _ = self.run_req(make_request2(build_canon2(frames, eps)[0]))
        self.assertEqual(r["tests"][0]["verdict"], "FAIL")

    def test_wrong_buyer_signature_is_void(self):
        self.void(make_request2(signer=Ed25519PrivateKey.generate()), "signature")

    def test_wrong_expected_buyer_fingerprint_is_void(self):
        self.void(make_request2(expected_fp="00" * 32), "fingerprint")

    def test_flipped_ciphertext_is_void(self):
        req = make_request2()
        blob = bytearray(base64.b64decode(req["tables"]["frames"]["sealed_b64"]))
        blob[20] ^= 1
        req["tables"]["frames"]["sealed_b64"] = base64.b64encode(bytes(blob)).decode()
        self.void(req, "sealed SHA-256 differs")

    def test_flipped_ciphertext_with_matching_signed_hash_still_fails_gcm(self):
        # a signed manifest that even names the altered blob: the GCM tag still refuses it
        req = make_request2()
        blob = bytearray(base64.b64decode(req["tables"]["frames"]["sealed_b64"]))
        blob[20] ^= 1
        req["tables"]["frames"]["sealed_b64"] = base64.b64encode(bytes(blob)).decode()
        resign_manifest(req, lambda m: m["sealed"]["tables"]["frames"].update(sealed_sha256=hashlib.sha256(bytes(blob)).hexdigest()))
        self.void(req, "does not decrypt")

    def test_wrong_canon_id_in_aad_is_void(self):
        folder, _ = build_canon2(aad_canon="fourdb-canon-1")  # sealed under another canon id, manifest honestly says canon-2
        self.void(make_request2(folder), "does not decrypt")

    def test_wrong_fingerprint_in_aad_is_void(self):
        folder, _ = build_canon2(aad_fp="ab" * 32)
        self.void(make_request2(folder), "does not decrypt")

    def test_tables_swapped_is_void(self):
        req = make_request2()
        t = req["tables"]
        t["frames"], t["episodes"] = t["episodes"], t["frames"]
        self.void(req, "sealed SHA-256 differs")

    def test_manifest_edited_after_signing_is_void(self):
        req = make_request2()
        req["manifest"] = req["manifest"].replace('"rows"', '"rows" ', 1)
        self.void(req, "signature")

    def test_manifest_edited_and_resigned_is_void(self):
        # the buyer signs a manifest whose table digest was edited but whose fingerprint was not: the fingerprint is no longer the hash of the neutral manifest
        req = resign_manifest(make_request2(), lambda m: m["neutral_manifest"]["tables"]["frames"].update(sha256="00" * 32))
        self.void(req, "not the SHA-256 of its neutral manifest")
        # ... and with the fingerprint recomputed too (AAD then changes, so the tables no longer open)
        def both(m):
            m["neutral_manifest"]["tables"]["frames"]["sha256"] = "00" * 32
            m["dataset_fingerprint"] = hashlib.sha256(json.dumps(m["neutral_manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.void(resign_manifest(make_request2(), both), "does not decrypt")

    def test_digest_that_does_not_match_the_rows_is_void(self):
        # sealed with the right AAD for a manifest that lies about the digest (both consistent with each other, signed)
        def lie(n):
            n["tables"]["frames"]["sha256"] = "11" * 32
        folder, _ = build_canon2(mutate_neutral=lie)
        self.void(make_request2(folder), "canon-2 digest differs")

    def test_other_canon_id_is_void(self):
        folder, _ = build_canon2(mutate_neutral=lambda n: n.update(canon="fourdb-canon-1"))
        self.void(make_request2(folder), "canon is not fourdb-canon-2")

    def test_hash_only_manifest_is_void(self):
        self.void(resign_manifest(make_request2(), lambda m: m.update(mode="hash-only")), "not a sealed intake")

    def test_non_canonical_rows_are_void(self):
        frames, eps = c2_rows()
        spaced = [json.dumps(r, sort_keys=True) for r in sorted(frames, key=lambda r: r["idx"])]  # ', ' separators: not canonical
        self.void(make_request2(build_canon2(frames, eps, lines_override={"frames": spaced})[0]), "not a canon-2 canonical row")

    def test_unordered_rows_are_void(self):
        frames, eps = c2_rows()
        lines = [cline(r) for r in sorted(frames, key=lambda r: -r["idx"])]
        self.void(make_request2(build_canon2(frames, eps, lines_override={"frames": lines})[0]), "strictly ascending")

    def test_kms_denied_and_bad_wrapped_key_are_void(self):
        self.void(make_request2(kms_key=KEY_ID.replace("11111111", "99999999")), "AccessDeniedException")
        req = make_request2()
        req["wrapped_dek_b64"] = base64.b64encode(os.urandom(256)).decode()
        self.void(req, "wrapped_dek")

    def test_verifier_rejects_altered_v2_receipt(self):
        _, reply = self.run_req(make_request2())
        for field, value in (("dataset_fingerprint", "00" * 32), ("canon", "fourdb-canon-1")):
            bad = copy.deepcopy(reply)
            bad["receipt"][field] = value
            with self.assertRaises(ValueError):
                verify_receipt.verify_reply(bad)
        # consistent-looking edits are still caught by the signature/attestation
        bad = copy.deepcopy(reply)
        bad["receipt"]["tests"][0]["verdict"] = "FAIL"
        with self.assertRaises(ValueError):
            verify_receipt.verify_reply(bad)

    def test_port_matches_the_connector_when_present(self):
        fourdb = "/workspace/li4db/tools/legacy-intake/fourdb"
        if not os.path.isdir(fourdb):
            self.skipTest("li4db fourdb not present")
        sys.dont_write_bytecode = True
        sys.path.insert(0, fourdb)
        try:
            import connector
        finally:
            sys.path.remove(fourdb)
        row = {"b": None, "a": "\u00e9\u4e2d", "c": [1, {"z": True}], "d": "1.5e+00"}
        self.assertEqual(intake_loop.canon2_line(row), connector.canon_line(row))
        folder, _ = build_canon2()
        neutral = json.loads(read(os.path.join(folder, "manifest.json")))["neutral_manifest"]
        self.assertEqual(intake_loop.canon2_dataset_fingerprint(neutral), connector.dataset_fingerprint(neutral))
        self.assertEqual(intake_loop.CANON2_ID, connector.CANON_VERSION)


class EvidenceTests(unittest.TestCase):
    def test_saved_real_v1_receipt_still_verifies_offline(self):
        with open(os.path.join(HERE, "evidence", "2026-10-16-receipt-honest-FAIL.json")) as f:
            reply = json.load(f)
        res = verify_receipt.verify_reply(reply, read(os.path.join(HERE, "evidence", "nitro-root-G1.pem")))
        self.assertEqual((res["format"], res["verdict"], res["chain_validated"], res["stub"]), ("aarloven-intake-test-receipt/1", "FAIL", True, False))
        self.assertTrue(res["pcr0"].startswith("b0d7bca6"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
