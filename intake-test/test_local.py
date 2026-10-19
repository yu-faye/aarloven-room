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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

TMP = tempfile.TemporaryDirectory()
atexit.register(TMP.cleanup)
KEY_ID = "arn:aws:kms:eu-north-1:123456789012:key/11111111-2222-3333-4444-555555555555"
RSA_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV_PATH = os.path.join(TMP.name, "kms_priv.pem")
PUB_PATH = os.path.join(TMP.name, "kms_pub.der")
FAKE_KMSTOOL = os.path.join(TMP.name, "fake_kmstool")
with open(PRIV_PATH, "wb") as f:
    f.write(RSA_PRIV.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
with open(PUB_PATH, "wb") as f:
    f.write(RSA_PRIV.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
with open(FAKE_KMSTOOL, "w") as f:
    f.write(f'''#!{sys.executable}
import base64, os, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
a = sys.argv[1:]
opt = {{a[i]: a[i + 1] for i in range(1, len(a) - 1) if a[i].startswith("--")}}
if a[0] != "decrypt" or opt.get("--encryption-algorithm") != "RSAES_OAEP_SHA_256":
    sys.exit("fake kmstool: bad invocation")
if opt.get("--key-id") != os.environ["FAKE_KMS_KEY"]:
    print("AccessDeniedException: key policy does not allow this enclave", file=sys.stderr); sys.exit(1)
priv = serialization.load_pem_private_key(open(os.environ["FAKE_KMS_PRIV"], "rb").read(), None)
try:
    pt = priv.decrypt(base64.b64decode(opt["--ciphertext"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
except Exception:
    print("InvalidCiphertextException", file=sys.stderr); sys.exit(1)
print("PLAINTEXT: " + base64.b64encode(pt).decode())
''')
os.chmod(FAKE_KMSTOOL, stat.S_IRWXU)
os.environ.update(KMSTOOL_CLI=FAKE_KMSTOOL, FAKE_KMS_KEY=KEY_ID, FAKE_KMS_PRIV=PRIV_PATH)

import buyer_seal  # noqa: E402
import intake_loop  # noqa: E402
import verify_receipt  # noqa: E402

PCR0 = bytes(range(48))


# ---------- a stubbed NSM: a COSE_Sign1 document signed by a throwaway P-384 chain ----------
def cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def _cert(subject, key, issuer_name, issuer_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer_name)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(issuer_key, hashes.SHA384()))


ROOT_KEY, LEAF_KEY = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
ROOT_CERT = _cert("test-root", ROOT_KEY, "test-root", ROOT_KEY)
LEAF_CERT = _cert("test-leaf", LEAF_KEY, "test-root", ROOT_KEY)
DER = lambda c: c.public_bytes(serialization.Encoding.DER)


def fake_nsm_attest(user_data, nonce, public_key):
    payload = cbor({"module_id": "i-test", "digest": "SHA384", "timestamp": int(datetime.datetime.now().timestamp() * 1000),
                    "pcrs": {0: PCR0}, "certificate": DER(LEAF_CERT), "cabundle": [DER(ROOT_CERT)],
                    "public_key": public_key, "user_data": user_data, "nonce": nonce})
    protected = cbor({1: 0})  # alg label; the value is not checked by the verifier
    to_sign = b"\x84\x6aSignature1" + verify_receipt.cbor_bstr_head(len(protected)) + protected \
        + b"\x40" + verify_receipt.cbor_bstr_head(len(payload)) + payload
    r, s = decode_dss_signature(LEAF_KEY.sign(to_sign, ec.ECDSA(hashes.SHA384())))
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return b"\xd2" + cbor([protected, {}, payload, sig])  # tag 18 + COSE_Sign1


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
