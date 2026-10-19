#!/usr/bin/env python3
"""Offline replay of a real canon-2 sealed intake (lerobot/pusht) through the intake TEST room's handler, in-process.

    replay_canon2.py --full DIR --subset DIR --kek FILE [--save DIR]

DIR = a fourdb connector output (`connector.py --mode sealed`), --kek = the local test KEK it was sealed with. replay_canon2.sh makes both.
Everything the real room gets from AWS is a stand-in here: kmstool is a fake with a local RSA key, the NSM is a stub (module_id
STUB-NOT-A-NITRO-ENCLAVE, throwaway certificate chain). The receipts it prints are therefore NOT evidence that any enclave ran.
What IS exercised for real: intake_loop.py's canon-2 handling (signature, AAD, digests, fingerprint re-derivation, T1-T4, receipt/2) on the real rows.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASELINE_FP = "06a0fb071b22183d0288a704925260fdb6f201e3bd0756e9e3ec8ad1c530b843"  # fourdb 4-engine baseline: episodes + frames + operators
KEY_ARN = "arn:aws:kms:eu-north-1:000000000000:key/00000000-0000-0000-0000-000000000000"  # fake; the fake kmstool compares it as a string


def read(p):
    with open(p, "rb") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--full", required=True)
    ap.add_argument("--subset", required=True)
    ap.add_argument("--kek", required=True)
    ap.add_argument("--save")
    a = ap.parse_args()

    tmp = tempfile.TemporaryDirectory()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_path = os.path.join(tmp.name, "kms_priv.pem")
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    import local_stubs
    local_stubs.install_fake_kmstool(tmp.name, KEY_ARN, priv_path)
    import buyer_seal_canon2
    import intake_loop
    import verify_receipt
    intake_loop.nsm_attest = local_stubs.fake_nsm_attest
    pub, kek = priv.public_key(), read(a.kek)
    buyer = Ed25519PrivateKey.generate()
    buyer_pub = buyer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    buyer_fp = hashlib.sha256(buyer_pub).hexdigest()
    creds = {"AccessKeyId": "STUB", "SecretAccessKey": "STUB", "Token": "STUB"}
    problems = []

    def check(ok, what):
        print(("  ok   " if ok else "  FAIL ") + what)
        if not ok:
            problems.append(what)

    def request(folder, mutate_manifest=None, signer=buyer, mutate=None):
        req = buyer_seal_canon2.bridge(folder, kek, pub)
        if mutate_manifest:
            man = json.loads(req["manifest"])
            mutate_manifest(man)
            req["manifest"] = json.dumps(man, sort_keys=True, indent=1)
        req.update(creds=creds, nonce=os.urandom(16).hex(), expected_buyer_fp=buyer_fp, kms_key=KEY_ARN, buyer_pubkey=buyer_pub.hex())
        if mutate:
            mutate(req)
        req["buyer_sig"] = signer.sign(req["manifest"].encode()).hex()
        return req

    def run(req):
        reply = intake_loop.process_request(req)
        res = verify_receipt.verify_reply(reply, local_stubs.ROOT_PEM)
        assert res["stub"] and res["format"] == "aarloven-intake-test-receipt/2"
        return reply, res

    saved = {}
    expectations = {}
    for label, folder in (("full (episodes, frames, operators)", a.full), ("pusht-only subset (episodes, frames)", a.subset)):
        man = json.loads(read(os.path.join(folder, "manifest.json")))
        connector_fp = man["dataset_fingerprint"]
        print(f"\n== {label}: connector fingerprint {connector_fp}")
        print("   tables:", {t: m["rows"] for t, m in man["neutral_manifest"]["tables"].items()})
        reply, res = run(request(folder))
        r = reply["receipt"]
        for t in r["tests"]:
            print(f"   {t['id']} {t['verdict']}: {t['detail']}")
        print(f"   receipt/2 verdict {r['verdict']}, canon {r['canon']}, dataset_fingerprint {r['dataset_fingerprint']}")
        print(f"   STUB attestation: module_id {res['module_id']} (not a Nitro Enclave; PCR0 is a placeholder)")
        check(r["dataset_fingerprint"] == connector_fp, "room's re-derived dataset_fingerprint == the connector's own")
        check(all(r["tables"][t]["sha256"] == m["sha256"] and r["tables"][t]["rows"] == m["rows"] for t, m in man["neutral_manifest"]["tables"].items()),
              "per-table canon-2 digests and row counts re-derived in the room == connector's")
        check(r["manifest_sha256"] == hashlib.sha256(read(os.path.join(folder, "manifest.json"))).hexdigest(), "manifest_sha256 is the hash of the manifest bytes the buyer signed")
        check({t["id"]: t["verdict"] for t in r["tests"]} == {"T1": "PASS", "T2": "PASS", "T3": "PASS", "T4": "FAIL"} and r["verdict"] == "FAIL",
              "T1-T3 PASS, T4 FAIL (0 of 206 episodes succeed), verdict FAIL - unchanged from the real v1 receipt")
        check(r["tests"][3]["detail"].startswith("rate=0.0000 (0/206)"), "T4 detail is 0/206 as in the saved real receipt")
        expectations[label] = connector_fp
        saved[label.split()[0]] = {"STUB": "local replay: stub NSM, fake kmstool, NOT an enclave, NOT evidence of PCR0", "reply": reply}

    full_fp, subset_fp = expectations["full (episodes, frames, operators)"], expectations["pusht-only subset (episodes, frames)"]
    print("\n== fingerprints")
    check(full_fp == BASELINE_FP, f"full intake fingerprint == fourdb baseline {BASELINE_FP[:12]}...")
    check(subset_fp != BASELINE_FP, "pusht-only subset fingerprint differs from the baseline, as it must: its neutral manifest has no operators table "
                                    f"(subset {subset_fp[:12]}...); it equals the connector's own fingerprint for the same two tables (checked above)")

    print("\n== tamper cases on the full intake (each must be VOID, with no dataset_fingerprint)")
    f = a.full

    def expect_void(name, req, needle):
        reply, _ = run(req)
        r = reply["receipt"]
        d = r["tests"][0]["detail"]
        check(r["verdict"] == "VOID" and r["dataset_fingerprint"] == "" and needle in d, f"{name}: VOID ({d[:90]})")

    expect_void("wrong buyer signature", request(f, signer=Ed25519PrivateKey.generate()), "signature")

    def flip(req):
        b = bytearray(base64.b64decode(req["tables"]["frames"]["sealed_b64"]))
        b[100] ^= 1
        req["tables"]["frames"]["sealed_b64"] = base64.b64encode(bytes(b)).decode()
    expect_void("flipped ciphertext bit", request(f, mutate=flip), "sealed SHA-256 differs")

    def flip_signed(req):
        b = bytearray(base64.b64decode(req["tables"]["episodes"]["sealed_b64"]))
        b[100] ^= 1
        man = json.loads(req["manifest"])
        man["sealed"]["tables"]["episodes"]["sealed_sha256"] = hashlib.sha256(bytes(b)).hexdigest()
        req["tables"]["episodes"]["sealed_b64"] = base64.b64encode(bytes(b)).decode()
        req["manifest"] = json.dumps(man, sort_keys=True, indent=1)
    expect_void("flipped ciphertext bit, hash in the (re-signed) manifest fixed up: GCM tag", request(f, mutate=flip_signed), "does not decrypt")

    # wrong canon id in the AAD: the same rows sealed under AAD ...|fourdb-canon-1|..., hash fixed up and re-signed by the buyer
    man = json.loads(read(os.path.join(f, "manifest.json")))
    part = buyer_seal_canon2.bridge(f, kek, pub)
    dek = AESGCM(kek).decrypt(*(lambda w: (w[:12], w[12:], f"fourdb-seal-1-dek|{man['neutral_manifest']['canon']}|{man['dataset_fingerprint']}".encode()))(read(os.path.join(f, "sealed", "dek.wrapped"))))
    old = base64.b64decode(part["tables"]["episodes"]["sealed_b64"])
    plain = AESGCM(dek).decrypt(old[:12], old[12:], f"fourdb-seal-1|fourdb-canon-2|{man['dataset_fingerprint']}|episodes".encode())
    check(len(plain) > 0, "(setup) episodes decrypts with the right AAD using the buyer-side DEK")
    bad = old[:12] + AESGCM(dek).encrypt(old[:12], plain, f"fourdb-seal-1|fourdb-canon-1|{man['dataset_fingerprint']}|episodes".encode())

    def wrong_aad(req):
        m = json.loads(req["manifest"])
        m["sealed"]["tables"]["episodes"]["sealed_sha256"] = hashlib.sha256(bad).hexdigest()
        req["tables"]["episodes"]["sealed_b64"] = base64.b64encode(bad).decode()
        req["manifest"] = json.dumps(m, sort_keys=True, indent=1)
    expect_void("wrong canon id in the AAD", request(f, mutate=wrong_aad), "does not decrypt")

    req = request(f)
    req["manifest"] = req["manifest"].replace('"rows": 206', '"rows": 207', 1)  # signature no longer matches
    reply, _ = run(req)
    check(reply["receipt"]["verdict"] == "VOID" and "signature" in reply["receipt"]["tests"][0]["detail"], "manifest edited after signing: VOID (signature)")
    expect_void("manifest edited and re-signed (table digest changed, fingerprint not)",
                request(f, mutate_manifest=lambda m: m["neutral_manifest"]["tables"]["episodes"].update(rows=207)), "not the SHA-256 of its neutral manifest")
    expect_void("canon id edited and re-signed", request(f, mutate_manifest=lambda m: m["neutral_manifest"].update(canon="fourdb-canon-1")), "canon is not fourdb-canon-2")

    if a.save:
        os.makedirs(a.save, exist_ok=True)
        for k, v in saved.items():
            with open(os.path.join(a.save, f"replay-{k}-STUB-receipt2.json"), "w") as fh:
                json.dump(v, fh, indent=1)
        print("\nsaved stub replies in", a.save)
    print("\nRESULT:", "ALL AS EXPECTED" if not problems else f"{len(problems)} UNEXPECTED: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
