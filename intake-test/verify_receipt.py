#!/usr/bin/env python3
"""Offline check of a reply from the intake TEST room: {receipt, sig, attestation_b64}.

    verify_receipt.py REPLY.json [--root AWS_NITRO_ROOT.pem] [--expect-pcr0 HEX]

Checks, and prints PCR0 from the attestation document:
- the attestation's user_data == SHA-256 of the canonical receipt, its nonce == receipt.nonce, and its
  public_key is the key that made `sig` (Ed25519 over the canonical receipt);
- the COSE_Sign1 signature (ES384) of the document under the certificate it carries;
- the certificate chain (cabundle -> certificate), when --root is given: the first cabundle certificate must be that
  root, and each certificate must be signed by the one before it. Without --root the chain is NOT validated and the
  output says so. TODO: fetch/pin the AWS Nitro root (https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)
  here, and check revocation, which Nitro documents do not offer.
"""
import argparse
import base64
import hashlib
import json
import re
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cbor_decode(data: bytes):
    """A small CBOR decoder: definite lengths, plus indefinite-length maps/arrays (real NSM documents use them)."""
    def item(i):
        major, info = data[i] >> 5, data[i] & 31
        i += 1
        if info < 24:
            val = info
        elif info in (24, 25, 26, 27):
            n = 1 << (info - 24)
            val = int.from_bytes(data[i:i + n], "big")
            i += n
        elif info == 31 and major in (4, 5):
            out = [] if major == 4 else {}
            while data[i] != 0xFF:
                if major == 4:
                    v, i = item(i)
                    out.append(v)
                else:
                    k, i = item(i)
                    out[k], i = item(i)
            return out, i + 1
        else:
            raise ValueError("unsupported CBOR item")
        if major == 0:
            return val, i
        if major == 1:
            return -1 - val, i
        if major in (2, 3):
            raw = data[i:i + val]
            if len(raw) != val:
                raise ValueError("truncated CBOR")
            return (raw if major == 2 else raw.decode()), i + val
        if major == 4:
            out = []
            for _ in range(val):
                v, i = item(i)
                out.append(v)
            return out, i
        if major == 5:
            out = {}
            for _ in range(val):
                k, i = item(i)
                out[k], i = item(i)
            return out, i
        if major == 6:
            return item(i)  # a tag: the value is what matters here
        if info == 20 or info == 21:
            return info == 21, i
        if info == 22:
            return None, i
        raise ValueError("unsupported CBOR simple value")
    value, end = item(0)
    if end != len(data):
        raise ValueError("trailing bytes after CBOR")
    return value


def cbor_bstr_head(n: int) -> bytes:
    if n < 24:
        return bytes([0x40 | n])
    if n < 256:
        return bytes([0x58, n])
    if n < 65536:
        return b"\x59" + struct.pack(">H", n)
    return b"\x5a" + struct.pack(">I", n)


def verify_cose(doc: bytes) -> dict:
    """Checks the COSE_Sign1 signature under the document's own certificate; returns the payload."""
    protected, _, payload, sig = cbor_decode(doc)
    sig_structure = b"\x84\x6aSignature1" + cbor_bstr_head(len(protected)) + protected + b"\x40" + cbor_bstr_head(len(payload)) + payload
    claims = cbor_decode(payload)
    leaf = x509.load_der_x509_certificate(claims["certificate"])
    half = len(sig) // 2
    leaf.public_key().verify(encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big")),
                             sig_structure, ec.ECDSA(hashes.SHA384()))
    return claims


def verify_chain(claims: dict, root_pem: bytes) -> None:
    root = x509.load_pem_x509_certificate(root_pem)
    chain = [x509.load_der_x509_certificate(c) for c in claims["cabundle"]] + [x509.load_der_x509_certificate(claims["certificate"])]
    if chain[0].public_bytes(serialization.Encoding.DER) != root.public_bytes(serialization.Encoding.DER):
        raise ValueError("the first cabundle certificate is not the given root")
    stamp = claims["timestamp"] / 1000
    for parent, child in zip(chain, chain[1:]):
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        for c in (parent, child):
            if not (c.not_valid_before_utc.timestamp() <= stamp <= c.not_valid_after_utc.timestamp()):
                raise ValueError("a certificate was not valid when the document was made")


def check_receipt_v2(receipt: dict) -> None:
    """Format-2 receipts (canon-2): the added fields must be there and consistent; ValueError otherwise.
    This checks the receipt's own consistency; it cannot say the fingerprint is the one the buyer meant (see --expect-fingerprint)."""
    hex64 = re.compile(r"[0-9a-f]{64}")
    if receipt.get("canon") != "fourdb-canon-2":
        raise ValueError("receipt/2: canon is not fourdb-canon-2")
    if not hex64.fullmatch(str(receipt.get("manifest_sha256", ""))):
        raise ValueError("receipt/2: manifest_sha256 missing")
    tests = receipt["tests"]
    for t in tests:
        if t.get("verdict") != t.get("result"):
            raise ValueError("receipt/2: a test's verdict and result differ")
    for k in ("opt_in", "legacy_policy", "omitted_columns"):
        if not isinstance(receipt.get(k), dict):
            raise ValueError(f"receipt/2: {k} missing (it must be an object, empty when there is none)")
    verdict, results = receipt["verdict"], [t.get("verdict") for t in tests]
    if verdict == "VOID":
        v0 = next((t for t in tests if t.get("id") == "V0"), None)  # by id: not necessarily the first entry
        if receipt.get("dataset_fingerprint") != "" or v0 is None or v0.get("verdict") != "VOID":
            raise ValueError("receipt/2: a VOID receipt must have no dataset_fingerprint and a V0 VOID test")
        if receipt["opt_in"] or receipt["legacy_policy"] or receipt["omitted_columns"]:
            raise ValueError("receipt/2: a VOID receipt must not surface policies (the manifest was not validated)")
        return
    if verdict not in ("PASS", "FAIL", "N/A"):
        raise ValueError(f"receipt/2: unknown verdict {verdict!r}")
    if not tests or "VOID" in results:
        raise ValueError("receipt/2: a measured receipt needs tests and no VOID test")
    if verdict == "PASS" and not all(r == "PASS" for r in results):
        raise ValueError("receipt/2: PASS but a test did not pass")
    if verdict == "N/A" and not all(r == "N/A" for r in results):
        raise ValueError("receipt/2: N/A verdict but a test ran")
    if verdict == "FAIL" and not ("FAIL" in results and "N/A" not in results):
        raise ValueError("receipt/2: FAIL without a failed test")
    if not hex64.fullmatch(str(receipt.get("dataset_fingerprint", ""))):
        raise ValueError("receipt/2: PASS/FAIL/N/A receipt without a dataset_fingerprint")
    if not all(hex64.fullmatch(str(v.get("sha256", ""))) for v in receipt["tables"].values()) or not receipt["tables"]:
        raise ValueError("receipt/2: per-table canon-2 digests missing")


def verify_reply(reply: dict, root_pem: bytes = None) -> dict:
    """Returns {"pcr0", "verdict", "chain_validated", "format", "module_id", "stub", plus "canon" and "dataset_fingerprint" for
    format 2}; raises ValueError (or a cryptography error) on any mismatch."""
    receipt, sig = reply["receipt"], bytes.fromhex(reply["sig"])
    raw = canon(receipt).encode()
    if not reply.get("attestation_b64"):
        raise ValueError("no attestation in the reply" + (": " + reply["attest_error"] if reply.get("attest_error") else ""))
    claims = verify_cose(base64.b64decode(reply["attestation_b64"]))
    if claims["user_data"] != hashlib.sha256(raw).digest():
        raise ValueError("attestation user_data is not the SHA-256 of the receipt")
    if claims["nonce"] != bytes.fromhex(receipt["nonce"]):
        raise ValueError("attestation nonce is not the receipt's nonce")
    Ed25519PublicKey.from_public_bytes(claims["public_key"]).verify(sig, raw)  # raises InvalidSignature
    chain_validated = False
    if root_pem:
        verify_chain(claims, root_pem)  # raises on any problem
        chain_validated = True
    fmt = receipt.get("format")
    if fmt == "aarloven-intake-test-receipt/2":
        check_receipt_v2(receipt)
    elif fmt != "aarloven-intake-test-receipt/1":
        raise ValueError(f"unknown receipt format {fmt!r}")
    module_id = claims.get("module_id", "")
    res = {"pcr0": claims["pcrs"][0].hex(), "verdict": receipt["verdict"], "chain_validated": chain_validated,
           "format": fmt, "module_id": module_id, "stub": str(module_id).startswith("STUB")}
    if fmt.endswith("/2"):
        res.update(canon=receipt["canon"], dataset_fingerprint=receipt["dataset_fingerprint"], opt_in=receipt["opt_in"],
                   legacy_policy=receipt["legacy_policy"], omitted_columns=receipt["omitted_columns"])
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reply")
    ap.add_argument("--root", help="the AWS Nitro root certificate (PEM), to validate the chain")
    ap.add_argument("--expect-pcr0", help="fail unless PCR0 is this")
    ap.add_argument("--expect-fingerprint", help="format 2: fail unless dataset_fingerprint is this (the one agreed out of band)")
    a = ap.parse_args()
    with open(a.reply, encoding="utf-8") as f:
        reply = json.load(f)
    try:
        root = None
        if a.root:
            with open(a.root, "rb") as f:
                root = f.read()
        res = verify_reply(reply, root)
    except Exception as e:
        print(f"INVALID: {type(e).__name__}: {e}")
        return 1
    print("signature, attestation user_data, nonce and public key: OK")
    print("certificate chain:", "OK" if res["chain_validated"] else "NOT VALIDATED (no --root; the document is not proven to come from AWS)")
    if res["stub"]:
        print("WARNING: STUB attestation (module_id %s): produced by a local test stub, NOT by a Nitro Enclave; the PCR0 below means nothing" % res["module_id"])
    print("receipt format:", res["format"])
    if "canon" in res:
        print("canon:", res["canon"])
        print("dataset_fingerprint:", res["dataset_fingerprint"] or "(none: VOID)")
        for k, what in (("opt_in", "opt-in policies"), ("legacy_policy", "legacy policy"), ("omitted_columns", "omitted columns (NOT covered by the fingerprint's rows)")):
            print(f"{what}:", json.dumps(res[k], sort_keys=True) if res[k] else "none")
        if res["opt_in"].get("timestamp_tz"):
            print("note: timestamp_tz.declared_zone is the SELLER'S statement; nothing verified it")
    print("verdict:", res["verdict"] + (" (no test applies to this dataset; this is not a pass)" if res["verdict"] == "N/A" else ""))
    print("PCR0:", res["pcr0"])
    if a.expect_fingerprint and a.expect_fingerprint.lower() != res.get("dataset_fingerprint"):
        print("dataset_fingerprint differs from --expect-fingerprint (or the receipt has none)")
        return 1
    if a.expect_pcr0 and a.expect_pcr0.lower() != res["pcr0"]:
        print("PCR0 differs from --expect-pcr0")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
