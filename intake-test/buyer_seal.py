#!/usr/bin/env python3
"""Seal a connector export for the intake TEST room.

    buyer_seal.py EXPORT_DIR KMS_PUBLIC_KEY [--out tables.json]

EXPORT_DIR holds manifest.json and one <table>.jsonl per table named in manifest["tables"]. KMS_PUBLIC_KEY is the
test key's RSA public key from KMS GetPublicKey (DER or PEM). Each table gets a fresh AES-256 key, is encrypted with
AES-256-GCM (AAD = table name), and the key is wrapped with RSAES_OAEP_SHA_256. Prints the request's `tables` object.
The manifest itself is not changed: sign its exact bytes with your Ed25519 key and send them as `manifest`.
"""
import argparse
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    loader = serialization.load_pem_public_key if data.lstrip().startswith(b"-----BEGIN") else serialization.load_der_public_key
    key = loader(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise SystemExit("the public key is not an RSA key")
    return key


def seal_table(pub, name: str, plaintext: bytes) -> dict:
    key, iv = AESGCM.generate_key(bit_length=256), os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext, name.encode())
    wrapped = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"wrapped_key_b64": b64(wrapped), "iv_b64": b64(iv), "ciphertext_b64": b64(ct)}


def seal_export(export_dir: str, pub) -> dict:
    with open(os.path.join(export_dir, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    tables = manifest.get("tables")
    if not isinstance(tables, dict) or not tables:
        raise SystemExit("manifest.json has no tables")
    out = {}
    for name, info in sorted(tables.items()):
        with open(os.path.join(export_dir, name + ".jsonl"), "rb") as f:
            data = f.read()
        if isinstance(info, dict) and info.get("sha256") not in (None, hashlib.sha256(data).hexdigest()):
            raise SystemExit(f"{name}.jsonl does not match the SHA-256 in manifest.json")
        out[name] = seal_table(pub, name, data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export_dir")
    ap.add_argument("public_key")
    ap.add_argument("--out", help="write here instead of stdout")
    a = ap.parse_args()
    text = json.dumps(seal_export(a.export_dir, load_public_key(a.public_key)), indent=1)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
