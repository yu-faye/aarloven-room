#!/usr/bin/env python3
"""Turn a fourdb connector sealed intake (`connector.py --mode sealed`) into the canon-2 request for the intake TEST room.

    buyer_seal_canon2.py SEALED_DIR KEK_FILE KMS_PUBLIC_KEY [--out part.json]

SEALED_DIR holds manifest.json and sealed/<table>.jsonl.sealed + sealed/dek.wrapped, as the connector wrote them. The connector wraps
the data key (DEK) with a LOCAL test key-encryption-key (fourdb seal.LocalTestKeyWrapper: AES-256-GCM, context
`fourdb-seal-1-dek|canon|fingerprint`); the room can only unwrap through KMS. This is the buyer-side bridge: it opens the DEK with the
local KEK and wraps it again with RSAES_OAEP_SHA_256 to the room's KMS public key. The sealed tables are NOT touched, so their AAD
(canon id, dataset fingerprint, table) still binds them. Prints {format, manifest, wrapped_dek_b64, tables}; `manifest` is the exact
text of manifest.json. Sign those bytes with your Ed25519 key and add creds, nonce, expected_buyer_fp, buyer_pubkey, buyer_sig, kms_key.
The manifest's `sealed.key_wrapper` still says local-test-kek-v1: it describes how the connector wrapped the key, not the room's path.
"""
import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import buyer_seal

FORMAT = "fourdb-canon-2"


def read(path):
    with open(path, "rb") as f:
        return f.read()


def bridge(sealed_dir: str, kek: bytes, pub) -> dict:
    manifest_bytes = read(os.path.join(sealed_dir, "manifest.json"))
    man = json.loads(manifest_bytes)
    if man.get("mode") != "sealed":
        raise SystemExit("not a sealed intake (mode=%r)" % man.get("mode"))
    canon, fp = man["neutral_manifest"]["canon"], man["dataset_fingerprint"]
    if len(kek) != 32:
        raise SystemExit("the local test KEK must be 32 bytes")
    wrapped = read(os.path.join(sealed_dir, "sealed", "dek.wrapped"))
    dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], f"fourdb-seal-1-dek|{canon}|{fp}".encode())
    b64 = lambda b: base64.b64encode(b).decode()
    return {
        "format": FORMAT,
        "manifest": manifest_bytes.decode("utf-8"),
        "wrapped_dek_b64": b64(pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
        "tables": {t: {"sealed_b64": b64(read(os.path.join(sealed_dir, "sealed", t + ".jsonl.sealed")))} for t in sorted(man["neutral_manifest"]["tables"])},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sealed_dir")
    ap.add_argument("kek_file")
    ap.add_argument("public_key")
    ap.add_argument("--out")
    a = ap.parse_args()
    text = json.dumps(bridge(a.sealed_dir, read(a.kek_file), buyer_seal.load_public_key(a.public_key)))
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
