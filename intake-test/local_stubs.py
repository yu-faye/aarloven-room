"""Local stand-ins for the two things only a real enclave has. NOT a Nitro Enclave, NOT AWS.
- a fake kmstool_enclave_cli: RSAES_OAEP_SHA_256 decrypt with a local RSA private key (the real one asks KMS, which checks PCR0);
- a stubbed NSM: a COSE_Sign1 document signed by a throwaway P-384 chain, with module_id STUB_MODULE_ID and a PCR0 that is
  plainly a placeholder. verify_receipt.py prints a STUB warning for such a document.
Used by test_local.py and replay_canon2.py. No network, no AWS.
"""
import datetime
import os
import stat
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

import verify_receipt

STUB_MODULE_ID = "STUB-NOT-A-NITRO-ENCLAVE"
STUB_PCR0 = b"STUB-NOT-A-REAL-PCR0".ljust(48, b"\0")


def install_fake_kmstool(directory: str, key_arn: str, priv_pem_path: str) -> str:
    """Writes the fake kmstool into `directory` and points the environment at it. Returns its path."""
    path = os.path.join(directory, "fake_kmstool")
    with open(path, "w") as f:
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
    os.chmod(path, stat.S_IRWXU)
    os.environ.update(KMSTOOL_CLI=path, FAKE_KMS_KEY=key_arn, FAKE_KMS_PRIV=priv_pem_path)
    return path


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
ROOT_CERT = _cert("STUB-root", ROOT_KEY, "STUB-root", ROOT_KEY)
LEAF_CERT = _cert("STUB-leaf", LEAF_KEY, "STUB-root", ROOT_KEY)
DER = lambda c: c.public_bytes(serialization.Encoding.DER)
ROOT_PEM = ROOT_CERT.public_bytes(serialization.Encoding.PEM)


def fake_nsm_attest(user_data, nonce, public_key):
    payload = cbor({"module_id": STUB_MODULE_ID, "digest": "SHA384", "timestamp": int(datetime.datetime.now().timestamp() * 1000),
                    "pcrs": {0: STUB_PCR0}, "certificate": DER(LEAF_CERT), "cabundle": [DER(ROOT_CERT)],
                    "public_key": public_key, "user_data": user_data, "nonce": nonce})
    protected = cbor({1: 0})  # alg label; the value is not checked by the verifier
    to_sign = b"\x84\x6aSignature1" + verify_receipt.cbor_bstr_head(len(protected)) + protected \
        + b"\x40" + verify_receipt.cbor_bstr_head(len(payload)) + payload
    r, s = decode_dss_signature(LEAF_KEY.sign(to_sign, ec.ECDSA(hashes.SHA384())))
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return b"\xd2" + cbor([protected, {}, payload, sig])  # tag 18 + COSE_Sign1
