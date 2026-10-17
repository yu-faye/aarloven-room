#!/usr/bin/env python3
"""Aarloven intake TEST room, inside an AWS Nitro Enclave. This is a test image, not Room v6.

One JSON request per vsock connection (port 5006, same framing as enclave_loop.py): short-lived AWS credentials, a
nonce, the buyer's Ed25519 key and signature over the manifest, and the buyer's legacy-DB export, one AES-256-GCM
ciphertext per table, each table key wrapped by KMS (RSAES_OAEP_SHA_256) to the test key.
1. Checks the buyer: the public key's fingerprint is the expected one, and the signature over the manifest verifies.
2. Unwraps each table key through kmstool_enclave_cli (KMS checks this enclave's PCR0 first) and opens the table.
3. Checks each table's SHA-256 and row count against the manifest. Any mismatch: VOID, nothing is tested.
4. Runs T1..T4 on `frames` and `episodes`. The verdict is PASS only when all four pass, else FAIL.
5. Signs a receipt with an Ed25519 key made in memory at start, and asks the NSM for an attestation document over
   the receipt's SHA-256, the nonce and that public key. The image's PCR0 is read from that document.

Two request formats. Without a `format` field: the prototype format 1 above (receipt `aarloven-intake-test-receipt/1`).
With `"format": "fourdb-canon-2"` (canon-2 draft, 2026-10-17): the buyer's sealed intake as the fourdb connector writes it
(`--mode sealed`): `manifest` is the exact bytes of its manifest.json (neutral manifest + dataset fingerprint + sealed block),
the buyer signs those bytes, `tables[name].sealed_b64` is nonce||ciphertext||tag of the canonical JSONL (AES-256-GCM, AAD
`fourdb-seal-1|canon|dataset_fingerprint|table`) and `wrapped_dek_b64` is the one data key wrapped by KMS (RSAES_OAEP_SHA_256).
The room re-derives each table digest and the dataset fingerprint from the decrypted rows (a self-contained port of the
canon-2 hashing rules, see CANON.md in the li4db repo) and answers with receipt `aarloven-intake-test-receipt/2`.
"""
from __future__ import annotations

import base64
import copy
import ctypes
import datetime
import decimal
import hashlib
import hmac
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import traceback
import unicodedata

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LISTEN_PORT = int(os.environ.get("INTAKE_VSOCK_PORT", "5006"))
REGION = os.environ.get("REGION", "eu-north-1")
PROXY_PORT = os.environ.get("KMS_PROXY_PORT", "8000")
KMSTOOL = os.environ.get("KMSTOOL_CLI", "/app/kmstool_enclave_cli")
NSM_LIB = os.environ.get("NSM_LIB", "/usr/lib64/libnsm.so")
MAX_REQUEST = int(os.environ.get("INTAKE_MAX_REQUEST", str(128 * 1024 * 1024)))

RECEIPT_FORMAT = "aarloven-intake-test-receipt/1"
RECEIPT_FORMAT_V2 = "aarloven-intake-test-receipt/2"
REQUEST_FORMAT_CANON2 = "fourdb-canon-2"
CANON2_ID = "fourdb-canon-2"
SEAL_AAD = "fourdb-seal-1"  # fourdb seal.py: AAD = SEAL_AAD|canon|dataset_fingerprint|table
FRAMES_COLUMNS = ["idx", "episode_index", "frame_index", "ts", "state_x", "state_y",
                  "action_x", "action_y", "reward", "done", "success", "task_index"]
ACTION_MIN, ACTION_MAX = 0, 512
MIN_SUCCESS_RATE = 0.5
NONCE_RE = re.compile(r"[0-9a-f]{32,128}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KMS_KEY_RE = re.compile(r"arn:aws:kms:eu-north-1:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# made here at boot, never written anywhere, gone when the enclave stops
_SIGNER = Ed25519PrivateKey.generate()
SIGNING_PUB = _SIGNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_nsm = None


def canon(obj) -> str:
    """Canonical JSON: sorted keys, no spaces, UTF-8 as is."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def nsm_attest(user_data: bytes, nonce: bytes, public_key: bytes) -> bytes:
    """An attestation document from the Nitro Secure Module, through libnsm (as kmstool uses it)."""
    global _nsm
    if _nsm is None:
        lib = ctypes.CDLL(NSM_LIB)
        lib.nsm_lib_init.restype = ctypes.c_int32
        lib.nsm_get_attestation_doc.restype = ctypes.c_int
        lib.nsm_get_attestation_doc.argtypes = [
            ctypes.c_int32,
            ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32),
        ]
        fd = lib.nsm_lib_init()
        if fd < 0:
            raise RuntimeError(f"nsm_init:{fd}")
        _nsm = (lib, fd)
    lib, fd = _nsm
    size = ctypes.c_uint32(16 * 1024)
    buf = (ctypes.c_uint8 * size.value)()
    rc = lib.nsm_get_attestation_doc(
        fd, user_data, len(user_data), nonce or None, len(nonce), public_key, len(public_key), buf, ctypes.byref(size)
    )
    if rc != 0:
        raise RuntimeError(f"nsm_attest:{rc}")
    return bytes(buf[: size.value])


def kmstool_error_text(out: str, limit: int = 400) -> str:
    """The part of kmstool's output that says why it failed, at most `limit` characters.

    kmstool logs many [INFO]/[DEBUG]/[TRACE] lines (event loop, DNS, ...) before the real error (e.g. KMS
    AccessDeniedException), so the first 400 characters showed only INFO noise (real run 2026-10-17, debug-mode reply).
    Drop those log lines and keep the TAIL; if nothing else is left, keep the tail of the whole output."""
    text = (out or "").strip()
    if not text:
        return "kmstool_decrypt_failed"
    kept = [l for l in text.splitlines() if l.strip() and not re.match(r"^\[(INFO|DEBUG|TRACE)\]", l.strip())]
    msg = "\n".join(kept) if kept else text
    return msg[-limit:]


def kms_decrypt_room_key(creds: dict, wrapped_b64: str, key_id: str = None, algorithm: str = None) -> bytes:
    """Decrypt a KMS-wrapped key inside enclave. Plaintext stays local."""
    cmd = [
        KMSTOOL,
        "decrypt",
        "--region", REGION,
        "--proxy-port", PROXY_PORT,
        "--aws-access-key-id", creds["AccessKeyId"],
        "--aws-secret-access-key", creds["SecretAccessKey"],
        "--aws-session-token", creds["Token"],
        "--ciphertext", wrapped_b64,
    ]
    if key_id:
        cmd += ["--key-id", key_id, "--encryption-algorithm", algorithm]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"kmstool_decrypt_failed:{kmstool_error_text(proc.stderr or proc.stdout)}")
    plaintext_b64 = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("PLAINTEXT:"):
            plaintext_b64 = line.split(":", 1)[1].strip()
            break
    if not plaintext_b64:
        raise RuntimeError("kmstool_decrypt_no_plaintext_line")
    return base64.b64decode(plaintext_b64)


class Void(Exception):
    """The input cannot be measured (bad signature, key, decryption or fingerprint): nothing is tested."""


# ---------- the tests ----------
def parse_jsonl(name: str, data: bytes) -> list:
    rows = []
    for n, line in enumerate(data.decode("utf-8").split("\n"), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise Void(f"table {name}: line {n} is not JSON")
        if not isinstance(row, dict):
            raise Void(f"table {name}: line {n} is not an object")
        rows.append(row)
    return rows


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def t1_schema(manifest: dict, rows: dict) -> tuple:
    for name, info in manifest["tables"].items():
        cols = info.get("columns")
        if not (isinstance(cols, list) and all(isinstance(c, str) for c in cols) and len(set(cols)) == len(cols)):
            return False, f"{name}: manifest columns missing or invalid"
        for i, row in enumerate(rows[name]):
            if set(row) != set(cols):
                return False, f"{name}: row {i} columns differ from the manifest"
    got = manifest["tables"]["frames"]["columns"]
    # format 1 lists the columns in table order; canon-2 lists them sorted (its column order is not significant)
    if (got != FRAMES_COLUMNS) if manifest.get("columns_ordered", True) else (sorted(got) != sorted(FRAMES_COLUMNS)):
        return False, "frames: manifest columns are not the expected ones"
    return True, f"columns match the manifest in {len(rows)} tables"


def t2_frame_count(manifest: dict, rows: dict) -> tuple:
    lengths = [e.get("length") for e in rows["episodes"]]
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in lengths):
        return False, "episodes.length is not a non-negative integer in every row"
    total, frames = sum(lengths), len(rows["frames"])
    return total == frames, f"frames={frames} sum(episodes.length)={total}"


def _canon_number(v, logical):
    """canon-2 writes f32/f64 as JSON strings (e.g. "1.28e+02"); format 1 rows hold plain numbers. T3 only needs the VALUE, so any string
    float() parses is read as a number here (nan/inf then fail the bounds). That the string is in canonical form (CANON.md s2) is NOT
    decided here: canon2_rows checks it for every f32/f64 cell and answers VOID, before any test runs."""
    if logical in ("f32", "f64") and isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return v
    return v


def t3_action_bounds(manifest: dict, rows: dict) -> tuple:
    bad, first = 0, None
    types = manifest["tables"]["frames"].get("types", {})
    for i, r in enumerate(rows["frames"]):
        for c in ("action_x", "action_y"):
            v = _canon_number(r.get(c), types.get(c))
            if not (_num(v) and ACTION_MIN <= v <= ACTION_MAX):
                bad += 1
                first = i if first is None else first
    if bad:
        return False, f"{bad} action values outside [{ACTION_MIN}, {ACTION_MAX}], first in row {first}"
    return True, f"all action_x/action_y in [{ACTION_MIN}, {ACTION_MAX}]"


def t4_success_rate(manifest: dict, rows: dict) -> tuple:
    episodes = {e.get("episode_index") for e in rows["episodes"]}
    if not episodes:
        return False, "no episodes"
    won = {r.get("episode_index") for r in rows["frames"]
           if isinstance(r.get("success"), (bool, int)) and r["success"]} & episodes
    rate = len(won) / len(episodes)
    return rate >= MIN_SUCCESS_RATE, f"rate={rate:.4f} ({len(won)}/{len(episodes)}), required >= {MIN_SUCCESS_RATE}"


TESTS = [
    ("T1", "schema columns match manifest", t1_schema),
    ("T2", "frames row count equals sum of episode lengths", t2_frame_count),
    ("T3", "action_x/action_y within [0, 512]", t3_action_bounds),
    ("T4", "success rate of episodes >= 0.5", t4_success_rate),
]


def run_tests(manifest: dict, rows: dict) -> list:
    out = []
    for tid, name, fn in TESTS:
        try:
            ok, detail = fn(manifest, rows)
        except Exception as e:
            ok, detail = False, f"test error: {type(e).__name__}"
        out.append({"id": tid, "name": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    return out


# ---------- the request ----------
def check_buyer(req: dict) -> str:
    """Returns the buyer's key fingerprint once the key is the expected one and the manifest signature verifies."""
    try:
        pub = bytes.fromhex(req["buyer_pubkey"])
        sig = bytes.fromhex(req["buyer_sig"])
        expected = req["expected_buyer_fp"]
        manifest = req["manifest"]
        if len(pub) != 32 or not isinstance(manifest, str) or not isinstance(expected, str):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise Void("buyer: pubkey, signature, expected fingerprint or manifest missing or malformed")
    fp = sha256_hex(pub)
    if not hmac.compare_digest(fp, expected.lower()):
        raise Void("buyer: public key fingerprint is not the expected one")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, manifest.encode())
    except Exception:
        raise Void("buyer: signature over the manifest does not verify")
    return fp


def request_kms_key(req: dict) -> str:
    """The request's kms_key if it is a well-formed key ARN, else ''. Not part of the image, so not part of PCR0."""
    key = req.get("kms_key")
    return key if isinstance(key, str) and KMS_KEY_RE.fullmatch(key) else ""


def open_tables(req: dict, manifest: dict, info: dict, kms_key: str) -> dict:
    """Unwraps, decrypts and checks every table against the manifest. Returns {name: parsed rows}."""
    if not kms_key:
        raise Void("kms_key: a key ARN arn:aws:kms:eu-north-1:<12 digits>:key/<uuid> expected")
    creds = req.get("creds")
    sent = req.get("tables")
    mtables = manifest.get("tables")
    if not (isinstance(creds, dict) and all(isinstance(creds.get(k), str) for k in ("AccessKeyId", "SecretAccessKey", "Token"))):
        raise Void("creds: AccessKeyId, SecretAccessKey and Token expected")
    if not (isinstance(mtables, dict) and isinstance(sent, dict)) or set(mtables) != set(sent) or not {"frames", "episodes"} <= set(mtables):
        raise Void("tables: the request and the manifest must name the same tables, including frames and episodes")
    rows = {}
    for name in sorted(mtables):
        m, t = mtables[name], sent[name]
        if not (isinstance(m, dict) and SHA256_RE.fullmatch(str(m.get("sha256", ""))) and isinstance(m.get("rows"), int) and isinstance(t, dict)):
            raise Void(f"table {name}: manifest entry or request entry malformed")
        try:
            key = kms_decrypt_room_key(creds, t["wrapped_key_b64"], kms_key, "RSAES_OAEP_SHA_256")
        except KeyError:
            raise Void(f"table {name}: wrapped_key_b64 missing")
        except Exception as e:
            raise Void(f"table {name}: {e}"[:500])
        if len(key) != 32:
            raise Void(f"table {name}: unwrapped key is {len(key)} bytes, expected 32")
        try:
            plain = AESGCM(key).decrypt(base64.b64decode(t["iv_b64"], validate=True),
                                        base64.b64decode(t["ciphertext_b64"], validate=True), name.encode())
        except Exception as e:
            raise Void(f"table {name}: does not decrypt ({type(e).__name__})")
        info[name] = {"rows": None, "sha256": sha256_hex(plain)}
        parsed = parse_jsonl(name, plain)
        info[name]["rows"] = len(parsed)
        if info[name]["sha256"] != m["sha256"]:
            raise Void(f"table {name}: SHA-256 differs from the manifest")
        if len(parsed) != m["rows"]:
            raise Void(f"table {name}: {len(parsed)} rows, manifest says {m['rows']}")
        rows[name] = parsed
    return rows


def _code_sha256() -> str:
    with open(__file__, "rb") as f:
        return sha256_hex(f.read())


def _void(why: str) -> dict:
    return {"id": "V0", "name": "input can be measured", "result": "VOID", "detail": why[:500]}


def finish(manifest_str, fp: str, info: dict, tests: list, verdict: str, nonce: str, kms_key: str = "") -> dict:
    receipt = {
        "format": RECEIPT_FORMAT,
        "mode": "test",
        "manifest_sha256": sha256_hex(manifest_str.encode()) if isinstance(manifest_str, str) else "",
        "buyer_pubkey_fp": fp,
        "tables": info,
        "tests": tests,
        "verdict": verdict,
        "kms_key": kms_key,
        "nonce": nonce,
        "code_sha256": _code_sha256(),
        "measured_by": "enclave",
    }
    return _sign_and_attest(receipt, nonce)


def _sign_and_attest(receipt: dict, nonce: str) -> dict:
    raw = canon(receipt).encode()
    out = {"receipt": receipt, "sig": _SIGNER.sign(raw).hex()}
    try:
        out["attestation_b64"] = base64.b64encode(nsm_attest(hashlib.sha256(raw).digest(), bytes.fromhex(nonce), SIGNING_PUB)).decode()
    except Exception as e:
        # the verdict still stands, but it is not attested
        out["attest_error"] = f"{type(e).__name__}:{e}"[:200]
    return out


# ---------- canon-2 (fourdb-canon-2): a self-contained port of what the room needs from the connector ----------
NEUTRAL_KEYS = {"canon", "source_tz", "tables", "legacy_policy", "opt_in"}
TABLE_KEYS = {"pk", "rows", "sha256", "columns", "timestamp_columns", "ordering", "declared_labels", "omitted_columns", "zero_dates"}
OPT_IN_KEYS = {"timestamp_tz", "enum_set_as", "binary_as", "omit_unsupported", "year_as", "geometry"}  # CANON.md s10, as written to the neutral manifest
HEX_MAX_BYTES = 4096  # connector HEX_MAX_BYTES: --binary-as hex refuses a longer value
YEAR_MIN, YEAR_MAX = 1901, 2155
SHA256_OF_EMPTY = hashlib.sha256(b"").hexdigest()
POLICY_NOTE = ("opt_in, omitted_columns and legacy_policy are copied from the buyer-signed manifest. The room checks that every value is well-formed "
               "for its declared type and that the fingerprint covers these policies; it cannot check what the seller declared "
               "(e.g. opt_in.timestamp_tz.declared_zone is the seller's statement) and it says nothing about the omitted columns' content.")
FIXED_LOGICAL = {"int", "bool", "f32", "f64", "text", "date", "year", "enum:text", "set:text", "binary:sha256", "binary:hex", "geometry:wkb-sha256"}
DEC_RE, CHAR_RE, TS_TYPE_RE = re.compile(r"dec:([0-9]+),([0-9]+)"), re.compile(r"char:([0-9]+)"), re.compile(r"timestamp:([0-9])")
DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
VERBATIM_ZERO_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}([ T][0-9:.]+)?")  # --zero-date string keeps the source text of an invalid date
HEX_RE = re.compile(r"([0-9a-f]{2})*")


def canon2_line(row: dict) -> str:
    """connector.canon_line: one canonical row, keys sorted, no spaces, ASCII only."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canon2_dataset_fingerprint(neutral: dict) -> str:
    """connector.dataset_fingerprint: SHA-256 of the neutral manifest (sorted keys, (',', ':') separators)."""
    return hashlib.sha256(json.dumps(neutral, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def canon2_aad(canon_id: str, fingerprint: str, table: str) -> bytes:
    """fourdb seal.aad: binds the canon id, the dataset fingerprint and the table name to the ciphertext."""
    return f"{SEAL_AAD}|{canon_id}|{fingerprint}|{table}".encode()


def canon2_float(v: float, bits: int) -> str:
    """connector.canon_float / _shortest: the shortest decimal that round-trips float32/float64, as d[.ddd]e+XX ('0', 'nan', 'inf', '-inf')."""
    if math.isnan(v):
        return "nan"
    if math.isinf(v):
        return "inf" if v > 0 else "-inf"
    if bits == 32:
        v = struct.unpack("f", struct.pack("f", v))[0]  # OverflowError when out of float32 range
    if v == 0:
        return "0"
    for n in range(1, 18):
        s = "%.*e" % (n - 1, v)
        x = float(s)
        if (bits == 64 and x == v) or (bits == 32 and struct.unpack("f", struct.pack("f", x))[0] == v):
            break
    m, e = s.split("e")
    if "." in m:
        m = m.rstrip("0").rstrip(".")
    return f"{m}e{int(e):+03d}"


def _logical_checker(lt: str, labels, zero_string: bool):
    """Returns f(value) -> None if the (non-null) value is well-formed for logical type `lt`, else a short reason. Raises Void on an unknown type."""
    def is_int(v):
        return type(v) is int

    def is_sha(v):
        return isinstance(v, str) and SHA256_RE.fullmatch(v) is not None

    def raw_text(v):  # CANON.md s7: undecodable/ambiguous text is kept as its stored bytes
        return isinstance(v, dict) and set(v) == {"declared_charset", "raw_hex"} and isinstance(v["declared_charset"], str) \
            and isinstance(v["raw_hex"], str) and HEX_RE.fullmatch(v["raw_hex"]) is not None

    if lt == "int":
        return lambda v: None if is_int(v) else "not an integer"
    if lt == "bool":
        return lambda v: None if isinstance(v, bool) else "not true/false"
    if lt in ("f32", "f64"):
        bits = 32 if lt == "f32" else 64

        def f(v):
            if not isinstance(v, str):
                return "float is not a JSON string"
            try:
                x = float(v)
                ok = canon2_float(x, bits) == v
            except (ValueError, OverflowError, struct.error):
                return "not a float string (or out of range for %s)" % lt
            return None if ok else "float string is not in canonical form (shortest round-trip d[.ddd]e+XX)"
        return f
    if lt == "text":
        return lambda v: None if (isinstance(v, str) and unicodedata.normalize("NFC", v) == v) or raw_text(v) else "text is not an NFC string"
    m = CHAR_RE.fullmatch(lt)
    if m and int(m.group(1)) >= 1:
        n = int(m.group(1))
        return lambda v: None if (isinstance(v, str) and len(v) == n and unicodedata.normalize("NFC", v) == v) or raw_text(v) else "char:%d value is not an NFC string of exactly %d characters" % (n, n)
    m = DEC_RE.fullmatch(lt)
    if m and 1 <= int(m.group(1)) and int(m.group(2)) <= int(m.group(1)):
        p, s = int(m.group(1)), int(m.group(2))
        ctx = decimal.Context(prec=p + 10)

        def f(v):
            if not isinstance(v, str):
                return "decimal is not a JSON string"
            try:
                d = decimal.Decimal(v)
                q = d.quantize(decimal.Decimal(1).scaleb(-s), context=ctx)
            except (decimal.InvalidOperation, ValueError):
                return "not a decimal string with %d fractional digits" % s
            if not d.is_finite() or format(q, "f") != v or abs(q) >= decimal.Decimal(10) ** (p - s) or (q == 0 and v.startswith("-")):
                return "decimal is not canonical for dec:%d,%d" % (p, s)
            return None
        return f
    m = TS_TYPE_RE.fullmatch(lt)
    if m:
        p = int(m.group(1))
        if p > 6:
            raise Void("unknown logical type %r" % lt)
        rx = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})" + (r"\.[0-9]{%d}" % p if p else "") + "Z")

        def f(v):
            mm = rx.fullmatch(v) if isinstance(v, str) else None
            if mm is None:
                if zero_string and isinstance(v, str) and VERBATIM_ZERO_DATE_RE.fullmatch(v):
                    return None  # legacy_policy.zero_date = string: the source text of an invalid datetime
                return "timestamp is not canonical UTC YYYY-MM-DDTHH:MM:SS%sZ with exactly %d fractional digits" % (".f" if p else "", p)
            try:
                datetime.datetime(*(int(x) for x in mm.groups()))
            except ValueError:
                return "timestamp is not a valid date and time"
            return None
        return f
    if lt == "date":
        def f(v):
            mm = DATE_RE.fullmatch(v) if isinstance(v, str) else None
            try:
                if mm:
                    datetime.date(*(int(x) for x in mm.groups()))
                    return None
            except ValueError:
                pass
            return None if zero_string and isinstance(v, str) and VERBATIM_ZERO_DATE_RE.fullmatch(v) else "date is not a valid YYYY-MM-DD"
        return f
    if lt == "year":
        return lambda v: None if is_int(v) and YEAR_MIN <= v <= YEAR_MAX else "year is not an integer in %d..%d" % (YEAR_MIN, YEAR_MAX)
    if lt == "binary:sha256":
        return lambda v: None if (isinstance(v, dict) and set(v) == {"len", "sha256"} and is_int(v["len"]) and v["len"] >= 0 and is_sha(v["sha256"])
                                  and (v["len"] > 0 or v["sha256"] == SHA256_OF_EMPTY)) else "binary:sha256 value is not {len, sha256}"
    if lt == "binary:hex":
        return lambda v: None if isinstance(v, str) and len(v) <= 2 * HEX_MAX_BYTES and HEX_RE.fullmatch(v) else "binary:hex value is not lowercase hex of at most %d bytes" % HEX_MAX_BYTES
    if lt == "geometry:wkb-sha256":
        return lambda v: None if (isinstance(v, dict) and set(v) == {"srid", "len", "sha256"} and is_int(v["srid"]) and 0 <= v["srid"] < 2 ** 32
                                  and is_int(v["len"]) and v["len"] >= 9 and is_sha(v["sha256"])) else "geometry value is not {srid (uint32), len (>= 9), sha256}"
    if lt == "enum:text":
        return lambda v: None if isinstance(v, str) and v in labels else "enum value is not one of the declared labels"
    if lt == "set:text":
        def f(v):
            if not isinstance(v, str):
                return "set value is not a string"
            parts = v.split(",") if v else []
            if any(x not in labels for x in parts):
                return "set member is not one of the declared labels"
            if parts != sorted(set(parts)):
                return "set members are not unique and sorted by code point"
            return None
        return f
    raise Void("unknown logical type %r" % (lt,))


def _expect(cond, why):
    if not cond:
        raise Void("manifest: " + why)


def _str_list(x):
    return isinstance(x, list) and all(isinstance(i, str) for i in x)


def canon2_policies(neutral: dict) -> dict:
    """Checks everything in the neutral manifest beyond tables/digests: legacy_policy, opt_in (CANON.md s10), per-table timestamp_columns,
    declared_labels, omitted_columns, zero_dates, and that every logical type is known and backed by the opt_in policy that allows it.
    Anything unknown or inconsistent is VOID. Returns {table: {column: checker}} for the per-value check."""
    unknown = sorted(set(neutral) - NEUTRAL_KEYS)
    _expect(not unknown, "unknown neutral_manifest key(s) %s" % unknown)
    _expect(isinstance(neutral.get("source_tz"), str), "neutral_manifest.source_tz missing")
    lp = neutral.get("legacy_policy", {})
    _expect(isinstance(lp, dict) and set(lp) <= {"zero_date", "ambiguous_encoding"} and lp.get("zero_date", "null") in ("null", "string")
            and lp.get("ambiguous_encoding", "refuse") == "refuse", "legacy_policy malformed (only non-default zero_date null|string, ambiguous_encoding refuse)")
    zero_string = lp.get("zero_date") == "string"
    oi = neutral.get("opt_in", {})
    _expect(isinstance(oi, dict) and (oi or "opt_in" not in neutral), "opt_in present but not a non-empty object")
    bad = sorted(set(oi) - OPT_IN_KEYS)
    _expect(not bad, "unknown opt_in key(s) %s" % bad)
    _expect(oi.get("enum_set_as", "text") == "text" and oi.get("binary_as", "sha256") in ("sha256", "hex") and oi.get("year_as", "int") == "int"
            and oi.get("omit_unsupported", True) is True, "opt_in has an unknown value")
    tz, geo = oi.get("timestamp_tz"), oi.get("geometry")
    if "timestamp_tz" in oi:
        _expect(isinstance(tz, dict) and set(tz) == {"declared_zone", "read_session_zone", "columns"} and isinstance(tz["declared_zone"], str) and tz["declared_zone"]
                and tz["read_session_zone"] == "+00:00" and isinstance(tz["columns"], dict) and tz["columns"]
                and all(_str_list(c) and c for c in tz["columns"].values()), "opt_in.timestamp_tz malformed")
    if "geometry" in oi:
        _expect(isinstance(geo, dict) and set(geo) == {"as", "storage", "columns"} and geo["as"] == "wkb-sha256" and geo["storage"] == "mysql-srid-wkb"
                and isinstance(geo["columns"], dict) and geo["columns"] and all(_str_list(c) and c for c in geo["columns"].values()), "opt_in.geometry malformed")
    checkers, geo_seen, tz_listed = {}, {}, {t: set(c) for t, c in (tz or {}).get("columns", {}).items()}
    for t, m in neutral["tables"].items():
        extra = sorted(set(m) - TABLE_KEYS)
        _expect(not extra, "table %s: unknown key(s) %s" % (t, extra))
        cols, ck = m["columns"], {}
        _expect(m.get("ordering", "multiset") == "multiset" and ("ordering" in m) == (m.get("pk") is None), "table %s: ordering/pk inconsistent" % t)
        lab = m.get("declared_labels", {})
        _expect(isinstance(lab, dict), "table %s: declared_labels malformed" % t)
        want_labels = {c for c, lt in cols.items() if lt in ("enum:text", "set:text")}
        _expect(set(lab) == want_labels, "table %s: declared_labels must be given for exactly the enum:text/set:text columns" % t)
        for c, d in lab.items():
            kind = cols[c].split(":")[0]
            _expect(isinstance(d, dict) and set(d) == {"kind", "labels"} and d["kind"] == kind and _str_list(d["labels"]) and d["labels"] and len(set(d["labels"])) == len(d["labels"])
                    and not (kind == "set" and any(x == "" or "," in x for x in d["labels"])), "table %s column %s: declared_labels malformed" % (t, c))
        for c, lt in cols.items():
            if lt.startswith("binary:"):
                _expect(oi.get("binary_as") == lt[7:], "table %s column %s is %s but opt_in.binary_as is %r" % (t, c, lt, oi.get("binary_as")))
            if lt in ("enum:text", "set:text"):
                _expect(oi.get("enum_set_as") == "text", "table %s column %s is %s but opt_in.enum_set_as is not text" % (t, c, lt))
            if lt == "year":
                _expect(oi.get("year_as") == "int", "table %s column %s is year but opt_in.year_as is not int" % (t, c))
            if lt == "geometry:wkb-sha256":
                geo_seen.setdefault(t, set()).add(c)
            ck[c] = _logical_checker(lt, lab[c]["labels"] if c in lab else None, zero_string)
        tsc = m.get("timestamp_columns")
        _expect(isinstance(tsc, dict) and set(tsc) == {c for c, lt in cols.items() if lt.startswith("timestamp:")}, "table %s: timestamp_columns must name exactly the timestamp columns" % t)
        for c, d in tsc.items():
            _expect(isinstance(d, dict) and set(d) == {"source_tz", "ambiguous", "nonexistent"} and (d["source_tz"] is None or isinstance(d["source_tz"], str))
                    and all(type(d[k]) is int and d[k] >= 0 for k in ("ambiguous", "nonexistent")), "table %s column %s: timestamp_columns entry malformed" % (t, c))
        for c in tz_listed.pop(t, set()):
            _expect(c in tsc and tsc[c]["source_tz"] == "UTC", "opt_in.timestamp_tz lists %s.%s, which is not a timestamp column read as UTC" % (t, c))
        zd = m.get("zero_dates", {})
        _expect(isinstance(zd, dict) and set(zd) <= set(cols) and all(type(v) is int and v > 0 for v in zd.values()), "table %s: zero_dates malformed" % t)
        om = m.get("omitted_columns")
        if "omitted_columns" in m:
            _expect(oi.get("omit_unsupported") is True, "table %s has omitted_columns but opt_in.omit_unsupported is not set" % t)
            _expect(isinstance(om, list) and om and all(isinstance(o, dict) and set(o) == {"name", "type", "reason"} and all(isinstance(o[k], str) for k in o) for o in om)
                    and [o["name"] for o in om] == sorted({o["name"] for o in om}) and not ({o["name"] for o in om} & set(cols)),
                    "table %s: omitted_columns malformed (sorted unique names, not among the columns)" % t)
        checkers[t] = ck
    _expect(not tz_listed, "opt_in.timestamp_tz lists table(s) %s that are not in the manifest" % sorted(tz_listed))
    _expect((geo["columns"] if geo else {}) == {t: sorted(c) for t, c in geo_seen.items()}, "opt_in.geometry.columns must list exactly the geometry:wkb-sha256 columns")
    return checkers


def canon2_manifest(mf) -> tuple:
    """Checks the shape of the signed canon-2 manifest.json. Returns (neutral manifest, claimed fingerprint)."""
    if not isinstance(mf, dict):
        raise Void("manifest: not an object")
    if mf.get("mode") != "sealed":
        raise Void("manifest: not a sealed intake (mode=%r); a hash-only intake gets no tests" % (mf.get("mode"),))
    neutral, claimed, sealed = mf.get("neutral_manifest"), mf.get("dataset_fingerprint"), mf.get("sealed")
    if not isinstance(neutral, dict) or neutral.get("canon") != CANON2_ID:
        raise Void("manifest: neutral_manifest.canon is not %s" % CANON2_ID)
    if not (isinstance(claimed, str) and SHA256_RE.fullmatch(claimed)):
        raise Void("manifest: dataset_fingerprint missing or malformed")
    if canon2_dataset_fingerprint(neutral) != claimed:
        raise Void("manifest: dataset_fingerprint is not the SHA-256 of its neutral manifest")
    tables = neutral.get("tables")
    if not (isinstance(tables, dict) and tables):
        raise Void("manifest: neutral_manifest.tables missing or empty")
    for name, m in tables.items():
        cols = m.get("columns") if isinstance(m, dict) else None
        if not (isinstance(m, dict) and IDENT_RE.fullmatch(name) and isinstance(m.get("sha256"), str) and SHA256_RE.fullmatch(m["sha256"])
                and isinstance(m.get("rows"), int) and not isinstance(m["rows"], bool) and m["rows"] >= 0
                and isinstance(cols, dict) and cols and all(isinstance(k, str) and isinstance(v, str) for k, v in cols.items())
                and (m.get("pk") is None or m["pk"] in cols)):
            raise Void(f"manifest: table {name} entry malformed")
    stables = sealed.get("tables") if isinstance(sealed, dict) else None
    if not (isinstance(stables, dict) and set(stables) == set(tables)
            and all(isinstance(v, dict) and isinstance(v.get("sealed_sha256"), str) and SHA256_RE.fullmatch(v["sealed_sha256"]) for v in stables.values())):
        raise Void("manifest: sealed block missing or does not match the neutral manifest tables")
    return neutral, claimed


def canon2_rows(name: str, plain: bytes, pk, checkers: dict) -> tuple:
    """Parses one table's decrypted canonical JSONL, re-derives its digest as connector.table_digest does and checks every cell against its
    declared logical type. Returns (rows, sha256, row count). Every line must already be in canonical form, and in the canonical order.
    Every line, the last one too, ends with "\\n": CANON.md s3 defines table.sha256 over `line + "\\n"` for each row, so a final line without
    it is not the bytes the connector hashed (kept strict; the connector's own sealer always writes it)."""
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        raise Void(f"table {name}: not UTF-8")
    if text and not text.endswith("\n"):
        raise Void(f"table {name}: last line is not newline-terminated")
    lines = text.split("\n")[:-1] if text else []
    h, rows, prev, cols = hashlib.sha256(), [], None, set(checkers)
    for n, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except ValueError:
            raise Void(f"table {name}: line {n} is not JSON")
        if not isinstance(row, dict) or canon2_line(row) != line:
            raise Void(f"table {name}: line {n} is not a canon-2 canonical row")
        if set(row) != cols:
            extra, missing = sorted(set(row) - cols), sorted(cols - set(row))
            raise Void(f"table {name}: line {n} has column(s) {extra} not in the manifest" if extra else f"table {name}: line {n} lacks column(s) {missing} the manifest declares")
        for c, v in row.items():
            if v is not None:
                why = checkers[c](v)
                if why:
                    raise Void(f"table {name}: line {n} column {c}: malformed value ({why})")
        if pk is not None:
            v = row.get(pk)
            if type(v) is not int or (prev is not None and v <= prev):
                raise Void(f"table {name}: rows are not strictly ascending by integer primary key {pk}")
            prev = v
        h.update(line.encode() + b"\n")
        rows.append(row)
    if pk is None and lines != sorted(lines):
        raise Void(f"table {name}: rows without a primary key must be sorted as lines (multiset order)")
    return rows, h.hexdigest(), len(rows)


def open_tables_canon2(req: dict, neutral: dict, claimed_fp: str, mf: dict, info: dict, kms_key: str, checkers: dict, reached: dict) -> tuple:
    """Unwraps the data key, decrypts every table and re-derives digests and the dataset fingerprint.
    Returns ({name: rows}, fingerprint re-derived from the rows). Any mismatch with the signed manifest raises Void.
    `reached["kms"]` is set just before the KMS call: a VOID before that point does not echo the request's kms_key."""
    if not kms_key:
        raise Void("kms_key: a key ARN arn:aws:kms:eu-north-1:<12 digits>:key/<uuid> expected")
    creds, sent, wrapped = req.get("creds"), req.get("tables"), req.get("wrapped_dek_b64")
    if not (isinstance(creds, dict) and all(isinstance(creds.get(k), str) for k in ("AccessKeyId", "SecretAccessKey", "Token"))):
        raise Void("creds: AccessKeyId, SecretAccessKey and Token expected")
    mtables, stables = neutral["tables"], mf["sealed"]["tables"]
    if not (isinstance(sent, dict) and set(sent) == set(mtables) and isinstance(wrapped, str)):
        raise Void("tables: the request must carry wrapped_dek_b64 and the same tables as the manifest")
    reached["kms"] = True
    try:
        dek = kms_decrypt_room_key(creds, wrapped, kms_key, "RSAES_OAEP_SHA_256")
    except Exception as e:
        raise Void(f"wrapped_dek: {e}"[:500])
    if len(dek) != 32:
        raise Void(f"wrapped_dek: unwrapped key is {len(dek)} bytes, expected 32")
    derived, rows = copy.deepcopy(neutral), {}
    for name in sorted(mtables):
        try:
            blob = base64.b64decode(sent[name]["sealed_b64"], validate=True)
        except Exception:
            raise Void(f"table {name}: sealed_b64 missing or not base64")
        if sha256_hex(blob) != stables[name]["sealed_sha256"]:
            raise Void(f"table {name}: sealed SHA-256 differs from the manifest (ciphertext changed or swapped)")
        try:
            plain = AESGCM(dek).decrypt(blob[:12], blob[12:], canon2_aad(neutral["canon"], claimed_fp, name))
        except Exception as e:
            raise Void(f"table {name}: does not decrypt ({type(e).__name__}); changed ciphertext or a different table, fingerprint or canon id in the AAD")
        rows[name], digest, count = canon2_rows(name, plain, mtables[name].get("pk"), checkers[name])
        info[name] = {"rows": count, "sha256": digest}
        if digest != mtables[name]["sha256"]:
            raise Void(f"table {name}: canon-2 digest differs from the manifest")
        if count != mtables[name]["rows"]:
            raise Void(f"table {name}: {count} rows, manifest says {mtables[name]['rows']}")
        derived["tables"][name]["sha256"], derived["tables"][name]["rows"] = digest, count
    # everything else (columns, logical types, pk, opt_in, declared_labels, omitted_columns, legacy_policy...) comes from the buyer-signed manifest and is
    # hashed as it stands, exactly as the connector does; digests and counts come from the decrypted rows
    fingerprint = canon2_dataset_fingerprint(derived)
    if fingerprint != claimed_fp:
        raise Void("dataset fingerprint re-derived from the rows differs from the manifest")
    return rows, fingerprint


def finish_v2(manifest_str, buyer_fp: str, fingerprint: str, info: dict, tests: list, verdict: str, nonce: str, kms_key: str = "", neutral: dict = None) -> dict:
    measured = verdict != "VOID" and neutral is not None  # policies are surfaced only for a manifest the room has fully validated
    receipt = {
        "format": RECEIPT_FORMAT_V2,
        "mode": "test",
        "canon": CANON2_ID,
        "dataset_fingerprint": fingerprint,  # re-derived from the decrypted rows; "" when the input was VOID before that
        "manifest_sha256": sha256_hex(manifest_str.encode()) if isinstance(manifest_str, str) else "",
        "buyer_pubkey_fp": buyer_fp,
        "tables": info if verdict != "VOID" else {},  # no per-table digests on a VOID intake (gpt-5 review, round 5)
        # the policies the fingerprint was made under, copied from the signed manifest ({} = none / not measured)
        "opt_in": copy.deepcopy(neutral.get("opt_in", {})) if measured else {},
        "legacy_policy": copy.deepcopy(neutral.get("legacy_policy", {})) if measured else {},
        "omitted_columns": {t: copy.deepcopy(m["omitted_columns"]) for t, m in sorted(neutral["tables"].items()) if "omitted_columns" in m} if measured else {},
        "policy_note": POLICY_NOTE if measured else "",
        # `verdict` is the v2 name; `result` is kept with the same value so v1 readers still work
        "tests": [dict(t, verdict=t["result"]) for t in tests],
        "verdict": verdict,
        "kms_key": kms_key,
        "nonce": nonce,
        "code_sha256": _code_sha256(),
        "measured_by": "enclave",
    }
    return _sign_and_attest(receipt, nonce)


def not_applicable(neutral: dict) -> list:
    """T1-T4 are defined for the pusht schema only (tables frames AND episodes). For any other dataset the receipt says so instead of passing."""
    return [{"id": "TX", "name": "tests applicable to this dataset", "result": "N/A",
             "detail": ("T1-T4 are defined for the pusht schema (tables frames and episodes); this dataset has %s. No test was run: the receipt "
                        "proves the fingerprint re-derived from the decrypted rows, nothing about the data's content." % sorted(neutral["tables"]))[:500]}]


def process_request_canon2(req: dict) -> dict:
    nonce, manifest_str = req.get("nonce"), req.get("manifest")
    buyer_fp, fingerprint, info, kms_key, reached = "", "", {}, request_kms_key(req), {"kms": False}
    if not (isinstance(nonce, str) and NONCE_RE.fullmatch(nonce)):
        return finish_v2(manifest_str, buyer_fp, fingerprint, info, [_void("nonce: 32 to 128 lowercase hex characters expected")], "VOID", "", "")
    try:
        buyer_fp = check_buyer(req)
        try:
            mf = json.loads(manifest_str)
        except ValueError:
            raise Void("manifest: not JSON")
        neutral, claimed = canon2_manifest(mf)
        checkers = canon2_policies(neutral)
        rows, fingerprint = open_tables_canon2(req, neutral, claimed, mf, info, kms_key, checkers, reached)
        if {"frames", "episodes"} <= set(neutral["tables"]):
            view = {"columns_ordered": False,
                    "tables": {n: {"columns": sorted(m["columns"]), "types": m["columns"]} for n, m in neutral["tables"].items()}}
            tests = run_tests(view, rows)
        else:
            tests = not_applicable(neutral)
    except Void as v:
        # the request's kms_key is echoed only once the KMS step was reached (it is not part of the signed input; a VOID before that has no use for it)
        return finish_v2(manifest_str, buyer_fp, "", info, [_void(str(v))], "VOID", nonce, kms_key if reached["kms"] else "")
    if tests[0]["result"] == "N/A":
        verdict = "N/A"
    else:
        verdict = "PASS" if all(t["result"] == "PASS" for t in tests) else "FAIL"
    return finish_v2(manifest_str, buyer_fp, fingerprint, info, tests, verdict, nonce, kms_key, neutral)


def process_request(req: dict) -> dict:
    if not isinstance(req, dict):
        req = {}
    if req.get("format") == REQUEST_FORMAT_CANON2:
        return process_request_canon2(req)
    nonce, manifest_str = req.get("nonce"), req.get("manifest")
    fp, info, kms_key = "", {}, request_kms_key(req)
    if not (isinstance(nonce, str) and NONCE_RE.fullmatch(nonce)):
        return finish(manifest_str, fp, info, [_void("nonce: 32 to 128 lowercase hex characters expected")], "VOID", "", kms_key)
    try:
        fp = check_buyer(req)
        try:
            manifest = json.loads(manifest_str)
        except ValueError:
            raise Void("manifest: not JSON")
        if not isinstance(manifest, dict):
            raise Void("manifest: not an object")
        rows = open_tables(req, manifest, info, kms_key)
        tests = run_tests(manifest, rows)
    except Void as v:
        return finish(manifest_str, fp, info, [_void(str(v))], "VOID", nonce, kms_key)
    verdict = "PASS" if all(t["result"] == "PASS" for t in tests) else "FAIL"
    return finish(manifest_str, fp, info, tests, verdict, nonce, kms_key)


def handle_conn(conn: socket.socket) -> None:
    buf = b""
    while True:
        chunk = conn.recv(1 << 20)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf or b"\0" in buf:
            break
        if len(buf) > MAX_REQUEST:
            conn.sendall(json.dumps({"error": "request_too_large"}).encode() + b"\n")
            return
    raw = buf.split(b"\0", 1)[0].split(b"\n", 1)[0]
    try:
        resp = process_request(json.loads(raw.decode()))
    except Exception as e:
        resp = {"error": f"handler:{type(e).__name__}", "trace": traceback.format_exc()[-500:]}
    conn.sendall(json.dumps(resp, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")


def main() -> int:
    print(f"[intake_loop] TEST room listening vsock:{LISTEN_PORT} region={REGION}", flush=True)
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((socket.VMADDR_CID_ANY, LISTEN_PORT))
    sock.listen(5)
    while True:
        conn, addr = sock.accept()
        try:
            handle_conn(conn)
        except Exception as e:
            print(f"[intake_loop] conn_error:{e}", flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main() or 0)
