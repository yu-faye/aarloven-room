#!/usr/bin/env python3
"""Aarloven sealed room, inside an AWS Nitro Enclave (Room v4: the room runs the agreed tests itself).

Receives over vsock: short-lived AWS credentials, the room key wrapped by KMS, and a sealed case (AES-256-GCM).
1. Gets the room key from KMS through kmstool_enclave_cli; KMS checks this enclave's measurement (PCR0) first.
2. Opens the case. If even one byte was changed it does not open: a signed VOID, and nothing is tested.
3. Runs each clause's test with Node: as an unprivileged user, in a folder in memory, with no network, a time
   limit and capped output. A clause is Yes when its test exits 0 with every check passed, No when it exits 10,
   and "not finished" otherwise. The verdict is PASS only when every clause is Yes. No language model decides.
4. Signs a receipt with an Ed25519 key made in memory at start. The receipt names each check and its outcome,
   fingerprints the build, the data and the tests, and names the previous receipt. It asks the Nitro Security
   Module for a document over the receipt's SHA-256, the caller's nonce and the room's public key.
5. Reports each step as it happens, one JSON line each: key, opened, each clause, signed. The steps carry
   fingerprints, check names and outcomes, never the case's files.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LISTEN_PORT = int(os.environ.get("AARLOVEN_VSOCK_PORT", "5005"))
REGION = os.environ.get("REGION", "eu-north-1")
PROXY_PORT = os.environ.get("KMS_PROXY_PORT", "8000")
KMSTOOL = os.environ.get("KMSTOOL_CLI", "/app/kmstool_enclave_cli")
NODE = os.environ.get("NODE_BIN", "/usr/bin/node")
AAD_DEFAULT = b"aarloven.min_closed_loop.v1"

# What a case may hold, and how long and how much its tests may take
CASE_KIND = "aarloven.case.v1"
MAX_FILES, MAX_BYTES, MAX_CLAUSES = 64, 512 * 1024, 12
TEST_SECONDS, TEST_OUTPUT = 10, 64 * 1024
MAX_CHECKS, NAME_CHARS, REASON_CHARS = 40, 160, 240
TEST_UID = TEST_GID = 65534  # "nobody": cannot read the room's memory, its key or its signing key
PATH_RE = re.compile(r"(build|data|tests)(/[A-Za-z0-9][A-Za-z0-9._-]*)+")
EXT_RE = re.compile(r".*\.(mjs|js|json|txt|csv)")
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,16}")


def _runner_version() -> str:
    try:
        return "node " + subprocess.run([NODE, "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:
        return f"node unavailable:{type(e).__name__}"


RUNNER = _runner_version()


# ---------- Phase A: signed, attested receipts ----------
RECEIPT_VERSION = "aarloven.receipt.v3"
NSM_LIB = os.environ.get("NSM_LIB", "/usr/lib64/libnsm.so")
# made here at boot, never written anywhere, gone when the enclave stops
_SIGNER = Ed25519PrivateKey.generate()
SIGNING_PUB = _SIGNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_prev_receipt = ""  # SHA-256 of this enclave's previous receipt: a chain for as long as it runs
_nsm = None
NONCE_RE = re.compile(r"[0-9a-f]{32,128}")


def canon(obj) -> str:
    """Canonical JSON, byte for byte the browser's canon(): sorted keys, no spaces, UTF-8 as is."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


def ciphertext_hash(envelope: dict) -> str:
    try:
        return hashlib.sha256(base64.b64decode(envelope.get("ct_b64") or "", validate=True)).hexdigest()
    except Exception:
        return ""


def seal(out: dict, request_nonce: str, h_ciphertext: str, verdict: str, emit=None) -> dict:
    """Adds the receipt, its signature and the hardware's attestation to a reply."""
    global _prev_receipt
    receipt = {
        "v": RECEIPT_VERSION,
        "verdict": verdict,
        "clauses": out.get("clauses") or [],
        "clause_results": out.get("clause_results") or [],
        "H_ciphertext": h_ciphertext,
        "H_input": out.get("H_input") or "",
        "H_build": out.get("H_build") or "",
        "H_data": out.get("H_data") or "",
        "H_tests": out.get("H_tests") or "",
        "H_clauses": out.get("H_clauses") or "",
        "runner": RUNNER,
        "request_nonce": request_nonce,
        "prev": _prev_receipt,
        "signing_key": SIGNING_PUB.hex(),
        "time": int(time.time()),
    }
    raw = canon(receipt).encode()
    digest = hashlib.sha256(raw).digest()
    out["receipt"] = receipt
    out["receipt_sig_b64"] = base64.b64encode(_SIGNER.sign(raw)).decode()
    try:
        out["attestation_b64"] = base64.b64encode(nsm_attest(digest, bytes.fromhex(request_nonce), SIGNING_PUB)).decode()
    except Exception as e:
        # the verdict still stands; the browser then shows the hardware check as failed, not as passed
        out["attest_error"] = f"{type(e).__name__}:{e}"[:200]
    _prev_receipt = digest.hex()
    if emit:
        emit({"event": "signed", "attested": "attestation_b64" in out})
    return out


def _fail(msg: str, **extra) -> dict:
    out = {
        "verdict": "fail",
        "error": msg,
        "H_input": extra.get("H_input", hashlib.sha256(b"").hexdigest()),
        "tee": "AWS Nitro Enclaves",
        "region": REGION,
        "runner": RUNNER,
    }
    out.update({k: v for k, v in extra.items() if k not in out})
    return out


def kms_decrypt_room_key(creds: dict, wrapped_b64: str) -> bytes:
    """Decrypt KMS-wrapped room_key inside enclave. Plaintext stays local."""
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
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "kmstool_decrypt_failed").strip()[:400]
        raise RuntimeError(f"kmstool_decrypt_failed:{err}")
    plaintext_b64 = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("PLAINTEXT:"):
            plaintext_b64 = line.split(":", 1)[1].strip()
            break
    if not plaintext_b64:
        raise RuntimeError("kmstool_decrypt_no_plaintext_line")
    return base64.b64decode(plaintext_b64)


def aesgcm_decrypt(key: bytes, envelope: dict) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aad = (envelope.get("aad") or AAD_DEFAULT.decode()).encode()
    iv = base64.b64decode(envelope["iv_b64"])
    ct = base64.b64decode(envelope["ct_b64"])
    return AESGCM(key).decrypt(iv, ct, aad)


def group_hash(files: dict, group: str) -> str:
    """One fingerprint for a group of files: SHA-256 of the canonical list of [path, SHA-256 of its text]."""
    items = sorted([p, hashlib.sha256(c.encode()).hexdigest()] for p, c in files.items() if p.startswith(group + "/"))
    return hashlib.sha256(canon(items).encode()).hexdigest()


def read_case(opened: bytes) -> tuple[dict, list[str]]:
    """The case, and what is wrong with it (nothing, when it may run)."""
    try:
        case = json.loads(opened.decode())
    except Exception as e:
        return {}, [f"json:{type(e).__name__}"]
    if not isinstance(case, dict) or case.get("kind") != CASE_KIND:
        return {}, ["kind: expected " + CASE_KIND]
    files, clauses, wrong = case.get("files"), case.get("clauses"), []
    if not isinstance(files, dict) or not 0 < len(files) <= MAX_FILES:
        return {}, [f"files: 1 to {MAX_FILES}"]
    for path, text in files.items():
        if not (isinstance(path, str) and PATH_RE.fullmatch(path) and EXT_RE.fullmatch(path) and isinstance(text, str)):
            wrong.append("file:" + str(path)[:80])
    if sum(len(t.encode()) for t in files.values() if isinstance(t, str)) > MAX_BYTES:
        wrong.append(f"size: over {MAX_BYTES} bytes")
    if not isinstance(clauses, list) or not 0 < len(clauses) <= MAX_CLAUSES:
        return {}, wrong + [f"clauses: 1 to {MAX_CLAUSES}"]
    seen = set()
    for c in clauses:
        cid = c.get("id") if isinstance(c, dict) else None
        test = c.get("test") if isinstance(c, dict) else None
        if not (isinstance(cid, str) and ID_RE.fullmatch(cid)) or cid in seen:
            wrong.append("clause id:" + str(cid)[:20])
        elif not (isinstance(test, str) and test.startswith("tests/") and test in files):
            wrong.append(f"clause {cid}: test not in the case")
        seen.add(cid)
    return case, wrong


def _limits() -> None:
    # in the test's own process, before Node starts
    resource.setrlimit(resource.RLIMIT_CPU, (TEST_SECONDS + 5, TEST_SECONDS + 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _clip(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def run_test(workdir: str, test: str) -> tuple[str, list, str]:
    """Runs one clause's test. Returns its result (Yes, No, not finished), its checks, and its output's SHA-256."""
    out_path = os.path.join(workdir, ".out-" + hashlib.sha256(test.encode()).hexdigest()[:12])
    with open(out_path, "wb") as out:
        try:
            proc = subprocess.Popen(
                [NODE, "--max-old-space-size=256", "--no-warnings", test],
                cwd=workdir, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "HOME": workdir, "LANG": "C.UTF-8"},
                preexec_fn=_limits, start_new_session=True,
                # in the enclave the room runs as root, and each test as "nobody"; a room already running
                # unprivileged (a developer's machine) cannot switch users, and needs no switch
                **(dict(user=TEST_UID, group=TEST_GID, extra_groups=[]) if os.geteuid() == 0 else {}),
            )
        except Exception as e:
            return "not finished", [["the test could start", False, f"{type(e).__name__}"]], ""
        try:
            code = proc.wait(timeout=TEST_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            code = None
    with open(out_path, "rb") as f:
        raw = f.read(TEST_OUTPUT)
    checks = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("✓ "):
            checks.append([_clip(line[2:], NAME_CHARS), True, ""])
        elif line.startswith("✗ "):
            name, _, reason = line[2:].partition(" — ")
            checks.append([_clip(name, NAME_CHARS), False, _clip(reason, REASON_CHARS)])
        if len(checks) >= MAX_CHECKS:
            break
    if code is None:
        checks.append([f"finishes within {TEST_SECONDS} s", False, "it was stopped"])
        result = "not finished"
    elif code == 0 and checks and all(ok for _, ok, _ in checks):
        result = "Yes"
    elif code == 10:
        result = "No"
    else:
        lines = [ln.strip() for ln in raw.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("Node.js v")]
        why = next((ln for ln in lines if re.match(r"^\w*Error\b", ln)), lines[-1] if lines else f"exit {code}")
        checks.append(["the test ran to its end", False, _clip(why, REASON_CHARS)])
        result = "not finished"
    return result, checks, hashlib.sha256(raw).hexdigest()


def run_case(case: dict, on_clause=None) -> tuple[str, list]:
    """Writes the case to a folder in memory, runs each clause's test, and removes the folder."""
    workdir = tempfile.mkdtemp(prefix="case-", dir="/tmp")
    try:
        os.chmod(workdir, 0o755)
        for path, text in case["files"].items():
            full = os.path.join(workdir, path)
            os.makedirs(os.path.dirname(full), mode=0o755, exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(full, 0o644)
        clauses = []
        for n, c in enumerate(case["clauses"], 1):
            result, checks, h_out = run_test(workdir, c["test"])
            clauses.append({"id": c["id"], "result": result, "checks": checks, "H_output": h_out})
            if on_clause:
                on_clause(n, c["id"], result, checks)
        verdict = "pass" if clauses and all(c["result"] == "Yes" for c in clauses) else "fail"
        return verdict, clauses
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def process_request(req: dict, emit=None) -> dict:
    """emit(step) reports each step as it happens; the reply is returned at the end, as before."""
    say = emit or (lambda step: None)
    creds = {
        "AccessKeyId": req["AccessKeyId"],
        "SecretAccessKey": req["SecretAccessKey"],
        "Token": req["Token"],
    }
    wrapped = req["WrappedRoomKeyB64"]
    envelope = req["Envelope"]
    request_nonce = req.get("ClientNonce") or ""
    if not (isinstance(request_nonce, str) and NONCE_RE.fullmatch(request_nonce)):
        request_nonce = ""
    h_ct = ciphertext_hash(envelope)
    # anything the host adds about the outcome is ignored: the room decides by running the tests
    for k in ("Jev", "jev", "judgments"):
        req.pop(k, None)

    room_key = None
    try:
        room_key = kms_decrypt_room_key(creds, wrapped)
        say({"event": "key"})
        if len(room_key) not in (16, 24, 32):
            say({"event": "refused"})
            return seal(_fail(f"bad_room_key_len:{len(room_key)}"), request_nonce, h_ct, "void", emit)
        opened = aesgcm_decrypt(room_key, envelope)
    except Exception as e:
        say({"event": "refused"})
        return seal(_fail(f"decrypt_fail:{type(e).__name__}:{e}"), request_nonce, h_ct, "void", emit)
    finally:
        if isinstance(room_key, (bytes, bytearray)):
            try:
                ba = bytearray(room_key)
                for i in range(len(ba)):
                    ba[i] = 0
            except Exception:
                pass
            room_key = None

    H_input = hashlib.sha256(opened).hexdigest()
    case, wrong = read_case(opened)
    files = case.get("files") or {}
    prints = {
        "H_input": H_input,
        "H_build": group_hash(files, "build") if files else "",
        "H_data": group_hash(files, "data") if files else "",
        "H_tests": group_hash(files, "tests") if files else "",
        "H_clauses": hashlib.sha256(canon(case.get("clauses") or []).encode()).hexdigest() if case else "",
    }
    say({"event": "opened", **prints, "clauses": len(case.get("clauses") or [])})
    if wrong:
        return seal(_fail("case:" + "; ".join(wrong)[:300], **prints), request_nonce, h_ct, "fail", emit)
    verdict, clauses = run_case(case, lambda n, cid, result, checks: say({"event": "point", "n": n, "id": cid, "result": result, "checks": checks}))
    return seal({
        "verdict": verdict,
        "clauses": clauses,
        "clause_results": [c["result"] for c in clauses],
        **prints,
        "tee": "AWS Nitro Enclaves",
        "region": REGION,
        "runner": RUNNER,
        # Explicitly absent: room_key, the case's files, plaintext
    }, request_nonce, h_ct, verdict, emit)


def handle_conn(conn: socket.socket) -> None:
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf or b"\0" in buf:
            break
        if len(buf) > 8_000_000:
            conn.sendall(json.dumps(_fail("request_too_large")).encode() + b"\n")
            return
    raw = buf.split(b"\0", 1)[0].split(b"\n", 1)[0]
    try:
        req = json.loads(raw.decode())
        for banned in ("room_key", "RoomKey", "plaintext", "seller_evidence"):
            req.pop(banned, None)

        def emit(step: dict) -> None:
            # a step line names what happened, never data or keys; a lost line never stops the run
            try:
                conn.sendall(json.dumps(step, separators=(",", ":")).encode() + b"\n")
            except Exception:
                pass

        resp = process_request(req, emit)
    except Exception as e:
        resp = _fail(f"handler:{type(e).__name__}:{e}")
        resp["trace"] = traceback.format_exc()[-500:]
    for banned in (
        "room_key", "RoomKey", "plaintext", "seller_evidence",
        "SecretAccessKey", "Token", "AccessKeyId", "Jev", "jev",
    ):
        resp.pop(banned, None)
    conn.sendall(json.dumps(resp, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")


def main() -> int:
    print(f"[enclave_loop] Room v4 listening vsock:{LISTEN_PORT} region={REGION} runner={RUNNER}", flush=True)
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((socket.VMADDR_CID_ANY, LISTEN_PORT))
    sock.listen(5)
    while True:
        conn, addr = sock.accept()
        print(f"[enclave_loop] connection from {addr}", flush=True)
        try:
            handle_conn(conn)
        except Exception as e:
            print(f"[enclave_loop] conn_error:{e}", flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main() or 0)
