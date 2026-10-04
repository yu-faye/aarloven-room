#!/usr/bin/env python3
"""Aarloven min closed-loop INSIDE Nitro Enclave (in-enclave JEV LLM).

Receives (over vsock): KMS-wrapped room_key + AES-GCM envelope (+ optional junk Jev — IGNORED).
Decrypts room_key via kmstool_enclave_cli (Recipient attestation → KMS).
Decrypts envelope, runs deterministic schema checks, then CPU llama.cpp on baked GGUF.
Emits ONLY verdict + hashes + model_name + model_hash. Never returns room_key or plaintext.
Fail-closed: any model/parse error → fail.

v2 (Phase A): every reply also carries a receipt signed with a key made inside this enclave at boot, and an
attestation document from the Nitro hardware binding this enclave's PCR0 to the receipt's SHA-256
(user_data), the caller's nonce, and the signing key (public_key). The browser checks both.

v2 also reports each step as it happens, one JSON line each ({"event": ...}), before the reply line:
key released, data opened, each point judged, receipt signed. The lines name steps, never data or keys.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
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
LLAMA_CLI = os.environ.get("LLAMA_CLI", "/app/llama-completion")
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/qwen2.5-0.5b-instruct-q4_k_m.gguf")
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen2.5-0.5B-Instruct-Q4_K_M")
MODEL_META = os.environ.get("MODEL_META", "/app/models/model_meta.json")
GRAMMAR_PATH = os.environ.get("GRAMMAR_PATH", "/app/yn.gbnf")
AAD_DEFAULT = b"aarloven.min_closed_loop.v1"

EXPECTED_CLAUSE_IDS = ["C1", "C2", "C3"]


def _load_model_meta() -> tuple[str, str]:
    name = MODEL_NAME
    mh = ""
    try:
        meta = json.loads(open(MODEL_META, encoding="utf-8").read())
        name = meta.get("model_name") or name
        mh = meta.get("model_hash") or ""
    except Exception:
        pass
    if not mh and os.path.isfile(MODEL_PATH):
        h = hashlib.sha256()
        with open(MODEL_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        mh = h.hexdigest()
    return name, mh


MODEL_NAME_RT, MODEL_HASH_RT = _load_model_meta()


# ---------- Phase A: signed, attested receipts ----------
RECEIPT_VERSION = "aarloven.receipt.v2"
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
        "clause_results": out.get("clause_results") or [],
        "H_ciphertext": h_ciphertext,
        "H_input": out.get("H_input") or "",
        "H_result": out.get("H_result") or "",
        "model_hash": MODEL_HASH_RT,
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
    H_result = hashlib.sha256(b"REJECT_DETERMINISTIC").hexdigest()
    H_jev = hashlib.sha256(b"SKIPPED").hexdigest()
    out = {
        "verdict": "fail",
        "zh": "不过",
        "det_ok": False,
        "error": msg,
        "H_input": extra.get("H_input", hashlib.sha256(b"").hexdigest()),
        "H_result": H_result,
        "H_jev": H_jev,
        "nonce": extra.get("nonce", ""),
        "tee": "AWS Nitro Enclaves",
        "region": REGION,
        "model_name": MODEL_NAME_RT,
        "model_hash": MODEL_HASH_RT,
        "summary": f"verdict=fail | error={msg} | H(result)={H_result} | model={MODEL_NAME_RT}",
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


def run_deterministic(opened: bytes) -> tuple[bool, list[str], dict, str]:
    fail: list[str] = []
    try:
        pkg = json.loads(opened.decode())
    except Exception as e:
        return False, [f"json:{e}"], {}, hashlib.sha256(opened).hexdigest()
    H_input = hashlib.sha256(opened).hexdigest()
    ids = [c.get("id") for c in (pkg.get("clauses") or [])]
    if not pkg.get("seller_evidence"):
        fail.append("missing_seller_evidence")
    if ids != EXPECTED_CLAUSE_IDS:
        fail.append(f"clause_ids:{ids}")
    if not pkg.get("nonce"):
        fail.append("missing_nonce")
    return (len(fail) == 0), fail, pkg, H_input


# Extractive questions tuned for Qwen2.5-0.5B Q4 (abstract rubric-satisfy prompts are unreliable at 0.5B).
CLAUSE_QUESTIONS = {
    "C1": "Does the TEXT say the user must have edit access?",
    "C2": "Does the TEXT say finding a duplicate stops conversion?",
    "C3": "Does the TEXT say the lead status is set to Converted when conversion finishes?",
}


def _build_prompt(evidence: str, clause: dict) -> str:
    """Qwen2.5 ChatML extractive Yes/No (GBNF-constrained)."""
    cid = clause.get("id", "?")
    q = CLAUSE_QUESTIONS.get(cid)
    if not q:
        rubric = (clause.get("rubric") or "").strip()
        q = f"Does the TEXT support this requirement: {rubric}"
    return (
        "<|im_start|>system\n"
        "Answer using only: Result: Yes OR Result: No\n"
        "<|im_end|>\n"
        "<|im_start|>user\n"
        f"TEXT:\n{evidence}\n\nQUESTION: {q}\n"
        "<|im_end|>\n"
        "<|im_start|>assistant\n"
    )


def _llama_once(prompt: str) -> str:
    """Run baked llama-cli on CPU; fail-closed on any error."""
    if not os.path.isfile(LLAMA_CLI):
        raise RuntimeError("llama_cli_missing")
    if not os.path.isfile(MODEL_PATH):
        raise RuntimeError("model_gguf_missing")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
        tf.write(prompt)
        prompt_path = tf.name
    try:
        cmd = [
            LLAMA_CLI,
            "-m", MODEL_PATH,
            "-f", prompt_path,
            "-n", "8",
            "--temp", "0",
            "--seed", "42",
            "-c", "2048",
            "-t", "2",
            "--no-display-prompt",
            "--simple-io",
            "-no-cnv",
        ]
        if os.path.isfile(GRAMMAR_PATH):
            cmd.extend(["--grammar-file", GRAMMAR_PATH])
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "LLAMA_ARG_NO_PERF": "1"},
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            raise RuntimeError(f"llama_rc={proc.returncode}:{(proc.stderr or '')[:300]}")
        return proc.stdout or out
    finally:
        try:
            os.unlink(prompt_path)
        except Exception:
            pass


def _parse_yes_no(text: str) -> str:
    """Parse Result: Yes|No; anything else → UNJUDGED (fail-closed)."""
    m = re.search(r"(?im)\bResult:\s*(Yes|No)\b", text or "")
    if m:
        return "Yes" if m.group(1).lower() == "yes" else "No"
    # fallback: lone Yes/No on a line near the end
    m2 = re.search(r"(?im)^\s*(Yes|No)\s*$", text or "", re.M)
    if m2:
        return "Yes" if m2.group(1).lower() == "yes" else "No"
    return "UNJUDGED"


def run_jev_llm(pkg: dict, on_point=None) -> tuple[str, list[str], str, str]:
    """In-enclave semantic JEV via baked GGUF. Parent-supplied Jev is NEVER used."""
    evidence = (pkg.get("seller_evidence") or "").strip()
    clauses = pkg.get("clauses") or []
    results: list[str] = []
    jev_parts: list[str] = []
    for c in clauses:
        try:
            raw = _llama_once(_build_prompt(evidence, c))
            parsed = _parse_yes_no(raw)
            # Keep a short reasoning snippet for hash only (not leaked as plaintext evidence)
            snippet = re.sub(r"\s+", " ", (raw or "").strip())[:240]
        except Exception as e:
            parsed = "FAIL"
            snippet = f"model_error:{type(e).__name__}"
        results.append(parsed)
        if on_point:
            on_point(len(results), c.get("id"), parsed)
        jev_parts.append(
            json.dumps(
                {
                    "id": c.get("id"),
                    "result": parsed,
                    "model": MODEL_NAME_RT,
                    "model_hash": MODEL_HASH_RT,
                    "raw_snip": snippet,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    # Fail-closed: No / FAIL / UNJUDGED → fail
    verdict = "fail" if any(r in ("No", "FAIL", "UNJUDGED") for r in results) else "pass"
    H_result = hashlib.sha256(
        json.dumps(
            {
                "verdict": verdict,
                "clause_results": results,
                "fail_default": "reject",
                "model_name": MODEL_NAME_RT,
                "model_hash": MODEL_HASH_RT,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    H_jev = hashlib.sha256("\n".join(jev_parts).encode()).hexdigest()
    return verdict, results, H_result, H_jev


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
    # IGNORE any parent-supplied Jev / judgments — in-enclave model only
    _ = req.pop("Jev", None)
    req.pop("jev", None)
    req.pop("judgments", None)

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

    det_ok, det_fail, pkg, H_input = run_deterministic(opened)
    say({"event": "opened", "H_input": H_input})
    nonce = (pkg or {}).get("nonce", "")
    if not det_ok:
        out = _fail("deterministic:" + ",".join(det_fail), H_input=H_input, nonce=nonce)
        out["det_fail"] = det_fail
        return seal(out, request_nonce, h_ct, "fail", emit)

    verdict, results, H_result, H_jev = run_jev_llm(pkg, lambda n, cid, result: say({"event": "point", "n": n, "id": cid, "result": result}))
    zh = "过" if verdict == "pass" else "不过"
    summary = (
        f"verdict={verdict} | H(input)={H_input} | H(result)={H_result} "
        f"| H(jev)={H_jev} | nonce={nonce} | model={MODEL_NAME_RT} | model_hash={MODEL_HASH_RT[:16]}…"
    )
    return seal({
        "verdict": verdict,
        "zh": zh,
        "det_ok": True,
        "clause_results": results,
        "H_input": H_input,
        "H_result": H_result,
        "H_jev": H_jev,
        "nonce": nonce,
        "summary": summary,
        "tee": "AWS Nitro Enclaves",
        "region": REGION,
        "model_name": MODEL_NAME_RT,
        "model_hash": MODEL_HASH_RT,
        # Explicitly absent: room_key, seller_evidence, plaintext, parent Jev
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
    print(
        f"[enclave_loop] listening vsock:{LISTEN_PORT} region={REGION} "
        f"model={MODEL_NAME_RT} hash={MODEL_HASH_RT[:16]}…",
        flush=True,
    )
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
