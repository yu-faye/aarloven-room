# Intake test room

A **test image**, not Room v6. It runs one test on a buyer's encrypted legacy-DB export inside a Nitro Enclave and returns a signed, attested receipt. Nothing at the repo root is changed; Room v6 and its PCR0 are untouched. This image has its own PCR0.

## What it does

`intake_loop.py` listens on vsock port 5006, one JSON request per connection (newline-terminated, as `enclave_loop.py`). The request carries `creds`, `nonce`, `kms_key` (a KMS key ARN, `arn:aws:kms:eu-north-1:<12 digits>:key/<uuid>`, checked with a strict regex), `expected_buyer_fp`, `manifest` (exact JSON string), `buyer_sig`, `buyer_pubkey` and `tables`.

1. Checks that the SHA-256 of `buyer_pubkey` is `expected_buyer_fp` and that `buyer_sig` is an Ed25519 signature over the manifest bytes.
2. Unwraps each table key with `kmstool_enclave_cli` (key = the request's `kms_key`, `RSAES_OAEP_SHA_256`), decrypts with AES-256-GCM (AAD = table name).
3. Checks each table's SHA-256 and row count against the manifest.
4. Any failure in 1 to 3 gives verdict **VOID** and nothing is tested.
5. Runs T1 to T4 on `frames` and `episodes` (columns match the manifest; frames rows = sum of `episodes.length`; `action_x`/`action_y` in [0, 512]; at least half of the episodes have a success frame). The verdict is **PASS** only if all pass, else **FAIL**.
6. Returns `{receipt, sig, attestation_b64}`. The receipt is canonical JSON, signed with an Ed25519 key made at start. The NSM attestation covers `sha256(receipt)`, the nonce and that public key. The image's PCR0 comes from the attestation, not from any config.

The manifest is `{"tables": {name: {"sha256", "rows", "columns"}}}`. `frames` columns must be exactly `idx, episode_index, frame_index, ts, state_x, state_y, action_x, action_y, reward, done, success, task_index`.

## Files

| File | Purpose |
| --- | --- |
| `intake_loop.py` | the enclave program (Python 3.9, stdlib + `cryptography`) |
| `Dockerfile`, `build.sh`, `entrypoint.sh` | image; same pins and flattening as the root Dockerfile |
| `buyer_seal.py` | `buyer_seal.py EXPORT_DIR KMS_PUBLIC_KEY` prints the `tables` object (fresh AES key per table) |
| `verify_receipt.py` | `verify_receipt.py REPLY.json [--root nitro-root.pem] [--expect-pcr0 HEX]` |
| `test_local.py` | local tests with a fake kmstool and a stubbed NSM (format 1 and canon-2) |
| `local_stubs.py` | the fake kmstool and the stub NSM (module_id `STUB-NOT-A-NITRO-ENCLAVE`), shared by the tests and the replay |
| `buyer_seal_canon2.py` | canon-2: re-wraps a fourdb sealed intake's data key to the room's KMS public key (see below) |
| `replay_canon2.sh`, `replay_canon2.py` | canon-2: one-command offline replay of the real pusht intake through the handler |

## Build and run

The build context is the repo root, because the image reuses `kmstool_enclave_cli`, `libnsm.so`, `requirements.txt` and `inputs.sha256`:

    intake-test/build.sh [TAG] [EIF] prints PCR0, PCR1, PCR2
    docker build -f intake-test/Dockerfile .              the image only

The KMS key is not a build input: each request carries it as `kms_key`, so PCR0 does not depend on it (the key policy is pinned to PCR0, so it could not). A wrong key cannot decrypt tables the buyer wrapped to the real key's public half, and the receipt records the key used as `kms_key`. A missing or malformed `kms_key` gives VOID.

    nitro-cli run-enclave --eif-path aarloven-intake-test.eif --cpu-count 2 --memory 1024 --enclave-cid 17

Locally: `python3 intake-test/test_local.py` (no AWS, no network).

## Not built

- The host does not fetch the export from D1 (or anywhere). Whoever runs the host hands the payload to the enclave. The host can see the ciphertext and the wrapped keys but not the plaintext.
- No KMS key, key policy, vsock proxy or host-side service is included here.
- `buyer_seal.py` seals tables only. Producing the manifest, the buyer's Ed25519 signature and `expected_buyer_fp` is left to the buyer's own tooling.
- `verify_receipt.py` validates the AWS certificate chain only when you pass the Nitro root certificate with `--root`. Fetching and pinning that root is a TODO, and so is the root's fingerprint check.
- The image is not yet rebuilt twice to check that PCR0 is reproducible. The Dockerfile mirrors the root one, but it has not been built here (no Docker or nitro-cli was used).
- Node.js stays in the image to keep the package set identical to the root Dockerfile. The intake program does not use it.

## Reproducible build (2026-10-16)

Two builds with the REBUILD.md recipe (AL2023, Docker 25.0.16, nitro-cli 1.5.0), second from a copy with different file times and permissions, both gave:

    PCR0 b0d7bca68b9f7be48f94f6472e3033ebe23984eb6f735b8f2da32ab03df9d34030421a08c39ba088b24a8fbdba8f9c13

`intake-test-key-policy.json` is the proposed policy for the test-only KMS key (RSA_4096, ENCRYPT_DECRYPT): only this PCR0 may decrypt; admins manage but cannot decrypt. Not created yet.

## canon-2 draft (2026-10-17)

Draft, local only. Nothing here has run in an enclave, on AWS, or on the real KMS key.

### What changed

`intake_loop.py` now also takes a sealed intake in the format **`fourdb-canon-2`** (the li4db `fourdb` connector, `--mode sealed`; rules in its `CANON.md`). The request carries `"format": "fourdb-canon-2"`; without that field it is the prototype format 1, handled as before and answered with receipt `/1`.

- `manifest`: the exact text of the connector's `manifest.json` (neutral manifest, `dataset_fingerprint`, `sealed` block). The buyer's Ed25519 signature, pinned fingerprint and `kms_key` work as in format 1.
- `wrapped_dek_b64`: the one data key, wrapped by KMS (`RSAES_OAEP_SHA_256`), unwrapped with kmstool as before. `tables[name].sealed_b64`: the connector's `nonce || ciphertext || tag`, AES-256-GCM, AAD `fourdb-seal-1|canon|dataset_fingerprint|table`.
- The room re-derives, from the decrypted rows, every table's row count and SHA-256 and the dataset fingerprint (a small stdlib port of the connector's `canon_line`, `table_digest`, `dataset_fingerprint`). It also requires every line to be in canonical form and in canonical order. Any mismatch with the signed manifest is **VOID** (bad signature, canon id other than `fourdb-canon-2`, fingerprint not the hash of the neutral manifest, ciphertext hash, GCM tag or AAD, digest, row count, hash-only manifest).
- Not ported: the connector's value canonicalization (floats, decimals, timestamps, NFC, ...). The room checks that rows are already canonical lines, not that they are the right canonical value for the source database. Column names, logical types and `pk` are taken from the buyer-signed manifest; they cannot be re-derived from the rows. T3 reads canon-2 `f32`/`f64` strings (e.g. `"1.28e+02"`) as numbers.
- T1 to T4 are the same tests with the same thresholds (T4 still FAILs on pusht, 0/206). T1 compares the `frames` columns as a set, since canon-2 lists columns sorted.

Receipt **`aarloven-intake-test-receipt/2`** adds `canon` (`fourdb-canon-2`), `dataset_fingerprint` (re-derived; `""` on VOID), `manifest_sha256`, and `tables` as `{name: {rows, sha256}}` in canon-2 digests. Each test carries `verdict`; `result` stays with the same value (so v1 readers work; `verdict` is the name going forward). `code_sha256` (hash of `intake_loop.py`) is as before. `verify_receipt.py` verifies both formats, prints canon and fingerprint, takes `--expect-fingerprint`, and prints a STUB warning when the attestation's module_id says so. The saved real v1 receipt in `evidence/` still verifies offline with `--root evidence/nitro-root-G1.pem` (that file is the AWS Nitro root from `AWS_NitroEnclaves_Root-G1.zip`; its SHA-256 fingerprint is 64:1A:03:21:...:79:BB:5B; I did not compare it to the AWS documentation online). `/workspace/intake/run/root.pem` does not exist; only the zip is there.

### KMS wrapping, honestly

The connector wraps its data key with a local KEK file, not KMS (its `KmsKeyWrapper` is a stub). `buyer_seal_canon2.py` is the buyer-side bridge: it opens that data key with the local KEK and wraps it again to an RSA public key. The sealed tables are untouched, so their AAD still binds canon id, fingerprint and table. In the local tests the RSA key is a throwaway one and the room's kmstool is a fake (`local_stubs.py`); the real path would use the test KMS key's public half and the real kmstool, which has never been exercised with a canon-2 request. The manifest's `sealed.key_wrapper` still says `local-test-kek-v1`; the room ignores it.

### Local replay

    intake-test/replay_canon2.sh

Offline, no docker. It builds the pusht SQLite from `/workspace/intake/raw` with the li4db loaders (read-only use of that checkout), seals it with the connector, bridges the key, runs the handler in-process with the fake kmstool and the stub NSM, verifies the receipt/2 and runs tamper cases (wrong buyer signature, flipped ciphertext, wrong canon id in the AAD, edited manifest, edited and re-signed manifest): all VOID. Needs a Python with pyarrow for the first step (default: the overnight venv; `FOURDB_PY`). Result of the last run: the full intake (episodes, frames, operators) gives `06a0fb071b22183d0288a704925260fdb6f201e3bd0756e9e3ec8ad1c530b843`, the connector's baseline, re-derived in the room. The pusht-only subset (episodes, frames) gives `769b4582...`: a different fingerprint, because the neutral manifest has no `operators` table (synthetic, not pusht); it equals the connector's own fingerprint for the same two tables. Verdict FAIL in both, T4 0/206, as in the real v1 receipt. The attestation in these receipts is a **stub** (module_id `STUB-NOT-A-NITRO-ENCLAVE`, throwaway certificate chain, placeholder PCR0); they prove nothing about any enclave. Tested with Python 3.13 here; the enclave runs 3.9 and the code avoids newer syntax, but it was not run under 3.9.

### What this does NOT do, and what is needed

1. **New PCR0.** `intake_loop.py` is copied into the image (`Dockerfile`: `COPY ... intake-test/intake_loop.py`), so this change changes the test-room image and its PCR0. The new PCR0 is **not computed here**: no reproducible build was run. It needs the AL2023 / nitro-cli recipe of REBUILD.md (two builds, compared). `b0d7bca6...` above is the PCR0 of the old image only.
2. **KMS key policy.** `intake-test-key-policy.json` (key `eb2d8fbd...`) pins decrypt to the OLD test PCR0 `b0d7bca6...`. The new image could not decrypt real wrapped keys until that policy is updated to the new PCR0. That needs Yufei's OK and an AWS change; **nothing was done on AWS** and the file here is unchanged. (The old image keeps working with the old policy but does not understand canon-2.)
3. **CI does not cover this.** `.github/workflows/repro-check.yml` builds Room v6 from the root files only (its path filter is the root Dockerfile, `build.sh`, `enclave_loop.py`, ..., `EXPECTED_PCR0.txt`, `ci/**`). It does not build `intake-test/`, does not compare any intake-test PCR0, and a change under `intake-test/` does not even trigger it. So it will **not** flag this change at all. Proposal, not implemented (no workflow was touched): a second workflow `intake-test-check.yml` on `intake-test/**` plus the shared inputs, that (a) runs `python3 intake-test/test_local.py`, (b) builds the test room twice with the same recipe and `intake-test/build.sh`, (c) compares both PCR0 values with a new `intake-test/EXPECTED_PCR0.txt`, and (d) fails if the PCR0 in `intake-test-key-policy.json` differs from that file, so the policy cannot silently lag the image.
4. **Room v6 untouched.** Nothing at the repo root was changed: Dockerfile, `enclave_loop.py`, `EXPECTED_PCR0.txt`, `build.sh`, `ci/` and the workflows are as they were, and so is Room v6's PCR0.
