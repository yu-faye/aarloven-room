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
| `test_local.py` | local tests with a fake kmstool and a stubbed NSM |

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
