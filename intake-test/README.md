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
| `replay_optin.sh`, `optin_make_intakes.py`, `replay_optin.py` | canon-2 opt-in policies: docker replay of Sakila / Northwind / pubs intakes through the handler (see "Opt-in policies") |

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
- Not ported: the connector's reading of the source database. The room checks that rows are canonical lines and that every cell is well-formed for its declared logical type (see "Opt-in policies"), not that it is the right value for the source. Column names, logical types and `pk` are taken from the buyer-signed manifest; they cannot be re-derived from the rows. T3 reads canon-2 `f32`/`f64` strings (e.g. `"1.28e+02"`) as numbers.
- T1 to T4 are the same tests with the same thresholds (T4 still FAILs on pusht, 0/206). T1 compares the `frames` columns as a set, since canon-2 lists columns sorted.

Receipt **`aarloven-intake-test-receipt/2`** adds `canon` (`fourdb-canon-2`), `dataset_fingerprint` (re-derived; `""` on VOID), `manifest_sha256`, and `tables` as `{name: {rows, sha256}}` in canon-2 digests. Each test carries `verdict`; `result` stays with the same value (so v1 readers work; `verdict` is the name going forward). `code_sha256` (hash of `intake_loop.py`) is as before. `verify_receipt.py` verifies both formats, prints canon and fingerprint, takes `--expect-fingerprint`, and prints a STUB warning when the attestation's module_id says so. The saved real v1 receipt in `evidence/` still verifies offline with `--root evidence/nitro-root-G1.pem` (that file is the AWS Nitro root from `AWS_NitroEnclaves_Root-G1.zip`; its SHA-256 fingerprint is 64:1A:03:21:...:79:BB:5B; I did not compare it to the AWS documentation online). `/workspace/intake/run/root.pem` does not exist; only the zip is there.

### KMS wrapping, honestly

The connector wraps its data key with a local KEK file, not KMS (its `KmsKeyWrapper` is a stub). `buyer_seal_canon2.py` is the buyer-side bridge: it opens that data key with the local KEK and wraps it again to an RSA public key. The sealed tables are untouched, so their AAD still binds canon id, fingerprint and table. In the local tests the RSA key is a throwaway one and the room's kmstool is a fake (`local_stubs.py`); the real path would use the test KMS key's public half and the real kmstool, which has never been exercised with a canon-2 request. The manifest's `sealed.key_wrapper` still says `local-test-kek-v1`; the room ignores it.

### Local replay

    intake-test/replay_canon2.sh

Offline, no docker. It builds the pusht SQLite from `/workspace/intake/raw` with the li4db loaders (read-only use of that checkout), seals it with the connector, bridges the key, runs the handler in-process with the fake kmstool and the stub NSM, verifies the receipt/2 and runs tamper cases (wrong buyer signature, flipped ciphertext, wrong canon id in the AAD, edited manifest, edited and re-signed manifest): all VOID. Needs a Python with pyarrow for the first step (default: the overnight venv; `FOURDB_PY`). Result of the last run: the full intake (episodes, frames, operators) gives `06a0fb071b22183d0288a704925260fdb6f201e3bd0756e9e3ec8ad1c530b843`, the connector's baseline, re-derived in the room. The pusht-only subset (episodes, frames) gives `769b4582...`: a different fingerprint, because the neutral manifest has no `operators` table (synthetic, not pusht); it equals the connector's own fingerprint for the same two tables. Verdict FAIL in both, T4 0/206, as in the real v1 receipt. The attestation in these receipts is a **stub** (module_id `STUB-NOT-A-NITRO-ENCLAVE`, throwaway certificate chain, placeholder PCR0); they prove nothing about any enclave. `test_local.py` passes under Python 3.13 and, as of round 6, under Python 3.9 (the enclave version) too (54 tests in both); the replays ran under 3.13.

### What this does NOT do, and what is needed

1. **New PCR0.** This branch (`room-intake-optin`) changes `intake_loop.py` again, so its PCR0 differs from PR #6's; it is recorded in the opt-in section below and in this branch's `EXPECTED_PCR0.txt`. **PR #6's tip (measured 2026-10-17, 18:13 Oslo):** `intake_loop.py` is copied into the image, so this change changes the test-room PCR0. Built twice on the box from commit `8ce21ad` with the REBUILD.md recipe (AL2023 host container, Docker 25.0.16, nitro-cli 1.5.0, each build in its own empty dockerd, the second from a copy with file times set to 2031 and group-write permissions):

       PCR0 7544b291e44d4654e418ae99b6211b807fc965acb2bb6eca7d26346a7502b0a82073c9fd0f42166740e9d4c39fa16e37
       PCR1 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
       PCR2 47ff64ab9c26eefbceef8fdaa5de729c662064817e80f4523f19f9d912ef5bcb0cd9a8e142b853ef791c372548619856

   Both builds gave the same PCR0. It is recorded in `intake-test/EXPECTED_PCR0.txt`. `b0d7bca6...` above is the PCR0 of the old image (PR #5) only. The image inputs are only `requirements.txt`, `inputs.sha256`, `kmstool_enclave_cli`, `libnsm.so`, `intake-test/{Dockerfile,intake_loop.py,entrypoint.sh}`, so README, tests, the verifier and the workflow do not change PCR0.
2. **KMS key policy.** `intake-test-key-policy.json` (key `eb2d8fbd...`) pins decrypt to the OLD test PCR0 `b0d7bca6...`. The new image could not decrypt real wrapped keys until that policy is updated to the new PCR0. That needs Yufei's OK and an AWS change; **nothing was done on AWS** and the file here is unchanged. (The old image keeps working with the old policy but does not understand canon-2.)
3. **CI.** `.github/workflows/repro-check.yml` builds Room v6 from the root files only and is not triggered by `intake-test/` changes. A separate draft workflow, `intake-test/ci-draft/intake-test-repro-check.yml` (not active: it must be moved to `.github/workflows/`, see `ci-draft/README.md`), runs `test_local.py` on Python 3.9, builds the test room twice, compares both PCR0 values with `intake-test/EXPECTED_PCR0.txt`, and fails if the PCR0 pinned in `intake-test-key-policy.json` differs from that file. **That last job fails on purpose today**: the proposed policy still pins `b0d7bca6...`. Updating the policy file and the real key policy needs Yufei's OK.
4. **Room v6 untouched.** Nothing at the repo root was changed: Dockerfile, `enclave_loop.py`, `EXPECTED_PCR0.txt`, `build.sh`, `ci/` and the workflows are as they were, and so is Room v6's PCR0.

## Opt-in policies (branch `room-intake-optin`, round 6; draft, local only)

Nothing here has run in an enclave, on AWS or on the real KMS key; the replays use a fake kmstool and a STUB NSM.

### What the room accepts and checks now

The buyer-signed canon-2 manifest may carry the opt-in policies of the connector's `CANON.md` section 10 and `omitted_columns`. `intake_loop.py` re-derives the digests and the dataset fingerprint exactly as before (the whole neutral manifest, `opt_in`, `declared_labels`, `omitted_columns` and `legacy_policy` included, is hashed as it stands; only table digests and row counts come from the decrypted rows) and now also checks, **before** any KMS call where it can:

- the neutral manifest keys, the table keys and `opt_in` (`timestamp_tz`, `enum_set_as`, `binary_as`, `omit_unsupported`, `year_as`, `geometry`) are known and well-formed; an unknown key or value is **VOID**;
- every logical type is known (`int bool f32 f64 text char:n dec:p,s timestamp:p date year enum:text set:text binary:sha256 binary:hex geometry:wkb-sha256`); an unknown one is **VOID**;
- a type is backed by its policy (a `binary:*` column needs the same `opt_in.binary_as`, `enum:text`/`set:text` need `enum_set_as`, `year` needs `year_as`, `opt_in.geometry.columns` must list exactly the geometry columns, `opt_in.timestamp_tz.columns` only timestamp columns read as UTC, `omitted_columns` need `omit_unsupported`); `declared_labels` exist for exactly the enum/set columns;
- after decryption, every row has exactly the manifest's columns (a row that still carries an omitted column, or lacks a declared one, is **VOID**) and every cell is well-formed for its type: geometry `{srid (uint32), len (>= 9), sha256 (64 lower hex)}`, binary `{len, sha256}` (an empty value has the SHA-256 of nothing), hex lowercase and at most 4096 bytes, year an integer 1901..2155, enum label among the declared labels, set labels declared, unique and sorted by code point, timestamp canonical UTC `YYYY-MM-DDTHH:MM:SS[.f x p]Z` and a real date, decimal canonical, float canonical, NFC text, char exactly n characters.

This is a format check. The room does not know the source database: it cannot tell a real geometry hash from a made-up one.

### Receipt/2 additions

`opt_in`, `legacy_policy` and `omitted_columns` (`{table: [{name, type, reason}]}`) are copied from the signed manifest into the receipt, plus a fixed `policy_note`; all are empty on a VOID receipt (the manifest was not validated). `verify_receipt.py` requires the fields and prints them. The room claims no more than the manifest says: **`opt_in.timestamp_tz.declared_zone` is the seller's word**, nothing verified it (the connector only forces its read session to UTC; the declared zone only says what zone the application used); the receipt says nothing about the content of omitted columns, and a fingerprint with omissions proves the supported columns only.

### PCR0 of this branch (measured 2026-10-17, ~18:50 Oslo)

Two builds of commit `901b310` with the same recipe as above (fresh dockerd each, second copy with other file times and permissions):

    PCR0 2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0
    PCR1 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
    PCR2 f2b70f8e2015b89103e38b6e03db2ba50280c8d292c2e3f82364367027b57b387b2250959b56dfab7d4c51c4fbc20d1e

Both identical. Any later change to `intake_loop.py` changes it again. Control: the same recipe on PR #5's tip `6c84a62` gave `b0d7bca6...` twice, the PCR0 measured on 2026-10-16 and pinned in the test key policy, so the box recipe matches the earlier one.

### Datasets other than pusht: verdict N/A

T1 to T4 are defined for the pusht schema (tables `frames` and `episodes`). For any other dataset (Sakila, Northwind, pubs, ...) the room still opens, checks and re-derives everything, then reports one test `TX` with result/verdict **`N/A`** ("no applicable test") and overall verdict **`N/A`**. It is never PASS: the receipt then proves the dataset fingerprint (and the policies) only. A dataset with only one of the two tables is also N/A. pusht behaviour is unchanged: the full intake still gives FAIL (T4 0/206) and fingerprint `06a0fb07...`. One deliberate change: a row that lacks a column the signed manifest declares is now VOID (before: T1 FAIL), because for tables the tests do not cover there is no test that would otherwise notice; T1 still FAILs when the manifest itself lacks an expected `frames` column.

### Round-5 review notes (gpt-5), decided

1. **Float strings.** CANON.md section 2 requires the canonical form (shortest round-trip decimal `d[.ddd]e+XX`, `0`, `nan`, `inf`, `-inf`; JSON string). So both: T3 (`_canon_number`) parses any string `float()` accepts, and the room separately enforces canonical form for every f32/f64 cell by re-computing it with a port of `canon_float` (checked against the connector in `test_local.py`); a non-canonical or out-of-range string is **VOID** with its own reason, not a T3 FAIL.
2. `verify_receipt.py` finds `V0` by id, not as `tests[0]`.
3. A receipt/2 VOID produced before the KMS step (bad nonce, buyer, manifest or policy check, missing credentials or tables) no longer echoes the request's `kms_key`; it is echoed once the KMS call was attempted and on PASS/FAIL/N/A. Format 1 is unchanged.
4. **Final newline.** CANON.md section 3: `table.sha256` is over `line + "\n"` for every row, so a last line without `\n` is not the byte stream the connector hashed. Kept strict (VOID) and documented in `canon2_rows`.
5. `chain_validated` is set True only after `verify_chain` returned.

### Replay: `intake-test/replay_optin.sh`

Needs docker with `mysql:5.7`, `mysql:8.4`, `mssql/server:2022-latest`, the dump cache `/workspace/cache/legacy-dumps` (never downloaded by the script) and the li4db checkout (read-only). It starts one container at a time (`r6-optin-my57/my84/ms22`, ports 58610 to 58612, removed at the end and on error), loads the dumps with `run_public`'s loaders, lets the connector seal canon-2 intakes (`--legacy`), runs them through the handler with the fake kmstool and STUB NSM, and compares fingerprints. About a minute. Result of the last run (`evidence/2026-10-17-optin-replay-results.json`; fingerprints and counts only, no rows; ALL AS EXPECTED):

| intake | flags | tables | room fp == connector fp |
| --- | --- | --- | --- |
| Sakila, MySQL 5.7.44 and 8.4.11 (A) | timestamp-tz UTC, enum-set-as text, binary-as sha256, year-as int, geometry-as wkb-sha256 + storage mysql-srid-wkb | 16/16 | yes; identical on 5.7 and 8.4 |
| Sakila, 5.7 and 8.4 (B) | same without geometry, with `--omit-unsupported` (`address.location` omitted and listed) | 16/16 | yes; identical on both |
| Northwind, SQL Server 2022, `--binary-as sha256` | | 12/13 | yes |
| Northwind, `--binary-as hex` | | 10/13 | yes |
| pubs, `--binary-as sha256` / `hex` | | 11/11 | yes |

Left out, and listed in the results: Northwind `Order Details` (the seal gate and the room accept only plain identifiers; a space in a table name is refused), and with hex `Categories` and `Employees` (images of 10746 and 21626 bytes exceed the 4096-byte limit of `hex`). Every receipt has verdict N/A (no pusht tables), never PASS. pubs fingerprints change from run to run (`titles.pubdate` is the load time). Tamper cases, each VOID (17, including: `declared_zone` edited and re-signed (fingerprint mismatch, and with the fingerprint recomputed the AAD no longer opens), enum label not declared, set unsorted / undeclared, malformed geometry, wrong-length binary hash, year 1800, timestamp with an offset, unknown logical type, unknown `opt_in` key, an omitted column present in the rows). The value-level cases re-seal consistent data, so only the room's own checks can catch them. The Sakila/SQL Server numbers are only as good as the connector's own reading; the room adds no check of the source.
