# Aarloven sealed room

This is the code that runs inside Aarloven's sealed room: an AWS Nitro Enclave in Stockholm (`eu-north-1`).

A buyer's case reaches the room sealed. It holds:
- the vendor's build;
- the buyer's data;
- the tests that buyer and vendor agreed on.

AWS KMS releases the key only to an enclave whose image measurement (PCR0) is the one this folder builds, so nothing else can open the case, not even us. The room then:
- runs the agreed tests itself;
- in a private case, seals each check's name and reason to the buyer's key (the vendor's copy shows only the outcomes);
- decides from their results (no language model is involved);
- signs a receipt;
- asks AWS's hardware for a document that vouches for that receipt.

Anyone can rebuild the image from this folder and get the same PCR0. Compare it with:
- the `pcr0` of the release in [aarloven.com/releases.json](https://aarloven.com/releases.json);
- the PCR0 inside the AWS document that comes with every receipt;
- the PCR0 that the KMS key policy requires ([aarloven.com/trust](https://aarloven.com/trust)).

## Run the same tests yourself

The sample case on aarloven.com is public: [samples/espocrm-1](samples/espocrm-1) holds the agreed points, the data, the tests, and two builds of the vendor's code (v1.4, and v1.3, which never wrote the duplicate check).

    node rerun.mjs v1.3                 the same tests, laid out as the room lays them out
    node rerun.mjs v1.3 receipt.json    and compared with a receipt saved on aarloven.com

It prints:
- each check;
- the result per point;
- the fingerprints the room puts in its receipt (`H_input` for the whole case, then `H_build`, `H_data`, `H_tests` and `H_clauses`).

A private receipt is compared by position, since it names no checks. Its case also names the demo buyer's public key (`samples/espocrm-1/demo-buyer-key.json`).

## Rebuild the room

You need x86_64 Linux with Docker (BuildKit) and `nitro-cli` 1.5.0. One way is an EC2 instance running Amazon Linux 2023 with Nitro Enclaves enabled, after `sudo dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel`.

    ./build.sh

The script checks the two AWS binaries against `inputs.sha256`, builds without any cache, and prints PCR0, PCR1 and PCR2. PCR0 covers the whole image. PCR1 depends on the kernel that ships with `nitro-cli`.

| Input | Pinned by |
| --- | --- |
| Base image | Digest `sha256:12052e9b…` (Amazon Linux 2023.12.20260930) |
| System packages | That release's versioned repository (`--releasever`), and each package by version: Python 3.9, Node.js 24.21 |
| Python packages | Version and SHA-256 (`requirements.txt`), installed without byte-code |
| `kmstool_enclave_cli`, `libnsm.so` | SHA-256 (`inputs.sha256`). Built from AWS's [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c) v0.4.5 (commit `cd61b618`) with its `containers/Dockerfile.al2`, and published here as built |

The Dockerfile removes or sets everything that would differ between two builds: package databases, logs, caches, the time on every file, and the permissions a checkout gives the copied files.

**Checked on 2026-10-05** (Docker 25.0.16, buildx 0.12.1, nitro-cli 1.5.0). Two builds with no cache, from two copies of this folder whose files carried different times and permissions, gave the same image and the same PCR0. For Room v5, the room with private receipts, that is `c5b644d4712d6393fcafe38907dd63f521599d12e8a918cf97732c7c340430f37b712a4061541e087fca4165fd462bf6`. Room v4 was `a2f8dbe4…`.

## What the room does with a request

`enclave_loop.py` listens on vsock port 5005 for one request at a time from its host. The request carries:
- short-lived AWS credentials;
- the room key, wrapped by KMS;
- the sealed case;
- the caller's one-time number (nonce).

The room then:
1. **Gets the key.** It asks KMS for the room key through `kmstool_enclave_cli`. The request carries the enclave's attestation, so KMS checks PCR0 before it answers.
2. **Opens the case.** The case is sealed with AES-256-GCM. If even one byte was changed, it does not open, nothing is tested, and the receipt says VOID.
3. **Runs each point's test with Node.**
   - Each test runs as the unprivileged user `nobody`, so it cannot read the room's memory or its keys.
   - It runs in a folder in memory, with no network.
   - It has 10 seconds, capped output, and limits on processes and file size.
   - A point is **Yes** when its test exits 0 with every check passed, **No** when it exits 10, and **not finished** otherwise.
   - The verdict is PASS only when every point is Yes.
4. **Keeps a private case private.** A case may name its buyer's public key (`private_to`, a P-256 JWK). Then the room:
   - seals every check's name, reason and output fingerprint to that key, using ECDH P-256, HKDF-SHA256 (salt `aarloven`, info `aarloven.receipt.details.v1`) and AES-256-GCM;
   - puts only each check's outcome, by position, in the receipt and in the live steps.

   The vendor knows the agreed tests, so the positions tell them what to fix, but nothing of the buyer's data. The buyer opens the sealed part with their key; [receipt-open.js](https://aarloven.com/receipt-open.js) does it in a browser.
5. **Signs a receipt.** The receipt lists each check and its outcome, fingerprints the build, the data and the tests, names the test runner, and names the previous receipt. It is signed with an Ed25519 key that the room makes in its memory when it starts.
6. **Gets AWS's document.** It asks the Nitro Security Module for a document that carries the receipt's SHA-256, the caller's nonce and the room's public key.
7. **Reports as it goes.** It reports each step while it happens (key, opened, each point with its checks, signed). The steps carry fingerprints, check names and outcomes, never the case's files.

A case is canonical JSON: `{"kind": "aarloven.case.v1", "clauses": [{"id", "clause", "test"}], "files": {"build/…", "data/…", "tests/…"}}`, plus `"private_to"` for a private case. It may hold at most 64 files and 512 KiB, with `.mjs`, `.js`, `.json`, `.txt` or `.csv` files under `build/`, `data/` and `tests/` only.

## Check a receipt

- In a browser, on a real receipt from the room: [aarloven.com/trust](https://aarloven.com/trust#check-aws).
- In code, with [nitro-verify.js](https://aarloven.com/nitro-verify.js). It checks the document against AWS's Nitro root certificate (fingerprint `64:1A:03:21…BB:5B`), the certificate chain, the hardware's signature, the PCR0, the nonce and the receipt's hash. The receipt's own Ed25519 signature is then checked with the key the document names.
