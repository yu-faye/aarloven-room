# Aarloven sealed room

This is the code that runs inside Aarloven's sealed room: an AWS Nitro Enclave in Stockholm (`eu-north-1`).

A buyer's data reaches the room sealed. AWS KMS releases the key only to an enclave whose image measurement (PCR0) is the one this folder builds, so nothing else can open the data, not even us. The room then:
- tests the delivery against the agreed points;
- signs a receipt;
- asks AWS's hardware for a document that vouches for that receipt.

Anyone can rebuild the image from this folder and get the same PCR0. Compare it with:
- the `pcr0` of the release in [aarloven.com/releases.json](https://aarloven.com/releases.json);
- the PCR0 inside the AWS document that comes with every receipt;
- the PCR0 that the KMS key policy requires ([aarloven.com/trust](https://aarloven.com/trust)).

## Rebuild it

You need x86_64 Linux with Docker (BuildKit) and `nitro-cli` 1.5.0. One way is an EC2 instance running Amazon Linux 2023 with Nitro Enclaves enabled, after `sudo dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel`.

    ./build.sh

The script:
1. fetches the model and checks every input against `inputs.sha256`;
2. builds without any cache;
3. prints PCR0, PCR1 and PCR2.

PCR0 covers the whole image; PCR2 covers the room's own filesystem. PCR1 depends on the kernel that ships with `nitro-cli`, so it changes with the `nitro-cli` version.

## What is pinned, and how

| Input | Pinned by |
| --- | --- |
| Base image | Digest `sha256:12052e9b…` (Amazon Linux 2023.12.20260930) |
| System packages | That release's versioned repository (`--releasever`), and each package by version |
| Python packages | Version and SHA-256 (`requirements.txt`), installed without byte-code |
| llama.cpp | Commit `d775ebf3…`, built for CPU with fixed flags |
| `kmstool_enclave_cli`, `libnsm.so` | SHA-256 (`inputs.sha256`). Built from AWS's [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c) v0.4.5 (commit `cd61b618`) with its `containers/Dockerfile.al2`, and published here as built |
| Model | SHA-256 (`inputs.sha256`): Qwen2.5-0.5B-Instruct, Q4_K_M, from [Qwen/Qwen2.5-0.5B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) |

Anything that would differ between two builds is removed or set to zero in stages 3 and 4 of the `Dockerfile`: package databases, logs, caches, and the time on every file.

**Checked on 2026-10-04** (Docker 25.0.16, buildx 0.12.1, nitro-cli 1.5.0). Two builds with no cache, from two copies of this folder whose files carried different times, gave the same image and the same PCR0: `5180d1aed202813220e7bb065c13169899aabbc0cc02617cdf2161e8e82e85fcdc40a0ad273d321a7c8726ad1d302a51`.

## What the room does with a request

`enclave_loop.py` listens on vsock port 5005 for one request at a time from its host. The request carries:
- short-lived AWS credentials;
- the room key, wrapped by KMS;
- the sealed package;
- the caller's one-time number (nonce).

The room then:
1. **Gets the key.** It asks KMS for the room key through `kmstool_enclave_cli`. The request carries the enclave's attestation, so KMS checks PCR0 before it answers.
2. **Opens the package.** The package is sealed with AES-256-GCM. If even one byte was changed, it does not open, nothing is judged, and the receipt says VOID.
3. **Judges each agreed point.** It asks Qwen2.5-0.5B (llama.cpp, limited to Yes or No by `yn.gbnf`) about each point.
4. **Signs a receipt.** The receipt carries the verdict, the answer per point, and fingerprints of the package and of the data read. It is signed with an Ed25519 key that the room makes in its memory when it starts, and it names the previous receipt.
5. **Gets AWS's document.** It asks the Nitro Security Module for a document that carries the receipt's SHA-256, the caller's nonce and the room's public key.
6. **Reports as it goes.** It reports each step while it happens (key, opened, each point, signed). The steps carry no data or keys.

Nothing is written to disk: an enclave has none. The files the judge needs live in memory and are deleted after each point.

## Check a receipt

- In a browser, on a real receipt from the room: [aarloven.com/trust](https://aarloven.com/trust#check-aws).
- In code, with [nitro-verify.js](https://aarloven.com/nitro-verify.js). It checks the document against AWS's Nitro root certificate (fingerprint `64:1A:03:21…BB:5B`), the certificate chain, the hardware's signature, the PCR0, the nonce and the receipt's hash. The receipt's own Ed25519 signature is then checked with the key the document names.
