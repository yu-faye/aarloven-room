# Real run of the intake TEST room at 1b9dc02 (PR #7), 2026-10-17 19:47-19:53 Oslo

- Host: i-0c2662642489fd7a7 (m6i.xlarge, eu-north-1), one start, stopped right after. EIF built on the host from this commit:
  PCR0 2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0 (= EXPECTED_PCR0.txt).
- Room v6 (PCR0 3ea0a6f5...) was stopped only for the test runs and restored (see RESTORED_PCR0 / HEALTH in host-run.txt).
- Test KMS key eb2d8fbd key policy: PCR0 condition changed b0d7bca6... -> 2b24ad8b... before the run.
- Dataset: the-future-dev/pusht-image-v1 @ 0b4d45ea (Hugging Face, Apache-2.0), 281 episodes / 24,549 frames, converted to the raw
  episodes/frames layout and sealed as fourdb-canon-2 (connector aarloven-arch a645bf6, --mode sealed); DEK wrapped to the test key.
  Payload sha256 b5811adc9d691ba193ac02a3522e9803c1fe409676bf97c4d387734e89bdea32.

| reply | enclave | expected | got |
|---|---|---|---|
| reply-good.json | prod | PASS T1-T4, fingerprint 921056c1...f25c1 | PASS T1-T4, fingerprint 921056c113dd0c79f3aa877b4e40b8bfdb4c0735519387c907ed0c53328f25c1 |
| reply-tampered.json | prod | VOID (1 bit flipped in frames ciphertext) | VOID: sealed SHA-256 differs from the manifest |
| reply-debug.json | debug mode (PCR0 = 0) | KMS refuses the key -> VOID | VOID: kmstool decrypt failed |

All three attestations chain to the AWS Nitro root (nitro-root-G1.pem); see verify-output.txt.
Re-check: `python3 intake-test/verify_receipt.py intake-test/evidence/2026-10-17-r7-real-run/reply-good.json --root intake-test/evidence/nitro-root-G1.pem --expect-pcr0 2b24ad8b... --expect-fingerprint 921056c1...`
Note: the debug reply's detail keeps only the first ~400 chars of kmstool stderr (INFO lines), so the KMS AccessDenied text itself is cut off; small follow-up: keep the stderr tail instead.
