# Runbook: re-pin the test KMS key to a new test-room PCR0

**For Yufei to run. This file was written on the box, where nothing was run against AWS; every `aws` command below is untested here.** The box has no credentials by design. The only offline parts that were run are `check_policy_pcr0.py` and its tests.

- Key: `eb2d8fbd-4b64-48d4-a0ff-796d15056d28`, region `eu-north-1`, account `882334275017` (from `intake-test-key-policy.json`). This is the **test** key only.
- Live policy today: pinned to PCR0 `2b24ad8b…` (PR #7, set 2026-10-17 19:47 Oslo). The repo copy `intake-test-key-policy.json` is older (`b0d7bca6…`) and is **not** a faithful copy of the live policy; always start from the live one (step 2).
- Target: the PCR0 in `intake-test/EXPECTED_PCR0.txt` of the room PR that gets merged. After PR #8 (kmstool-tail) it is `22248f58…`; after PR #9 (quoted identifiers, stacked on #8) it is `88c12e7b…`. If both merge, re-pin once, to `88c12e7b…`. Every later change to `intake_loop.py`, `Dockerfile` or `entrypoint.sh` changes PCR0 and needs this again.
- Until it is done, every real run is VOID at the KMS step (AccessDenied).
- I did not find the exact `aws` commands of 17 Oct in the repo (only the result: "PCR0 condition changed b0d7bca6… -> 2b24ad8b…", `evidence/2026-10-17-r7-real-run/README.md`). The commands below are the standard KMS ones; adjust to your profile.

```sh
export AWS_REGION=eu-north-1
KEY=eb2d8fbd-4b64-48d4-a0ff-796d15056d28
cd <checkout of the merged branch>
NEW=$(tr -d '[:space:]' < intake-test/EXPECTED_PCR0.txt); echo "$NEW"
```

## 1. Pre-checks

1. The checkout is the merged commit and `git status` is clean.
2. Build the test room **twice** with the `REBUILD.md` recipe (AL2023 host container, Docker 25.0.16, nitro-cli 1.5.0, each build in its own empty dockerd; for the test room use `intake-test/build.sh`). Both PCR0 lines must be identical and equal to `$NEW`:
   `test "$(cat pcr0-build1.txt)" = "$NEW" && test "$(cat pcr0-build2.txt)" = "$NEW" && echo REPRODUCED`
   If they differ, stop. Do not pin a PCR0 you have not reproduced; pin what the enclave will report.
3. `python3 intake-test/test_local.py` passes.
4. Check nothing else uses the key policy right now (no run in progress).

## 2. Back up the live policy

```sh
aws kms get-key-policy --key-id $KEY --policy-name default --output json > policy-backup-$(date +%Y%m%dT%H%M%S).json
python3 intake-test/check_policy_pcr0.py policy-backup-*.json     # expect: mismatch, showing 2b24ad8b… twice (Allow and Deny)
```

Keep the backup file; it is the rollback. Extract the policy document (`Policy` is a JSON string) for editing:

```sh
python3 -c 'import json,sys; print(json.dumps(json.loads(json.load(open(sys.argv[1]))["Policy"]), indent=2))' policy-backup-*.json > policy-new.json
```

## 3. The edit: only the PCR0 value changes

The PCR0 appears **twice**, in the Allow statement and in the Deny statement. Change both, nothing else. Expected diff (`diff policy-old.json policy-new.json`, both pretty-printed):

```diff
   "Sid": "DecryptOnlyIfTestRoomPCR0Matches" ...
   "Condition": {"StringEqualsIgnoreCase": {
-    "kms:RecipientAttestation:PCR0": "2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0"}}
+    "kms:RecipientAttestation:PCR0": "<NEW>"}}
   "Sid": "NobodyDecryptsOutsideTheTestRoom" ...
   "Condition": {"StringNotEqualsIgnoreCase": {
-    "kms:RecipientAttestation:PCR0": "2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0"}}
+    "kms:RecipientAttestation:PCR0": "<NEW>"}}
```

Shape of the policy (as in `intake-test-key-policy.json`; compare the live backup against it): `RootAccountAdmin` (kms:*), `DecryptOnlyIfTestRoomPCR0Matches` (Allow kms:Decrypt for `role/aarloven-nitro-parent-role`), `NobodyDecryptsOutsideTheTestRoom` (Deny kms:Decrypt unless PCR0 matches), `NobodyReEncryptsOut` (Deny kms:ReEncryptFrom). The `diff` must show exactly those two changed lines. If it shows anything else (a statement added or removed, a different principal), stop and find out why before going on.

Do it mechanically rather than by hand:

```sh
OLD=$(python3 -c 'import json,re,sys; print(sorted(set(re.findall(r"[0-9a-f]{96}", json.load(open(sys.argv[1]))["Policy"])))[0])' policy-backup-*.json)
sed "s/$OLD/$NEW/g" policy-new.json > policy-new2.json && mv policy-new2.json policy-new.json
diff <(python3 -c 'import json,sys; print(json.dumps(json.loads(json.load(open(sys.argv[1]))["Policy"]), indent=2))' policy-backup-*.json) policy-new.json   # exactly 2 lines changed
python3 intake-test/check_policy_pcr0.py policy-new.json        # expect MATCH
```

## 4. Apply

```sh
aws kms put-key-policy --key-id $KEY --policy-name default --policy file://policy-new.json
aws kms get-key-policy --key-id $KEY --policy-name default --output json > policy-live-after.json
python3 intake-test/check_policy_pcr0.py policy-live-after.json   # expect MATCH
```

Ordering: do this **before** starting the real run, and only when the old image is not needed (the old image stops decrypting at this moment).

Commit the new policy to the repo afterwards (update `intake-test-key-policy.json` to the live one, so the CI job comparing it with `EXPECTED_PCR0.txt` passes).

## 5. Verify with real runs

Start the test host as on 17 Oct (m6i.xlarge, one start, stop right after).

1. **Real run, same dataset as 17 Oct (pusht-image-v1 payload):** expect PASS T1-T4, fingerprint `921056c1…f25c1`; `verify_receipt.py REPLY --root evidence/nitro-root-G1.pem --expect-pcr0 $NEW` passes.
2. **Debug mode (`--debug-mode`, PCR0 all zeros):** expect `VOID: kmstool decrypt failed`; with the kmstool-tail build (#8 and later) the detail now ends with the KMS AccessDenied text.
3. **Tampered payload (1 bit flipped):** expect VOID.

If (1) is VOID with AccessDenied, the PCR0 reported by the enclave is not the pinned one: compare the attestation PCR0 in the reply with `$NEW` before touching the policy again.

## 6. Rollback

```sh
python3 - <<'PY'
import json,glob
f=sorted(glob.glob("policy-backup-*.json"))[0]
open("policy-rollback.json","w").write(json.dumps(json.loads(json.load(open(f))["Policy"]), indent=2))
PY
aws kms put-key-policy --key-id $KEY --policy-name default --policy file://policy-rollback.json
aws kms get-key-policy --key-id $KEY --policy-name default --output json | python3 intake-test/check_policy_pcr0.py /dev/stdin --expected <(echo 2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0)
```

Rollback restores the `2b24ad8b…` image's ability to decrypt (PR #7 only). It does not make newer images work.

## 7. Cost

KMS API calls only: `GetKeyPolicy` and `PutKeyPolicy` are control-plane calls (a handful; no per-call charge to speak of; they appear in CloudTrail). The key itself costs the same USD 1/month as before. The verification runs cost one host start (m6i.xlarge for a few minutes) plus a few `Decrypt` calls (USD 0.03 per 10,000). No new resources are created.

## 8. What must NOT change

- **Room v6 production key and its policy.** This runbook touches key `eb2d8fbd-…` only. Check the key id in every command; `get-key-policy` output must show the `aarloven-intake-test-key` policy `Id`.
- **Room v6 PCR0 `3ea0a6f506be…`** (root `EXPECTED_PCR0.txt`, `releases.json`, the public log). The test PCR0 is never written there.
- The statement structure, principals, the `kms:ReEncryptFrom` deny and the root-admin statement of the test key.
- Room v6 is stopped only for test runs (as on 17 Oct) and must be restored; check `RESTORED_PCR0 3ea0a6f5…` and `/health` afterwards.
