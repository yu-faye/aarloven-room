# Evidence

`2026-10-16-receipt-honest-FAIL.json` is the first real receipt from the intake test room. It was produced by the enclave whose PCR0 begins b0d7bca6…, using the test KMS key eb2d8fbd…. The signature and the attestation chain both verify offline against the AWS Nitro root certificate.

The verdict is **FAIL**, and the receipt is kept as it is.

- T1 to T3 pass.
- T4 fails with a success rate of 0/206.

## Why T4 fails

T4 reads the correct field: the export's `success` column is the raw `next.success`. In lerobot/pusht that field is False on all 25,650 frames.

`next.reward`, which is the coverage of the block over the target, reaches at most 0.9489. The upstream success threshold is 0.95. Recomputing success from reward therefore also gives 0/206.

This is a true negative, not a bug. Changing T4 to make it pass would loosen the test.

## 2026-10-17-optin-replay-results.json

Output of `../replay_optin.sh`: eight connector-made canon-2 intakes of Sakila / Northwind / pubs with the opt-in policies, replayed through the handler with a fake kmstool and a STUB NSM (not an enclave, no PCR0). Fingerprints, counts and tamper outcomes only; no data rows. pubs fingerprints change on every run (`titles.pubdate` is the load time).
