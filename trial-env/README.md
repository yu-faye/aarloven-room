# Trial-environment receipt fingerprints

This folder holds one small file per export day, `YYYY-MM-DD.json`, written by the trial environment
(`export_daily.sh`) and committed here by a maintainer. The daily transparency-log run signs it in.
**This README is the only file here until the first real export is merged.**

## What a day file contains (and what it does not)

```json
{"date":"2026-10-24","format":"aarloven.trial-env-day.v1",
 "heads":[{"buyer":"<pseudonym>","receipt_sha256":"<64 hex>","seq":3}],
 "receipts":[{"buyer":"<pseudonym>","receipt_sha256":"<64 hex>","seq":3}],
 "trial_signing_key_sha256":"<64 hex>"}
```

- `receipts`: one line per receipt that was not yet published: SHA-256 of the signed receipt payload, and its
  position (`seq`) in that buyer's chain.
- `heads`: the latest receipt (`seq` + hash) of **every** buyer's chain on that day, so a deleted tail
  or a chain rolled back is visible even on a day without new receipts for that buyer.
- `buyer` is a pseudonym: the first 32 hex chars of
  `SHA-256("aarloven.trial-buyer.v1\n" + salt + "\n" + buyer_id)` with a random per-buyer salt. Only the
  buyer is given their salt, so nobody else can link a pseudonym to a buyer.
- **Not included:** buyer names, receipt contents, prompts, outputs, packages, timestamps of runs.
- **Visible to anyone:** on which day new receipts were exported, how many, how many buyers exist,
  and how many runs each pseudonym has made so far (`seq`).

The file must be canonical JSON (`json.dumps(sort_keys=True, separators=(',',':'))` + `"\n"`), its `date`
field must equal its file name, and its format must be `aarloven.trial-env-day.v1`. Anything else is
skipped with a warning (it never stops the daily log).

## How it gets into the signed log

Each daily run (`transparency-log/publisher.py`, default `--trial-env-dir trial-env`) adds every day file
here that is dated on or before the run date and that no earlier run has included, as ONE record each:
`record_type="trial_env_day"`, `timestamp=<file date>`, `content_hash=SHA-256(file bytes)`,
`metadata={"file":"trial-env/<name>"}`. On such days it also writes `public-log/leaves/<run date>.json`
with the day's leaf hashes in tree order and the list of trial files it included, so anyone can recompute
the signed Merkle root without the private `records/`. A file is included at most once; editing or
deleting it afterwards is detected by the buyer-side verifier.

So it does not matter exactly when GitHub starts the scheduled run: a file merged after a run is simply
included by the next one.

## Verifying

The trial environment's offline verifier does it in one step:

```
./verify_receipt.sh --chain r1.json r2.json r3.json \
    --public-log <clone of this repo> --buyer-salt <your salt> [--require-published]
```

It checks every log entry signature (key in `public-log/PUBLIC_KEY.txt`; compare it out of band), the
day-to-day hash chain, that each trial file is in the leaves of the day that signed it and that those
leaves give the signed root, then that each of your receipts is published under your pseudonym, that the
published chain head matches your last receipt, and that your published history never loses a receipt,
changes a hash, or moves its head backwards.

It does not use `MerkleTree.get_inclusion_proof` (that function has a known, parked issue for the last
node of an odd-sized level); it recomputes the full tree from the published leaves instead.
