# Draft workflow for the intake test room

`intake-test-repro-check.yml` is a GitHub Actions workflow, kept here because the box's GitHub token has no `workflow` scope and GitHub refuses pushes that create files under `.github/workflows/`.

To enable it (Yufei, from a machine with a normal login), after review:

    git checkout room-intake-canon2
    git mv intake-test/ci-draft/intake-test-repro-check.yml .github/workflows/intake-test-repro-check.yml
    git commit -m "enable intake-test repro-check" && git push

What it checks: `test_local.py` on Python 3.9; two builds of the test room with the REBUILD.md recipe give the same PCR0, equal to `intake-test/EXPECTED_PCR0.txt`; the PCR0 pinned in `intake-test-key-policy.json` equals that file. The last job fails on purpose until the key policy is updated (needs Yufei's OK; the real KMS key is an AWS change).

Undo: delete the workflow file.
