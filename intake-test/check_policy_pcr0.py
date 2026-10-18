#!/usr/bin/env python3
"""Offline: does the PCR0 pinned in a saved KMS key policy equal EXPECTED_PCR0.txt?

    python3 intake-test/check_policy_pcr0.py POLICY.json [--expected intake-test/EXPECTED_PCR0.txt]

POLICY.json is either the policy document itself (like intake-test-key-policy.json) or the output of
`aws kms get-key-policy` ({"Policy": "<json string>", ...}). Reads files only; no AWS calls.
Exit 0 = every kms:RecipientAttestation:PCR0 condition equals the expected value (and there are at least two:
the Allow and the Deny), 1 = mismatch or malformed, 2 = usage / unreadable input.
"""
import argparse
import json
import os
import re
import sys

KEY = "kms:RecipientAttestation:PCR0"
HEX96 = re.compile(r"^[0-9a-f]{96}$")


def load_policy(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict) and isinstance(doc.get("Policy"), str):
        doc = json.loads(doc["Policy"])
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise ValueError("not a key policy (no Statement)")
    return doc


def pcr0_conditions(policy):
    """[(sid, effect, operator, value)] for every PCR0 condition in the policy."""
    out = []
    stmts = policy["Statement"]
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        for op, cond in (s.get("Condition") or {}).items():
            if KEY in cond:
                out.append((s.get("Sid", "?"), s.get("Effect", "?"), op, cond[KEY]))
    return out


def read_expected(path):
    with open(path, encoding="utf-8") as f:
        v = f.read().strip().lower()
    if not HEX96.match(v):
        raise ValueError("%s does not hold one 96-hex-digit PCR0" % path)
    return v


def check(policy, expected):
    """(ok, lines)"""
    conds = pcr0_conditions(policy)
    lines, ok = [], True
    if len(conds) < 2:
        ok = False
        lines.append("expected at least 2 PCR0 conditions (Allow + Deny), found %d" % len(conds))
    for sid, eff, op, val in conds:
        vals = [val] if isinstance(val, str) else list(val)
        match = len(vals) == 1 and vals[0].lower() == expected
        ok = ok and match
        lines.append("%s %-5s %-28s %-40s %s" % ("OK      " if match else "MISMATCH", eff, op, sid, ",".join(v[:8] + "..." for v in vals)))
    return ok, lines


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("policy")
    ap.add_argument("--expected", default=os.path.join(here, "EXPECTED_PCR0.txt"))
    a = ap.parse_args(argv)
    try:
        policy = load_policy(a.policy)
        expected = read_expected(a.expected)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    ok, lines = check(policy, expected)
    print("expected PCR0 %s..." % expected[:8])
    print("\n".join(lines))
    print("MATCH" if ok else "NO MATCH: the key policy does not pin the expected PCR0")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
