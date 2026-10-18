#!/usr/bin/env python3
"""Tests for check_policy_pcr0.py (fixtures only, no AWS).   python3 intake-test/test_check_policy_pcr0.py"""
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest

import check_policy_pcr0 as c

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "get-key-policy-2b24ad8b.json")  # shape of `aws kms get-key-policy` output
OLD = "2b24ad8b14c2866b6efa0702dc57751c94248364fcf94ede408b2e7a2748dcf0f4aa3d6279209fa32261895eae7876e0"
NEW = "88c12e7b81dff6d82ffeba3eda1efe36b6756587670bac31e87c164784510ad8db5e65c521b0dee04db54cbc5cc0b62d"


def run(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = c.main(list(args))
    return rc, out.getvalue()


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def write(self, name, text):
        p = os.path.join(self.d.name, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_fixture_matches_its_own_pcr0(self):
        rc, out = run(FIX, "--expected", self.write("e", OLD + "\n"))
        self.assertEqual(rc, 0, out)
        self.assertIn("MATCH", out)

    def test_fixture_vs_new_pcr0_is_mismatch(self):
        rc, out = run(FIX, "--expected", self.write("e", NEW))
        self.assertEqual(rc, 1)
        self.assertEqual(out.count("MISMATCH"), 2)

    def test_repo_policy_file_is_old_b0d7(self):
        rc, _ = run(os.path.join(HERE, "intake-test-key-policy.json"))
        self.assertEqual(rc, 1)  # repo EXPECTED_PCR0.txt is newer than the proposed policy file

    def test_raw_policy_document_accepted_and_case_insensitive(self):
        pol = json.loads(json.load(open(FIX))["Policy"])
        pol["Statement"][1]["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"] = OLD.upper()
        rc, _ = run(self.write("p.json", json.dumps(pol)), "--expected", self.write("e", OLD))
        self.assertEqual(rc, 0)

    def test_one_condition_changed_is_mismatch(self):
        pol = json.loads(json.load(open(FIX))["Policy"])
        pol["Statement"][2]["Condition"]["StringNotEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"] = NEW
        rc, out = run(self.write("p.json", json.dumps(pol)), "--expected", self.write("e", OLD))
        self.assertEqual(rc, 1)
        self.assertEqual(out.count("MISMATCH"), 1)

    def test_no_pcr0_condition_fails(self):
        pol = {"Statement": [{"Sid": "x", "Effect": "Allow", "Action": "kms:*", "Resource": "*"}]}
        rc, _ = run(self.write("p.json", json.dumps(pol)), "--expected", self.write("e", OLD))
        self.assertEqual(rc, 1)

    def test_bad_inputs_exit_2(self):
        self.assertEqual(run(self.write("p.json", "{"), "--expected", self.write("e", OLD))[0], 2)
        self.assertEqual(run(FIX, "--expected", self.write("e", "abc"))[0], 2)
        self.assertEqual(run(os.path.join(self.d.name, "missing"))[0], 2)


if __name__ == "__main__":
    unittest.main()
