#!/usr/bin/env python3
"""Step 2 of replay_optin.sh: replays sealed canon-2 intakes with opt-in policies (made by optin_make_intakes.py from the connector) through the intake TEST
room's handler, in-process, with a fake kmstool and a STUB NSM (so the receipts prove nothing about any enclave).

    replay_optin.py WORKDIR [--save evidence.json]

For every intake: the room's re-derived dataset fingerprint must equal the connector's, the receipt must surface opt_in / omitted_columns exactly as the
signed manifest has them, and (no sample dataset has pusht's frames+episodes) the verdict must be N/A, never PASS. Then tamper cases, each of which must be VOID:
the buyer "signs" a manifest consistent with data that breaks a policy, so only the room's own checks can catch it.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ARN = "arn:aws:kms:eu-north-1:000000000000:key/00000000-0000-0000-0000-000000000000"  # fake; the fake kmstool compares it as a string
SHA = "ab" * 32


def read(p):
    with open(p, "rb") as f:
        return f.read()


def cline(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("work")
    ap.add_argument("--save")
    a = ap.parse_args()
    tmp = tempfile.TemporaryDirectory()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_path = os.path.join(tmp.name, "kms_priv.pem")
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    import local_stubs
    local_stubs.install_fake_kmstool(tmp.name, KEY_ARN, priv_path)
    import buyer_seal_canon2
    import intake_loop
    import verify_receipt
    intake_loop.nsm_attest = local_stubs.fake_nsm_attest
    pub = priv.public_key()
    buyer = Ed25519PrivateKey.generate()
    buyer_pub = buyer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    buyer_fp = hashlib.sha256(buyer_pub).hexdigest()
    creds = {"AccessKeyId": "STUB", "SecretAccessKey": "STUB", "Token": "STUB"}
    problems, evidence = [], {"stub": "local replay: stub NSM, fake kmstool, NOT an enclave; no PCR0 is claimed", "runs": [], "tamper": []}

    def check(ok, what):
        print(("  ok   " if ok else "  FAIL ") + what)
        if not ok:
            problems.append(what)

    def sign(req, manifest=None, signer=buyer):
        if manifest is not None:
            req["manifest"] = manifest
        req.update(creds=creds, nonce=os.urandom(16).hex(), expected_buyer_fp=buyer_fp, kms_key=KEY_ARN, buyer_pubkey=buyer_pub.hex(),
                   buyer_sig=signer.sign(req["manifest"].encode()).hex())
        return req

    def run(req):
        reply = intake_loop.process_request(req)
        res = verify_receipt.verify_reply(reply, local_stubs.ROOT_PEM)
        assert res["stub"] and res["format"] == "aarloven-intake-test-receipt/2"
        return reply["receipt"], res

    def reseal(entry, mutate):
        """What a buyer who signs a manifest that matches (bad) data would send: open the table files with the buyer-side DEK, let `mutate(neutral, rows_by_table)`
        change the manifest and the rows (rows are dicts), then recompute digests, fingerprint, AAD and ciphertexts, and sign. Only the room's own checks can catch it."""
        folder, kek = entry["dir"], read(entry["kek"])
        man = json.loads(read(os.path.join(folder, "manifest.json")))
        canon, fp0 = man["neutral_manifest"]["canon"], man["dataset_fingerprint"]
        wrapped = read(os.path.join(folder, "sealed", "dek.wrapped"))
        dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], f"fourdb-seal-1-dek|{canon}|{fp0}".encode())
        rows = {}
        for t in man["neutral_manifest"]["tables"]:
            blob = read(os.path.join(folder, buyer_seal_canon2.sealed_relpath(t)))
            plain = AESGCM(dek).decrypt(blob[:12], blob[12:], f"fourdb-seal-1|{canon}|{fp0}|{t}".encode()).decode()
            rows[t] = [json.loads(l) for l in plain.split("\n")[:-1]]
        neutral = man["neutral_manifest"]
        mutate(neutral, rows)
        fp, tabs, files = None, {}, {}
        for t, rs in rows.items():
            lines = [cline(r) for r in rs]
            neutral["tables"][t]["rows"] = len(lines)
            neutral["tables"][t]["sha256"] = hashlib.sha256(b"".join(l.encode() + b"\n" for l in lines)).hexdigest()
            files[t] = "".join(l + "\n" for l in lines).encode()
        fp = hashlib.sha256(json.dumps(neutral, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        man["dataset_fingerprint"] = fp
        req = {"format": "fourdb-canon-2", "tables": {}}
        for t, plain in files.items():
            n = os.urandom(12)
            blob = n + AESGCM(dek).encrypt(n, plain, f"fourdb-seal-1|{canon}|{fp}|{t}".encode())
            req["tables"][t] = {"sealed_b64": base64.b64encode(blob).decode()}
            tabs[t] = {"sealed_sha256": hashlib.sha256(blob).hexdigest()}
        man["sealed"]["tables"] = tabs
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        req["wrapped_dek_b64"] = base64.b64encode(pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()
        return sign(req, json.dumps(man, sort_keys=True, indent=1))

    def tamper(entry, name, mutate, needle):
        r, _ = run(reseal(entry, mutate))
        d = r["tests"][0]["detail"]
        ok = r["verdict"] == "VOID" and r["dataset_fingerprint"] == "" and needle in d
        check(ok, f"{entry['target']} {entry['label']}: {name}: VOID ({d[:110]})")
        evidence["tamper"].append({"run": f"{entry['target']}/{entry['label']}", "case": name, "verdict": r["verdict"], "reason": d[:200], "as_expected": ok})

    index = json.loads(read(os.path.join(a.work, "index.json")))
    by = {(e["target"], e["label"]): e for e in index}
    for e in index:
        folder = e["dir"]
        man = json.loads(read(os.path.join(folder, "manifest.json")))
        neutral = man["neutral_manifest"]
        print(f"\n== {e['target']} {e['label']} ({e['server_version']}): {len(e['tables'])}/{e['tables_in_database']} tables, flags {' '.join(e['flags'])}")
        if e["left_out"]:
            print("   left out:", {k: v[:70] for k, v in e["left_out"].items()})
        req = sign(buyer_seal_canon2.bridge(folder, read(e["kek"]), pub))
        r, res = run(req)
        check(r["dataset_fingerprint"] == e["connector_fingerprint"] == man["dataset_fingerprint"], f"room fingerprint == connector fingerprint ({r['dataset_fingerprint'][:16]}...)")
        check(r["verdict"] == "N/A" and [t["id"] for t in r["tests"]] == ["TX"], "verdict N/A with the single test TX (no pusht tables), not PASS")
        check(sorted(r["tables"]) == sorted(neutral["tables"]) == sorted(e["tables"]), "receipt lists exactly the table names of the manifest (spaces and all)")
        check(all(r["tables"][t]["sha256"] == m["sha256"] and r["tables"][t]["rows"] == m["rows"] for t, m in neutral["tables"].items()), "per-table digests and row counts re-derived == connector's")
        check(r["opt_in"] == neutral.get("opt_in", {}) and r["omitted_columns"] == {t: m["omitted_columns"] for t, m in neutral["tables"].items() if "omitted_columns" in m},
              "receipt opt_in / omitted_columns == the signed manifest's")
        check(r["manifest_sha256"] == hashlib.sha256(read(os.path.join(folder, "manifest.json"))).hexdigest(), "manifest_sha256 is the hash of the signed manifest bytes")
        evidence["runs"].append({
            "target": e["target"], "label": e["label"], "server_version": e["server_version"], "database": e["database"], "connector_flags": e["flags"],
            "tables_in_receipt": len(e["tables"]), "tables_in_database": e["tables_in_database"], "left_out": e["left_out"],
            "connector_fingerprint": e["connector_fingerprint"], "room_fingerprint": r["dataset_fingerprint"], "fingerprints_equal": r["dataset_fingerprint"] == e["connector_fingerprint"],
            "room_verdict": r["verdict"], "receipt_opt_in": r["opt_in"], "receipt_omitted_columns": {t: [c["name"] for c in cs] for t, cs in r["omitted_columns"].items()},
            "logical_types_seen": sorted({lt for m in neutral["tables"].values() for lt in m["columns"].values()})})
    print("\n== expectations on the intakes themselves")
    sakila_a = [e for e in index if e["label"] == "sakila-A-geometry"]
    for e in sakila_a:
        check(len(e["tables"]) == 16 and not e["left_out"], f"{e['target']} sakila-A: 16/16 tables with the five type policies incl. geometry")
        man = json.loads(read(os.path.join(e["dir"], "manifest.json")))["neutral_manifest"]
        check("geometry:wkb-sha256" in man["tables"]["address"]["columns"].values() and "geometry" in man["opt_in"] and "omit_unsupported" not in man["opt_in"], f"{e['target']} sakila-A: address.location read as geometry, nothing omitted")
    for e in [e for e in index if e["label"] == "northwind-sha256"]:
        check(len(e["tables"]) == 13 and not e["left_out"] and "Order Details" in e["tables"], f"{e['target']} northwind-sha256: 13/13 tables including \"Order Details\" (was 12/13)")
    for e in [e for e in index if e["label"] == "northwind-hex"]:
        check(len(e["tables"]) == 11 and "Order Details" in e["tables"] and sorted(e["left_out"]) == ["Categories", "Employees"], f"{e['target']} northwind-hex: 11/13, \"Order Details\" in, only the two image tables left out (was 10/13)")
    for e in [e for e in index if e["label"] == "sakila-B-omit"]:
        man = json.loads(read(os.path.join(e["dir"], "manifest.json")))["neutral_manifest"]
        om = man["tables"]["address"].get("omitted_columns", [])
        check(len(e["tables"]) == 16 and [c["name"] for c in om] == ["location"] and "geometry" not in man["opt_in"], f"{e['target']} sakila-B: 16/16 tables, address.location omitted and listed, no geometry policy")
    if len(sakila_a) == 2:
        same = sakila_a[0]["connector_fingerprint"] == sakila_a[1]["connector_fingerprint"]
        check(same, "sakila-A fingerprint identical on MySQL 5.7 and 8.4")
        evidence["sakila_A_57_equals_84"] = same
    for e in index:
        if e["target"] == "ms22":
            man = json.loads(read(os.path.join(e["dir"], "manifest.json")))["neutral_manifest"]
            want = e["flags"][1]
            kinds = {lt for m in man["tables"].values() for lt in m["columns"].values() if lt.startswith("binary:")}
            check(kinds <= {"binary:" + want} and man["opt_in"] == {"binary_as": want}, f"{e['label']}: binary columns are binary:{want}, opt_in is exactly binary_as={want}")

    print("\n== tamper cases (each must be VOID with no dataset_fingerprint)")
    big = by.get(("my84", "sakila-A-geometry")) or sakila_a[0]
    p = big["dir"]
    nm = json.loads(read(os.path.join(p, "manifest.json")))["neutral_manifest"]
    ts_tbl = next(t for t, m in nm["tables"].items() if m.get("timestamp_columns") and any(d["source_tz"] == "UTC" for d in m["timestamp_columns"].values()))
    ts_col = next(c for c, d in nm["tables"][ts_tbl]["timestamp_columns"].items() if d["source_tz"] == "UTC")
    # 1. opt_in value edited and re-signed: the fingerprint no longer matches (manifest only), or matches but the AAD no longer opens the tables
    def zone(m):
        m["neutral_manifest"]["opt_in"]["timestamp_tz"]["declared_zone"] = "Europe/Copenhagen"
    q = sign(buyer_seal_canon2.bridge(p, read(big["kek"]), pub))
    man = json.loads(q["manifest"])
    zone(man)
    r, _ = run(sign(q, json.dumps(man, sort_keys=True, indent=1)))
    check(r["verdict"] == "VOID" and "not the SHA-256 of its neutral manifest" in r["tests"][0]["detail"], "opt_in.timestamp_tz.declared_zone edited and re-signed: VOID (fingerprint mismatch)")
    evidence["tamper"].append({"run": "my84/sakila-A-geometry", "case": "opt_in declared_zone edited, re-signed", "verdict": r["verdict"], "reason": r["tests"][0]["detail"][:200], "as_expected": r["verdict"] == "VOID"})
    man = json.loads(buyer_seal_canon2.bridge(p, read(big["kek"]), pub)["manifest"])
    zone(man)
    man["dataset_fingerprint"] = hashlib.sha256(json.dumps(man["neutral_manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    q = buyer_seal_canon2.bridge(p, read(big["kek"]), pub)
    r, _ = run(sign(q, json.dumps(man, sort_keys=True, indent=1)))
    check(r["verdict"] == "VOID" and "does not decrypt" in r["tests"][0]["detail"], "declared_zone edited, fingerprint recomputed, re-signed: VOID (AAD binds the old fingerprint)")
    evidence["tamper"].append({"run": "my84/sakila-A-geometry", "case": "declared_zone edited, fingerprint recomputed, re-signed", "verdict": r["verdict"], "reason": r["tests"][0]["detail"][:200], "as_expected": r["verdict"] == "VOID"})
    # 2. value-level violations in a manifest the buyer signed consistently
    def set_first(table, col, value, only_if=lambda v: v is not None):
        def f(n, rows):
            for row in rows[table]:
                if only_if(row[col]):
                    row[col] = value
                    return
            raise SystemExit(f"no row in {table}.{col} to edit")
        return f
    tamper(big, "enum label not declared (film.rating = 'NC-18')", set_first("film", "rating", "NC-18"), "enum value is not one of the declared labels")
    tamper(big, "set members not sorted (film.special_features)", set_first("film", "special_features", "Trailers,Commentaries", lambda v: v == "Commentaries,Trailers"), "not unique and sorted")
    tamper(big, "set member not declared", set_first("film", "special_features", "Karaoke", lambda v: v), "set member is not one of the declared labels")
    tamper(big, "malformed geometry (address.location without len)", set_first("address", "location", {"srid": 0, "sha256": SHA}), "geometry value is not")
    tamper(big, "malformed geometry (sha256 63 chars)", set_first("address", "location", {"srid": 0, "len": 21, "sha256": SHA[:63]}), "geometry value is not")
    tamper(big, "binary sha256 wrong length (staff.picture)", set_first("staff", "picture", {"len": 5, "sha256": SHA[:62]}), "binary:sha256 value")
    tamper(big, "year out of range (film.release_year = 1800)", set_first("film", "release_year", 1800), "year is not an integer in 1901..2155")
    tamper(big, "timestamp with an offset (%s.%s)" % (ts_tbl, ts_col), set_first(ts_tbl, ts_col, "2006-02-15T04:34:33+01:00"), "timestamp is not canonical UTC")
    tamper(big, "unknown logical type (film.title -> text:utf8)", lambda n, rows: n["tables"]["film"]["columns"].update(title="text:utf8"), "unknown logical type 'text:utf8'")
    tamper(big, "unknown opt_in key", lambda n, rows: n["opt_in"].update(json_as="text"), "unknown opt_in key(s) ['json_as']")
    tamper(big, "geometry opt_in dropped but geometry column kept", lambda n, rows: n["opt_in"].pop("geometry"), "opt_in.geometry.columns must list exactly")
    om = by.get(("my84", "sakila-B-omit"))
    if om:
        tamper(om, "omitted column (address.location) present in the rows", lambda n, rows: [r.update(location={"srid": 0, "len": 21, "sha256": SHA}) for r in rows["address"]], "column(s) ['location'] not in the manifest")
        tamper(om, "omission flag dropped while columns are listed omitted", lambda n, rows: n["opt_in"].pop("omit_unsupported"), "omit_unsupported is not set")
    ms = by.get(("ms22", "northwind-sha256"))
    if ms:
        pic = next((t, c) for t, m in json.loads(read(os.path.join(ms["dir"], "manifest.json")))["neutral_manifest"]["tables"].items() for c, lt in m["columns"].items() if lt == "binary:sha256")
        tamper(ms, "binary sha256 uppercase (%s.%s)" % pic, set_first(pic[0], pic[1], {"len": 3, "sha256": SHA.upper()}), "binary:sha256 value")
        def rename_table(n, rows):
            n["tables"]["Order\tDetails"] = n["tables"].pop("Order Details")
            rows["Order\tDetails"] = rows.pop("Order Details")

        def rename_column(n, rows):
            n["tables"]["Order Details"]["columns"]["Quantity\u0301"] = n["tables"]["Order Details"]["columns"].pop("Quantity")
            for row in rows["Order Details"]:
                row["Quantity\u0301"] = row.pop("Quantity")

        if "Order Details" in json.loads(read(os.path.join(ms["dir"], "manifest.json")))["neutral_manifest"]["tables"]:
            tamper(ms, "table \"Order Details\" renamed with a TAB (control character)", rename_table, "table name")
            tamper(ms, "column Quantity renamed to a non-NFC spelling", rename_column, "column name")
        tamper(ms, "binary:hex declared under opt_in.binary_as=sha256", lambda n, rows: n["tables"][pic[0]]["columns"].update({pic[1]: "binary:hex"}), "opt_in.binary_as")

    if a.save:
        with open(a.save, "w") as f:
            json.dump(evidence, f, indent=1, sort_keys=True)
        print("\nsaved", a.save)
    print("\nRESULT:", "ALL AS EXPECTED" if not problems else f"{len(problems)} UNEXPECTED: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
