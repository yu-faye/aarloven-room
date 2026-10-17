#!/usr/bin/env python3
"""Step 1 of replay_optin.sh: sealed canon-2 intakes of the public sample dumps, made by the fourdb connector, with the opt-in policies (CANON.md s10).

    optin_make_intakes.py WORKDIR            (needs the fourdb connector's Python: pymysql, pymssql; reads the li4db checkout, writes only WORKDIR)

Sakila -> MySQL 5.7 and 8.4 (A: all five type policies incl. geometry; B: --omit-unsupported instead of geometry), Northwind and pubs -> SQL Server 2022
(--binary-as sha256 and --binary-as hex). Docker containers r6-optin-* on ports 58610..58612, one at a time, always removed. The dumps come from the cache dir
(never downloaded here). A table the connector refuses under the given flags is left out and listed (e.g. hex on a 20 KB image). Names with spaces such as
Northwind's `Order Details` are kept (fourdb CANON.md s11: the connector needs FOURDB_DIR to be a checkout that has it); only a name the identifier rule refuses is left out.
Env: OPTIN_PREFIX (container name prefix, default r6-optin-), OPTIN_PORT_BASE (default 58610; the three targets use base, base+1, base+2; 0 = a random free port each),
OPTIN_ONLY (comma list of targets my57,my84,ms22; default all). Writes WORKDIR/index.json.
"""
import json
import os
import socket
import subprocess
import sys

FOURDB = os.environ.get("FOURDB_DIR", "/workspace/li4db/tools/legacy-intake/fourdb")
CACHE = os.environ.get("LEGACY_DUMPS_CACHE", "/workspace/cache/legacy-dumps")
sys.dont_write_bytecode = True
sys.path.insert(0, FOURDB)
sys.path.insert(0, os.path.join(FOURDB, "public_dumps"))
import awsguard  # noqa: E402
awsguard.install()
import connector  # noqa: E402
import fetch_dumps  # noqa: E402
import run_public as rp  # noqa: E402  (its loaders: start, load, admin, catalog, inventory)

PREFIX = os.environ.get("OPTIN_PREFIX", "r6-optin-")
PORT_BASE = int(os.environ.get("OPTIN_PORT_BASE", "58610"))


def _port(i):
    if PORT_BASE:
        return PORT_BASE + i
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


TARGETS = {  # name: (engine, port, image, container, dump key, database) - run_public's shape, but our own names and ports (published on 127.0.0.1 by run_public.start)
    "my57": ("mysql", _port(0), "mysql:5.7", PREFIX + "my57", "sakila", "sakila"),
    "my84": ("mysql", _port(1), "mysql:8.4", PREFIX + "my84", "sakila", "sakila"),
    "ms22": ("mssql", _port(2), "mcr.microsoft.com/mssql/server:2022-latest", PREFIX + "ms22", "northwind+pubs", None),
}
rp.TARGETS.clear()
rp.TARGETS.update(TARGETS)
MY_TYPES = ["--timestamp-tz", "UTC", "--enum-set-as", "text", "--binary-as", "sha256", "--year-as", "int"]
GEO = ["--geometry-as", "wkb-sha256", "--geometry-storage", "mysql-srid-wkb"]
RUNS = {  # target -> [(label, database, flags)]
    "my57": [("sakila-A-geometry", "sakila", MY_TYPES + GEO), ("sakila-B-omit", "sakila", MY_TYPES + ["--omit-unsupported"])],
    "my84": [("sakila-A-geometry", "sakila", MY_TYPES + GEO), ("sakila-B-omit", "sakila", MY_TYPES + ["--omit-unsupported"])],
    "ms22": [("northwind-sha256", "northwind", ["--binary-as", "sha256"]), ("northwind-hex", "northwind", ["--binary-as", "hex"]),
             ("pubs-sha256", "pubs", ["--binary-as", "sha256"]), ("pubs-hex", "pubs", ["--binary-as", "hex"])],
}


def flags_to_optin(flags):
    o, it = {}, iter(flags)
    for f in it:
        if f == "--omit-unsupported":
            o["omit_unsupported"] = True
        else:
            o[f[2:].replace("-", "_")] = next(it)
    return o


def cleanup():
    names = [n for n in rp.sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split() if n.startswith(PREFIX)]
    if names:
        rp.sh("docker", "rm", "-f", *names)  # only our own containers


def table_plan(t, db, flags):
    """-> ({table: pk}, {table: why left out}) : the tables of `db` that the connector accepts under `flags` (in-process dry run, one refusal at a time)."""
    engine = TARGETS[t][0]
    tables, out = {}, {}
    for name, pkcols in rp.catalog(t, db)["tables"].items():
        problem = connector.ident_problem(name)
        if problem:
            out[name] = "%s (%s)" % problem
            continue
        cols, _ = rp.inventory(t, db, name)
        lt = {n: l for n, l, _ in cols}
        tables[name] = pkcols[0] if len(pkcols) == 1 and lt.get(pkcols[0]) == "int" else None
    optin = flags_to_optin(flags)
    while tables:
        try:
            connector.intake(engine, rp.dsn(t, db), tables=dict(tables), legacy=True, optin=optin)
            return tables, out
        except connector.Refusal as r:
            name = r.info.get("table")
            if name not in tables:
                raise
            out[name] = "%s (%s)" % (r.info["code"], str(r.info.get("detail", ""))[:120])
            del tables[name]
    return tables, out


def main():
    work = sys.argv[1]
    os.makedirs(work, exist_ok=True)
    need = ["instnwnd.sql", "instpubs.sql", "sakila/sakila-schema.sql", "sakila/sakila-data.sql"]
    missing = [n for n in need if not os.path.exists(os.path.join(CACHE, n))]
    if missing:
        raise SystemExit("dump cache incomplete (%s); not downloading here: run public_dumps/fetch_dumps.py" % missing)
    dumps = fetch_dumps.fetch(CACHE)  # every file exists, so this only checks the pinned SHA-256s
    index, mark = [], {"server": None}
    cleanup()
    try:
        for t, runs in RUNS.items():
            if os.environ.get("OPTIN_ONLY") and t not in os.environ["OPTIN_ONLY"].split(","):
                continue
            engine = TARGETS[t][0]
            rp.start(t)
            rp.load(t, dumps)
            c = rp.admin(t)
            ver = rp.q1(c, "SELECT VERSION()" if engine == "mysql" else "SELECT CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(40))")[0][0]
            c.close()
            for label, db, flags in runs:
                tables, left_out = table_plan(t, db, flags)
                out = os.path.join(work, f"{t}-{label}")
                kek = os.path.join(work, f"{t}-{label}.kek")
                spec = json.dumps([{"name": n, "pk": pk} for n, pk in tables.items()])
                p = subprocess.run([sys.executable, os.path.join(FOURDB, "connector.py"), "--engine", engine, "--dsn", rp.dsn(t, db), "--out", out, "--mode", "sealed",
                                    "--kek-file", kek, "--tables-json", spec, "--legacy", *flags], capture_output=True, text=True)
                if p.returncode:
                    raise SystemExit(f"{t} {label}: connector failed: {p.stderr[-400:]}")
                info = json.loads(p.stdout)
                entry = {"target": t, "label": label, "engine": engine, "server_version": ver, "database": db, "flags": flags, "dir": out, "kek": kek,
                         "connector_fingerprint": info["dataset_fingerprint"], "tables": sorted(tables), "tables_in_database": len(tables) + len(left_out), "left_out": left_out}
                index.append(entry)
                print(f"{t:5s} {label:20s} {len(tables):2d}/{entry['tables_in_database']:2d} tables  {info['dataset_fingerprint'][:16]}  left out: {sorted(left_out)}", flush=True)
            cleanup()
    finally:
        cleanup()
    with open(os.path.join(work, "index.json"), "w") as f:
        json.dump(index, f, indent=1)


if __name__ == "__main__":
    main()
