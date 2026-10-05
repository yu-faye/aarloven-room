// node rerun.mjs v1.3 [receipt.json]
// Runs the published sample case the way the sealed room does, on your machine. It lays the case out
// (build/, data/, tests/), runs each point's test with Node, and prints:
// - each check;
// - the result per point;
// - the fingerprints the room puts in its receipt.
// Given a receipt saved from aarloven.com ("Save the receipt"), it compares them, line by line.
// The case is samples/espocrm-1, the same files as https://aarloven.com/samples/espocrm-1/.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const caseDir = join(here, "samples", "espocrm-1");
const build = process.argv[2] || "v1.4";
const sha = (s) => createHash("sha256").update(s).digest("hex");
// canonical JSON, byte for byte the room's: sorted keys, no spaces, UTF-8 as is
const canon = (v) => (v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}");

const meta = JSON.parse(readFileSync(join(caseDir, "case.json"), "utf8"));
if (!meta.builds[build]) throw new Error(`no build ${build}; the case has ${Object.keys(meta.builds).join(", ")}`);
const files = Object.fromEntries(meta.files.map((p) => [p, readFileSync(join(caseDir, p), "utf8")]));
files["build/convert.mjs"] = readFileSync(join(caseDir, meta.builds[build].file), "utf8");
const group = (g) => sha(canon(Object.entries(files).filter(([p]) => p.startsWith(g + "/")).map(([p, c]) => [p, sha(c)]).sort((a, b) => (a[0] < b[0] ? -1 : 1))));
const prints = {
  H_input: sha(canon({ kind: meta.kind, clauses: meta.clauses, files })),
  H_build: group("build"), H_data: group("data"), H_tests: group("tests"), H_clauses: sha(canon(meta.clauses)),
};

const work = mkdtempSync(join(tmpdir(), "aarloven-case-"));
const clauses = [];
try {
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(work, p)), { recursive: true }); writeFileSync(join(work, p), c); }
  for (const cl of meta.clauses) {
    const run = spawnSync(process.execPath, ["--no-warnings", cl.test], { cwd: work, encoding: "utf8", timeout: 10000 });
    const checks = (run.stdout || "").split("\n").filter((l) => /^[✓✗] /.test(l)).map((l) => {
      const [name, why = ""] = l.slice(2).split(" — ");
      return [name, l[0] === "✓", l[0] === "✓" ? "" : why];
    });
    const result = run.status === 0 && checks.length && checks.every((c) => c[1]) ? "Yes" : run.status === 10 ? "No" : "not finished";
    clauses.push({ id: cl.id, result, checks });
    console.log(`${cl.id} ${result.padEnd(12)} ${cl.clause}`);
    for (const [name, ok, why] of checks) console.log(`   ${ok ? "✓" : "✗"} ${name}${ok ? "" : " — " + why}`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
const verdict = clauses.every((c) => c.result === "Yes") ? "pass" : "fail";
console.log(`\nverdict ${verdict.toUpperCase()} · build ${build} · ${process.version}`);
for (const [k, v] of Object.entries(prints)) console.log(`${k.padEnd(10)} ${v}`);

const saved = process.argv[3];
if (saved) {
  const file = JSON.parse(readFileSync(saved, "utf8"));
  const rc = file.receipt || (file.room_reply && file.room_reply.receipt) || file;
  const same = [["verdict", verdict === rc.verdict], ...Object.keys(prints).map((k) => [k, prints[k] === rc[k]]),
    ["checks", JSON.stringify(clauses.map((c) => [c.id, c.result, c.checks.map((x) => [x[0], x[1]])])) === JSON.stringify((rc.clauses || []).map((c) => [c.id, c.result, c.checks.map((x) => [x[0], x[1]])]))]];
  console.log(`\nagainst ${saved}:`);
  for (const [k, ok] of same) console.log(`   ${ok ? "same     " : "DIFFERENT"} ${k}`);
  process.exitCode = same.every(([, ok]) => ok) ? 0 : 1;
}
