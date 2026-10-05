// node seal.mjs v1.4 [--data my-leads.json] [--key room-key.json] > sealed.json
// Seals a case to the sealed room's case key on your own machine, with code you can read, instead of the page's.
// The case is the published sample (samples/espocrm-1): its agreed points and tests, the chosen build of the vendor's
// code, and the sample's data or yours (--data). It is laid out exactly as the room reads it.
// - A fresh AES-256-GCM key encrypts the case.
// - That key is wrapped with RSA-OAEP (SHA-256) to the case key's public half: https://aarloven.com/room-key.json, or
//   a saved copy (--key). It is the public half of an AWS KMS key whose policy lets only the measured room decrypt.
// It prints the sealed package. On stderr it prints the two fingerprints to compare with the receipt:
//   H_input (the case, as the room should read it) and H_wrap (the wrapped key, as the room should receive it).
// Send the package with "Check your own sealed package" on aarloven.com, and give it the H_input printed here.
import { createCipheriv, createHash, createPublicKey, publicEncrypt, randomBytes, constants } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const caseDir = join(here, "samples", "espocrm-1");
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const build = args.find((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--"))) || "v1.4";
const AAD = "aarloven.min_closed_loop.v1";
const sha = (b) => createHash("sha256").update(b).digest("hex");
// canonical JSON, byte for byte the room's: sorted keys, no spaces, UTF-8 as is
const canon = (v) => (v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}");

const meta = JSON.parse(readFileSync(join(caseDir, "case.json"), "utf8"));
if (!meta.builds[build]) throw new Error(`no build ${build}; the case has ${Object.keys(meta.builds).join(", ")}`);
const files = Object.fromEntries(meta.files.map((p) => [p, readFileSync(join(caseDir, p), "utf8")]));
files["build/convert.mjs"] = readFileSync(join(caseDir, meta.builds[build].file), "utf8");
if (opt("--data")) {
  files["data/leads.json"] = readFileSync(opt("--data"), "utf8");
  JSON.parse(files["data/leads.json"]);  // the tests read it as JSON: refuse to seal anything else
}
const plain = Buffer.from(canon({ kind: meta.kind, clauses: meta.clauses, files }), "utf8");

const room = opt("--key") ? JSON.parse(readFileSync(opt("--key"), "utf8"))
  : await fetch("https://aarloven.com/room-key.json", { cache: "no-store" }).then((r) => { if (!r.ok) throw new Error("room-key.json: HTTP " + r.status); return r.json(); });
const key = randomBytes(32), iv = randomBytes(12);
const cipher = createCipheriv("aes-256-gcm", key, iv).setAAD(Buffer.from(AAD));
const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);  // the room reads ciphertext, then the 16-byte tag
const wrapped = publicEncrypt({ key: createPublicKey({ key: Buffer.from(room.spki_b64, "base64"), format: "der", type: "spki" }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, key);
key.fill(0);

process.stdout.write(JSON.stringify({
  seal_version: "aarloven.sealed_case.v2",
  sealed_in: "the buyer's own machine (seal.mjs)",
  wrap_mode: "kms",
  WrappedRoomKeyB64: wrapped.toString("base64"),
  Envelope: { alg: "AES-256-GCM", aad: AAD, iv_b64: iv.toString("base64"), ct_b64: ct.toString("base64"), wrap: { kms_key: room.kms_key, algorithm: "RSAES_OAEP_SHA_256" } },
}) + "\n");
console.error(`sealed build ${build} with ${opt("--data") ? "your data" : "the sample's data"} to case key ${room.kms_key}`);
console.error(`H_input  ${sha(plain)}   (the case: the room's receipt must name this)`);
console.error(`H_wrap   ${sha(wrapped)}   (the wrapped key: the receipt must name this too)`);
