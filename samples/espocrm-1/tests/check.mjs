// The harness for the clause tests. The same file runs in the sealed room (Node), on your machine (Node) and in
// your browser (a worker), so all three can be compared check by check.
// Each check reports ✓ or ✗ with its reason. Exit status 0 means every check passed (Yes), 10 means one failed
// (No); anything else, or no answer within the time limit, is "not finished". In a browser the checks are posted
// to the page instead of printed.
const inNode = typeof process === "object" && !!(process.versions && process.versions.node);
const results = [];

// The build under test is build/convert.mjs, as the room lays the case out; a browser page may name another URL.
export async function load() {
  const build = await import(globalThis.AARLOVEN_BUILD || new URL("../build/convert.mjs", import.meta.url).href);
  const dataUrl = new URL("../data/leads.json", import.meta.url);
  const text = inNode ? (await import("node:fs")).readFileSync(dataUrl, "utf8") : await (await fetch(dataUrl)).text();
  const data = JSON.parse(text);
  return { convert: build.convert, fresh: () => structuredClone(data) };
}

export async function check(name, fn) {
  try {
    await fn();
    results.push([name, true, ""]);
    if (inNode) console.log(`✓ ${name}`);
  } catch (err) {
    results.push([name, false, err.message]);
    if (inNode) console.log(`✗ ${name} — ${err.message}`);
  }
}

export function expect(ok, why) {
  if (!ok) throw new Error(why);
}

export function said(out) {
  return out.ok ? "it converted" : `it answered ${out.error}`;
}

export function finish() {
  const failed = results.filter((r) => !r[1]).length;
  const code = failed ? 10 : results.length ? 0 : 2;
  if (inNode) process.exitCode = code;
  else postMessage({ checks: results, code });
}
