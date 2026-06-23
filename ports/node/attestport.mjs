#!/usr/bin/env node
// attestport (Node port) — air-gap supply-chain SBOM + provenance, mirroring the
// primary Python CLI's `sbom`, `attest`, and `verify` surface. Standard library
// only (node:crypto, node:fs) — no npm deps, no network.
//
//   node attestport.mjs sbom   <dir>
//   node attestport.mjs attest <artifact> [--key K]
//   node attestport.mjs verify <artifact> <attestation.json> [--key K]
//   node attestport.mjs --version
//
// The SBOM is byte-compatible in shape with the Python tool's CycloneDX output;
// the attestation uses the same canonical-JSON + HMAC-SHA256 scheme so the two
// implementations interoperate on a shared key.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, basename, resolve, relative, sep } from "node:path";

const TOOL_NAME = "attestport";
const TOOL_VERSION = "0.1.0";
const CYCLONEDX_VERSION = "1.5";
const INTOTO = "https://in-toto.io/Statement/v1";
const SLSA = "https://slsa.dev/provenance/v1";
const SKIP = new Set([".git", "node_modules", "__pycache__", ".venv", "venv",
  "dist", "build", ".pytest_cache", "target", ".idea", ".vscode"]);
const UNPINNED = /[<>~^*]|\bx\b|,| - |\|\|/;

// ---- canonical JSON (sorted keys, no whitespace) ----
function canonical(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

function purl(eco, name, version) {
  const safe = name.replace(/@/g, "%40");
  return version ? `pkg:${eco}/${safe}@${version}` : `pkg:${eco}/${safe}`;
}

// ---- lockfile parsers ----
function parseRequirements(text) {
  const out = [];
  for (let raw of text.split(/\r?\n/)) {
    let line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    line = line.split(";")[0].trim();
    const m = line.match(/^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    const spec = (m[3] || "").trim();
    const pinned = spec.startsWith("==") && !UNPINNED.test(spec.slice(2));
    const version = spec.startsWith("==") ? spec.slice(2).trim()
      : spec.replace(/^[=<>~!^ ]+/, "");
    out.push({ name, version, ecosystem: "pypi",
      purl: purl("pypi", name, pinned ? version : ""), pinned });
  }
  return out;
}

function parsePackageLock(text) {
  const data = JSON.parse(text);
  const out = [];
  if (data.packages && typeof data.packages === "object") {
    for (const [path, meta] of Object.entries(data.packages)) {
      if (!path || typeof meta !== "object") continue;
      const name = path.split("node_modules/").pop();
      const version = String(meta.version || "");
      out.push({ name, version, ecosystem: "npm",
        purl: purl("npm", name, version), pinned: !!version });
    }
    if (out.length) return out;
  }
  if (data.dependencies && typeof data.dependencies === "object") {
    for (const [name, meta] of Object.entries(data.dependencies)) {
      if (typeof meta !== "object") continue;
      const version = String(meta.version || "");
      out.push({ name, version, ecosystem: "npm",
        purl: purl("npm", name, version), pinned: !!version });
    }
  }
  return out;
}

const LOCKFILES = { "requirements.txt": parseRequirements,
  "package-lock.json": parsePackageLock };

function detectComponents(dir) {
  if (!existsSync(dir) || !statSync(dir).isDirectory())
    throw new Error(`not a directory: ${dir}`);
  let comps = [];
  for (const [fname, parser] of Object.entries(LOCKFILES)) {
    const p = join(dir, fname);
    if (existsSync(p)) comps = comps.concat(parser(readFileSync(p, "utf-8")));
  }
  const seen = new Set(), out = [];
  for (const c of comps) {
    const key = `${c.ecosystem}|${c.name}|${c.version}`;
    if (seen.has(key)) continue;
    seen.add(key); out.push(c);
  }
  out.sort((a, b) => (a.ecosystem + a.name.toLowerCase() + a.version)
    .localeCompare(b.ecosystem + b.name.toLowerCase() + b.version));
  return out;
}

function hashTree(dir) {
  const files = [];
  (function walk(d) {
    for (const name of readdirSync(d)) {
      if (SKIP.has(name)) continue;
      const full = join(d, name);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile())
        files.push({ path: relative(dir, full).split(sep).join("/"),
          sha256: sha256(readFileSync(full)) });
    }
  })(dir);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return files;
}

const merkle = (files) =>
  sha256(canonical(files.map(f => [f.path, f.sha256])));

function toCycloneDX(c) {
  const comp = { type: "library", name: c.name, version: c.version,
    "bom-ref": c.purl || `${c.ecosystem}:${c.name}@${c.version}` };
  if (c.purl) comp.purl = c.purl;
  comp.properties = [
    { name: "attestport:ecosystem", value: c.ecosystem },
    { name: "attestport:pinned", value: c.pinned ? "true" : "false" }];
  return comp;
}

function generateSbom(dir, includeFiles = true) {
  const components = detectComponents(dir);
  const files = includeFiles ? hashTree(dir) : [];
  const root = basename(resolve(dir)) || "project";
  const digest = merkle(files);
  const u = sha256(`${root}|${digest}`);
  const serial = `urn:uuid:${u.slice(0,8)}-${u.slice(8,12)}-${u.slice(12,16)}-${u.slice(16,20)}-${u.slice(20,32)}`;
  const bom = { bomFormat: "CycloneDX", specVersion: CYCLONEDX_VERSION,
    serialNumber: serial, version: 1,
    metadata: { tools: [{ vendor: "Cognis Digital", name: TOOL_NAME, version: TOOL_VERSION }],
      component: { type: "application", name: root, "bom-ref": `root:${root}` },
      properties: [
        { name: "attestport:file-count", value: String(files.length) },
        { name: "attestport:source-digest", value: digest }] },
    components: components.map(toCycloneDX) };
  if (includeFiles)
    bom.properties = [{ name: "attestport:files", value: JSON.stringify(files) }];
  return bom;
}

// ---- attest / verify ----
function resolveKey(key) {
  return Buffer.from(key || process.env.ATTESTPORT_KEY || "attestport-insecure-demo-key", "utf-8");
}
function subjectDigest(artifact) {
  return statSync(artifact).isDirectory()
    ? merkle(hashTree(artifact))
    : sha256(readFileSync(artifact));
}
function attest(artifact, key) {
  if (!existsSync(artifact)) throw new Error(`artifact not found: ${artifact}`);
  const statement = { _type: INTOTO, predicateType: SLSA,
    subject: [{ name: basename(resolve(artifact)),
      digest: { sha256: subjectDigest(artifact) } }],
    predicate: { buildType: "https://cognis.digital/attestport/buildtype/v1",
      builder: { id: "attestport:local" }, invocation: { configSource: {} }, materials: [] } };
  const payload = Buffer.from(canonical(statement), "utf-8");
  const sig = createHmac("sha256", resolveKey(key)).update(payload).digest("hex");
  return { ...statement, signature: { algorithm: "hmac-sha256", value: sig,
    payloadSha256: sha256(payload) } };
}
function verify(artifact, att, key) {
  const problems = [];
  const { signature, ...statement } = att;
  if (!signature || !signature.value) return { ok: false, problems: ["no signature"] };
  const payload = Buffer.from(canonical(statement), "utf-8");
  const expected = createHmac("sha256", resolveKey(key)).update(payload).digest("hex");
  const a = Buffer.from(expected), b = Buffer.from(String(signature.value));
  if (a.length !== b.length || !timingSafeEqual(a, b)) problems.push("signature mismatch");
  if (existsSync(artifact)) {
    const actual = subjectDigest(artifact);
    if (att.subject?.[0]?.digest?.sha256 !== actual) problems.push("subject digest mismatch");
  } else problems.push(`artifact not found: ${artifact}`);
  return { ok: problems.length === 0, problems };
}

// ---- CLI ----
function main(argv) {
  const [cmd, ...rest] = argv;
  const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
  const pos = rest.filter((a, i) => !a.startsWith("--") &&
    !(i > 0 && rest[i - 1].startsWith("--")));
  if (cmd === "--version" || cmd === "-v") { console.log(`${TOOL_NAME} ${TOOL_VERSION}`); return 0; }
  if (cmd === "sbom") { console.log(JSON.stringify(generateSbom(pos[0]), null, 2)); return 0; }
  if (cmd === "attest") { console.log(JSON.stringify(attest(pos[0], flag("--key")), null, 2)); return 0; }
  if (cmd === "verify") {
    const att = JSON.parse(readFileSync(pos[1], "utf-8"));
    const { ok, problems } = verify(pos[0], att, flag("--key"));
    if (ok) console.log("VERIFY: PASS");
    else { console.log("VERIFY: FAIL"); problems.forEach(p => console.log("  - " + p)); }
    return ok ? 0 : 1;
  }
  console.error(`usage: attestport {sbom|attest|verify|--version}`);
  return 2;
}

export { canonical, sha256, generateSbom, attest, verify, detectComponents, merkle };

if (import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith("attestport.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
