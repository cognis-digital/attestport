// Smoke test for the Node port. Run: node --test ports/node/attestport.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonical, sha256, generateSbom, attest, verify, detectComponents, merkle }
  from "./attestport.mjs";

function mkproj(files) {
  const dir = mkdtempSync(join(tmpdir(), "ap-"));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

test("canonical is order-independent", () => {
  assert.equal(canonical({ b: 1, a: 2 }), canonical({ a: 2, b: 1 }));
});

test("sha256 empty vector", () => {
  assert.equal(sha256(Buffer.from("")),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("detect pinned vs unpinned", () => {
  const dir = mkproj({ "requirements.txt": "a==1.0\nb>=2\n" });
  const by = Object.fromEntries(detectComponents(dir).map(c => [c.name, c]));
  assert.equal(by.a.pinned, true);
  assert.equal(by.b.pinned, false);
  rmSync(dir, { recursive: true, force: true });
});

test("sbom is CycloneDX", () => {
  const dir = mkproj({ "requirements.txt": "requests==2.31.0\n" });
  const bom = generateSbom(dir);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.ok(bom.components.some(c => c.name === "requests"));
  assert.ok(bom.serialNumber.startsWith("urn:uuid:"));
  rmSync(dir, { recursive: true, force: true });
});

test("attest/verify roundtrip passes", () => {
  const dir = mkproj({ "requirements.txt": "a==1.0\n" });
  const att = attest(dir);
  assert.equal(verify(dir, att).ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test("tampered signature fails", () => {
  const dir = mkproj({ "requirements.txt": "a==1.0\n" });
  const att = attest(dir);
  att.signature.value = "0".repeat(64);
  assert.equal(verify(dir, att).ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test("wrong key fails", () => {
  const dir = mkproj({ "requirements.txt": "a==1.0\n" });
  const att = attest(dir, "key-A");
  assert.equal(verify(dir, att, "key-B").ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test("merkle stable", () => {
  const files = [{ path: "a", sha256: "1" }, { path: "b", sha256: "2" }];
  assert.equal(merkle(files), merkle([...files]));
});
