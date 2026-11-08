import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function misreadAsUtf16(bytes) {
  const units = [];
  for (let i = 0; i + 1 < bytes.length; i += 2) units.push(bytes[i] | (bytes[i + 1] << 8));
  return units;
}

function decodeChildBytes(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return new TextDecoder("utf-8").decode(bytes.subarray(3));
  }
  const utf16Le = bytes.length >= 2 && bytes.length % 2 === 0
    && [...bytes].every((byte, index) => index % 2 === 0 || byte === 0);
  if (utf16Le) return new TextDecoder("utf-16le").decode(bytes);
  return new TextDecoder("latin1").decode(bytes);
}

test("the Windows diagnostic units are ASCII C:\\Users bytes read as UTF-16", () => {
  const head = Buffer.from("C:\\Users", "ascii");
  const units = misreadAsUtf16(head);
  assert.deepEqual(units, [14915, 21852, 25971, 29554]);
  assert.equal(units[0].toString(16), "3a43");
  const payload = Buffer.concat([
    Buffer.from("C:\\Users"),
    Buffer.alloc(118 - "C:\\Users".length, 0x41),
    Buffer.from("\r\n", "ascii"),
  ]);
  assert.equal(payload.length, 120);
  const misread = misreadAsUtf16(payload);
  assert.equal(misread.length, 60);
  assert.equal(misread.includes(10), false);
  assert.equal(decodeChildBytes(payload).replace(/\r\n$/, ""), payload.subarray(0, 118).toString("ascii"));
});

test("single-byte child text matches exactly and UTF-16 child text still matches", () => {
  const text = "C:\\Users\\naesm\\AppData\\Local\\Temp\\cpa-v13-test\\fixture";
  const single = Buffer.concat([Buffer.from(text, "ascii"), Buffer.from("\r\n", "ascii")]);
  assert.equal(decodeChildBytes(single).trim(), text);
  const utf16 = Buffer.from(`\uFEFF${text}\r\n`, "utf16le");
  assert.equal(decodeChildBytes(utf16).trim(), text);
  const utf16NoBom = Buffer.from(`${text}\r\n`, "utf16le");
  assert.equal(decodeChildBytes(utf16NoBom).trim(), text);
  assert.notEqual(misreadAsUtf16(single).length, text.length);
});

test("the harness and diagnostic share the child decoder and do not print child text", () => {
  const decoder = fs.readFileSync(path.join(root, "decode-child-text.ps1"), "utf8");
  const harness = fs.readFileSync(path.join(root, "isolated-migration-test.ps1"), "utf8");
  const diagnostic = fs.readFileSync(path.join(root, "isolated-resolve-diagnostic.ps1"), "utf8");
  for (const marker of ["GetEncoding(28591)", "bytes[0] -eq 255", "bytes[$i] -ne 0"]) {
    assert.equal(decoder.includes(marker), true, marker);
  }
  for (const file of [harness, diagnostic]) {
    assert.match(file, /Set-ChildStreamEncoding/);
    assert.match(file, /ConvertFrom-ChildText/);
    assert.match(file, /decode-child-text\.ps1/);
    assert.equal(file.includes("StandardOutputEncoding = [System.Text.Encoding]::Unicode"), false);
    assert.equal(/throw "[^"]*\$(stdout|stderr|output|combined)/.test(file), false);
  }
  assert.match(harness, /\$actual\.Equals\(\$expected, \[StringComparison\]::OrdinalIgnoreCase\)/);
});
