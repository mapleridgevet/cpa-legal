import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("the resolve diagnostic reports child facts without printing child text or migrating", () => {
  const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "isolated-resolve-diagnostic.ps1");
  const text = fs.readFileSync(file, "utf8");
  assert.match(text, /Mandatory = \$true/);
  assert.match(text, /Refusing to use a folder outside TEMP/);
  assert.match(text, /Refusing to use a live CPA path/);
  assert.match(text, /-ResolveOnly/);
  assert.match(text, /DIAG\|exitCode/);
  assert.match(text, /DIAG\|stdoutTrimEquals/);
  assert.match(text, /DIAG\|hasMigrationStarted/);
  assert.equal(text.includes("8787"), false);
  assert.equal(text.includes("Export-Clixml"), false);
  assert.equal(text.includes("OWNER_PASSWORD"), false);
  assert.equal(text.includes("Write-Host $stdout"), false);
  assert.equal(text.includes("Write-Host $stderr"), false);
  assert.equal(text.includes("Write-Host $combined"), false);
  assert.ok(text.indexOf("-ResolveOnly") < text.indexOf("DIAG|exitCode"));
});
