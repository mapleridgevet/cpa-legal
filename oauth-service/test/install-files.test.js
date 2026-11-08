import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { copyRelease, missingReleaseFiles, releaseRootFromModuleUrl } from "../src/install-files.js";

const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function writeRelease(dir, extra = {}) {
  for (const rel of [
    "package.json",
    "package-lock.json",
    "host-settings.json",
    "install.ps1",
    "start-oauth-service.ps1",
    "migrate-secrets.ps1",
    "README.md",
    "src/protect-path.js",
    "src/install-files.js",
    "src/acl.js",
    "src/preflight.js",
    "src/index.js",
    "src/app.js",
    "src/login-throttle.js",
    "src/secret-policy.js",
    "src/check-intuit-credentials.js",
    "src/password-hash.js",
    "src/token-crypto.js",
    "src/owner-password-cli.js",
    "src/migrate-token-file.js",
    "src/token-check-cli.js",
    "test/state-file.test.js",
  ]) {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, extra[rel] ?? `new ${rel}`);
  }
}

test("the source tree and installer contain the helper before it is invoked", () => {
  assert.deepEqual(missingReleaseFiles(releaseRoot), []);
  const installer = fs.readFileSync(path.join(releaseRoot, "install.ps1"), "utf8");
  const copyAt = installer.indexOf("src\\install-files.js");
  const placedAt = installer.indexOf("Install copy did not place");
  const protectAt = installer.indexOf("Protect-OwnerOnly $DataDir");
  assert.equal(copyAt > 0 && placedAt > copyAt && protectAt > placedAt, true);
  assert.equal(installer.includes("Copy-Item"), false);
  assert.equal(installer.includes("Set-Acl"), false);
  assert.equal(installer.includes("$ConfigureOwner"), true);
  assert.equal(installer.includes("$ConfigureIntuit"), true);
  assert.equal(installer.includes("src\\index.js") || installer.includes("src/index.js"), false);
  assert.equal(installer.includes("start-oauth-service.ps1"), false);
  assert.equal(installer.includes("migrate-secrets.ps1"), false);
  const harness = fs.readFileSync(path.join(releaseRoot, "isolated-migration-test.ps1"), "utf8");
  assert.match(harness, /Mandatory = \$true/);
  assert.match(harness, /Refusing to use a live CPA path/);
  assert.match(harness, /Refusing to use a folder outside TEMP/);
  assert.match(harness, /migrate-secrets\.ps1/);
  assert.match(harness, /CPA_MIGRATION_ISOLATED/);
  assert.equal(harness.includes("8787"), false);
  const migration = fs.readFileSync(path.join(releaseRoot, "migrate-secrets.ps1"), "utf8");
  assert.match(migration, /\[string\]\$DataDir = "C:\\Users\\naesm\\AppData\\Local\\MapleRidge\\cpa-oauth"/);
  assert.match(migration, /CPA_MIGRATION_ISOLATED/);
  assert.match(migration, /Refusing isolated migration on a live CPA path/);
  assert.match(installer, /Move-Item -LiteralPath \$temp -Destination \$dest/);
  assert.match(installer, /check-intuit-credentials\.js/);
  const starter = fs.readFileSync(path.join(releaseRoot, "start-oauth-service.ps1"), "utf8");
  assert.match(starter, /Intuit credentials are partial/);
  assert.match(starter, /Starting in setup mode/);
  assert.match(starter, /still reversible/);
  assert.equal(starter.includes("QBO_CLIENT_ID") && starter.includes("OWNER_PASSWORD"), true);
  const winUrl = "file:///C:/Users/naesm/cpa-oauth-service/test/install-files.test.js";
  const fromPathname = path.win32.resolve(path.win32.dirname(new URL(winUrl).pathname), "..");
  assert.equal(releaseRootFromModuleUrl(winUrl, path.win32), "C:\\Users\\naesm\\cpa-oauth-service");
  assert.notEqual(fromPathname, "C:\\Users\\naesm\\cpa-oauth-service");
});

test("fresh install and upgrade both place protect-path.js without nesting src", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-install-"));
  const source = path.join(root, "source");
  const program = path.join(root, "cpa-oauth-service");
  const data = path.join(root, "cpa-oauth");
  const connector = path.join(root, "quickbooks-card-connector");
  writeRelease(source);
  fs.mkdirSync(path.join(program, "src", "src"), { recursive: true });
  fs.writeFileSync(path.join(program, "src", "src", "acl.js"), "nested src");
  fs.mkdirSync(path.join(program, "test", "test"), { recursive: true });
  fs.writeFileSync(path.join(program, "test", "test", "acl.test.js"), "nested test");
  fs.mkdirSync(path.join(program, "src"), { recursive: true });
  fs.writeFileSync(path.join(program, "src", "acl.js"), "old acl");
  fs.mkdirSync(data, { recursive: true });
  fs.writeFileSync(path.join(data, "service-config.json"), "keep-config");
  fs.writeFileSync(path.join(data, "qbo-tokens.json"), "keep-token");
  fs.writeFileSync(path.join(data, "secrets.clixml"), "keep-secret");
  fs.mkdirSync(connector, { recursive: true });
  fs.writeFileSync(path.join(connector, "authorize-quickbooks.ps1"), "keep-connector");

  copyRelease(source, program);

  assert.equal(fs.readFileSync(path.join(program, "src", "protect-path.js"), "utf8"), "new src/protect-path.js");
  assert.equal(fs.existsSync(path.join(program, "src", "src")), false);
  assert.equal(fs.existsSync(path.join(program, "test", "test")), false);
  assert.equal(fs.readFileSync(path.join(program, "src", "acl.js"), "utf8"), "new src/acl.js");
  assert.equal(fs.readFileSync(path.join(data, "service-config.json"), "utf8"), "keep-config");
  assert.equal(fs.readFileSync(path.join(data, "qbo-tokens.json"), "utf8"), "keep-token");
  assert.equal(fs.readFileSync(path.join(data, "secrets.clixml"), "utf8"), "keep-secret");
  assert.equal(fs.readFileSync(path.join(connector, "authorize-quickbooks.ps1"), "utf8"), "keep-connector");

  copyRelease(source, program);
  assert.equal(fs.existsSync(path.join(program, "src", "src")), false);
  assert.equal(fs.existsSync(path.join(program, "test", "test")), false);
  assert.equal(fs.readFileSync(path.join(data, "qbo-tokens.json"), "utf8"), "keep-token");
  assert.equal(fs.readFileSync(path.join(connector, "authorize-quickbooks.ps1"), "utf8"), "keep-connector");

  const fresh = path.join(root, "fresh");
  copyRelease(source, fresh);
  assert.equal(fs.existsSync(path.join(fresh, "src", "protect-path.js")), true);
  assert.equal(fs.existsSync(path.join(fresh, "src", "src")), false);

  assert.throws(() => copyRelease(source, connector), /connector directory/);
  assert.equal(fs.readFileSync(path.join(connector, "authorize-quickbooks.ps1"), "utf8"), "keep-connector");
});
