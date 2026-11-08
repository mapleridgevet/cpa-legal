import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { REQUIRED, ROOT_FILES, copyRelease, missingReleaseFiles, releaseRootFromModuleUrl } from "../src/install-files.js";

const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function writeRelease(dir, extra = {}) {
  for (const rel of REQUIRED) {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, extra[rel] ?? `new ${rel}`);
  }
}

function rootFilesReadBySuite(dir) {
  const names = new Set();
  for (const name of fs.readdirSync(path.join(dir, "test")).filter((entry) => entry.endsWith(".js"))) {
    const text = fs.readFileSync(path.join(dir, "test", name), "utf8");
    for (const match of text.matchAll(/join\(\s*(?:root|releaseRoot|serviceRoot)\s*,\s*"([^"]+)"\s*\)/g)) names.add(match[1]);
    for (const match of text.matchAll(/"\.\.",\s*"([^"]+)"/g)) names.add(match[1]);
  }
  return [...names].filter((name) => !name.includes("/") && !name.includes("\\") && name.includes("."));
}

function assertInstalledSuitePasses(program) {
  const env = { ...process.env, CPA_SKIP_INSTALLED_RERUN: "1" };
  delete env.NODE_CHANNEL_FD;
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test"], {
    cwd: program,
    env,
    encoding: "utf8",
  });
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  assert.equal(result.status, 0, output.slice(-800));
  const failed = output.match(/(?:^|\n)[^\n]*\bfail\s+(\d+)/);
  const passed = output.match(/(?:^|\n)[^\n]*\bpass\s+(\d+)/);
  assert.equal(failed !== null && passed !== null && Number(failed[1]) === 0 && Number(passed[1]) >= 40, true, output.slice(-800));
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
  assert.ok(migration.indexOf("Write-Output \"MIGRATION_STARTED\"") < migration.indexOf("Import-Clixml"));
  assert.ok(migration.indexOf("if ($ResolveOnly)") < migration.indexOf("Write-Output \"MIGRATION_STARTED\""));
  assert.match(harness, /childResolvedUnderFixture/);
  assert.match(harness, /-ResolveOnly/);
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

test("the installer copies every root file the suite reads, then the installed tree passes", () => {
  if (process.env.CPA_SKIP_INSTALLED_RERUN === "1") return;
  const needed = rootFilesReadBySuite(releaseRoot);
  assert.deepEqual(needed.filter((name) => !ROOT_FILES.includes(name)), []);
  for (const name of ["decode-child-text.ps1", "isolated-migration-test.ps1", "isolated-resolve-diagnostic.ps1"]) {
    assert.equal(ROOT_FILES.includes(name), true);
    assert.equal(fs.existsSync(path.join(releaseRoot, name)), true);
  }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-installed-"));
  const fresh = path.join(root, "fresh");
  copyRelease(releaseRoot, fresh);
  for (const name of needed) assert.equal(fs.existsSync(path.join(fresh, name)), true);
  assertInstalledSuitePasses(fresh);

  const upgrade = path.join(root, "upgrade");
  fs.mkdirSync(path.join(upgrade, "src"), { recursive: true });
  fs.writeFileSync(path.join(upgrade, "src", "acl.js"), "old acl");
  const data = path.join(root, "data");
  fs.mkdirSync(data, { recursive: true });
  fs.writeFileSync(path.join(data, "secrets.clixml"), "keep-secret");
  fs.writeFileSync(path.join(data, "service-config.json"), "keep-config");
  fs.writeFileSync(path.join(data, "login-throttle.json"), "keep-throttle");
  copyRelease(releaseRoot, upgrade);
  assert.equal(fs.readFileSync(path.join(data, "secrets.clixml"), "utf8"), "keep-secret");
  assert.equal(fs.readFileSync(path.join(data, "service-config.json"), "utf8"), "keep-config");
  assert.equal(fs.readFileSync(path.join(data, "login-throttle.json"), "utf8"), "keep-throttle");
  assert.equal(fs.readFileSync(path.join(upgrade, "src", "acl.js"), "utf8").includes("old acl"), false);
  for (const name of needed) assert.equal(fs.existsSync(path.join(upgrade, name)), true);
  assertInstalledSuitePasses(upgrade);
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
