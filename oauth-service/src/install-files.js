import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const ROOT_FILES = [
  "package.json",
  "package-lock.json",
  "host-settings.json",
  "install.ps1",
  "start-oauth-service.ps1",
  "README.md",
];

export const TREES = ["src", "test"];

export const REQUIRED = [
  ...ROOT_FILES,
  "src/protect-path.js",
  "src/install-files.js",
  "src/acl.js",
  "src/preflight.js",
  "src/index.js",
  "test/state-file.test.js",
];

export function assertNotConnector(candidate) {
  const parts = path.resolve(candidate).split(path.sep);
  if (parts.includes("quickbooks-card-connector")) {
    throw new Error("Refusing to touch the QuickBooks connector directory.");
  }
}

function copyChildren(fromDir, toDir) {
  fs.mkdirSync(toDir, { recursive: true });
  for (const entry of fs.readdirSync(fromDir, { withFileTypes: true })) {
    const from = path.join(fromDir, entry.name);
    const to = path.join(toDir, entry.name);
    if (entry.isDirectory()) copyChildren(from, to);
    else fs.copyFileSync(from, to);
  }
}

export function missingReleaseFiles(sourceDir) {
  return REQUIRED.filter((rel) => !fs.existsSync(path.join(sourceDir, rel)));
}

export function copyRelease(sourceDir, programDir) {
  assertNotConnector(sourceDir);
  assertNotConnector(programDir);
  const missing = missingReleaseFiles(sourceDir);
  if (missing.length) throw new Error(`Release is missing ${missing.join(", ")}`);
  const source = path.resolve(sourceDir);
  const program = path.resolve(programDir);
  if (source !== program) {
    fs.mkdirSync(program, { recursive: true });
    for (const name of ROOT_FILES) {
      fs.copyFileSync(path.join(source, name), path.join(program, name));
    }
    for (const name of TREES) {
      copyChildren(path.join(source, name), path.join(program, name));
    }
  }
  const notPlaced = missingReleaseFiles(program);
  if (notPlaced.length) throw new Error(`Install copy did not place ${notPlaced.join(", ")}`);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const [, , sourceDir, programDir] = process.argv;
    if (!sourceDir || !programDir) throw new Error("Usage: node src/install-files.js <source> <program>");
    copyRelease(sourceDir, programDir);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Install copy failed");
    process.exit(1);
  }
}
