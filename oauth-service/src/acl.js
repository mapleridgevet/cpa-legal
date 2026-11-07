import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

export function restrictPrivate(target, options = {}) {
  const platform = options.platform || process.platform;
  const directory = options.directory === true;
  if (platform !== "win32") {
    fs.chmodSync(target, directory ? 0o700 : 0o600);
    return;
  }
  const user = options.user || process.env.USERNAME || "";
  if (!/^[A-Za-z0-9 ._$()-]+$/.test(user)) {
    throw new Error("Refusing to store tokens: Windows user name is unavailable");
  }
  const grant = directory ? `${user}:(OI)(CI)F` : `${user}:(F)`;
  const run = options.run || ((command, args) => spawnSync(command, args, { windowsHide: true, encoding: "utf8" }));
  const result = run("icacls", [target, "/inheritance:r", "/grant:r", grant]);
  if (!result || result.status !== 0) {
    throw new Error("Refusing to store tokens: Windows ACL could not be restricted");
  }
}

export function saveRestricted(filePath, contents, options = {}) {
  const restrict = options.restrict || ((target, extra) => restrictPrivate(target, { ...options, ...extra }));
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  restrict(directory, { directory: true });
  const tmp = `${filePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, contents, { mode: 0o600 });
    restrict(tmp, { directory: false });
    fs.renameSync(tmp, filePath);
    restrict(filePath, { directory: false });
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(filePath, { force: true });
    throw error;
  }
}
