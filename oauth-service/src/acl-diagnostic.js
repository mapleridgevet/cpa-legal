import fs from "node:fs";
import { WINDOWS_ACL_INDEX_READ_SCRIPT, WINDOWS_ACL_READ_SCRIPT, captureWindowsAclRead, evaluateWindowsAclReport } from "./acl.js";

function escapeText(value) {
  return String(value ?? "").replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\0/g, "\\0");
}

function hexPrefix(buffer) {
  return Buffer.from(buffer || []).subarray(0, 64).toString("hex");
}

export function formatCapture(label, capture) {
  const stdout = capture ? capture.stdout : "";
  const stderr = capture ? capture.stderr : "";
  const verdict = label === "installer-read" ? evaluateWindowsAclReport(stdout) : null;
  return [
    `BEGIN|${label}`,
    `status|${capture ? capture.status : "missing"}`,
    `error|${capture && capture.error ? capture.error : ""}`,
    `stdoutBytes|${capture && capture.stdoutRaw ? capture.stdoutRaw.length : 0}`,
    `stdoutHex|${hexPrefix(capture && capture.stdoutRaw)}`,
    `stdout|${escapeText(stdout)}`,
    `stderr|${escapeText(stderr)}`,
    verdict ? `verdict|${verdict.ok}|${verdict.detail}` : "verdict|not-evaluated",
    `END|${label}`,
  ].join("\n");
}

export function diagnoseDirectory(target, options = {}) {
  const installer = captureWindowsAclRead(target, WINDOWS_ACL_READ_SCRIPT, options);
  const indexed = captureWindowsAclRead(target, WINDOWS_ACL_INDEX_READ_SCRIPT, options);
  return [
    formatCapture("installer-read", installer),
    formatCapture("index-read", indexed),
  ].join("\n");
}

const isMain = process.argv[1] && process.argv[1].endsWith("acl-diagnostic.js");
if (isMain) {
  const target = process.argv[2];
  if (!target || !fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
    console.error("Pass the data directory only. File contents are not read.");
    process.exit(2);
  }
  console.log(diagnoseDirectory(target));
}
