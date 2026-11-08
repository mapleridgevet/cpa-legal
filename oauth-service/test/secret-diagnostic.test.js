import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { describeSecret, parseFormFields, sameSecret } from "../src/secret-diagnostic.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "src", "secret-diagnostic.js");
const sentinel = "SENTINEL-owner-secret-do-not-print-9f3a";
const sessionSentinel = "SENTINEL-session-secret-do-not-print-32chars";

function runReport(owner, session) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, OWNER_PASSWORD: owner, SESSION_SECRET: session },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("the launcher report describes a secret without printing it or a hash", async () => {
  const flags = describeSecret(`  ${sentinel}%&+"\\\n\uFFFD密码`);
  assert.equal(flags.length > 16, true);
  assert.equal(flags.nonAscii, true);
  assert.equal(flags.replacement, true);
  assert.equal(flags.leadingSpace, true);
  assert.equal(flags.lf, true);
  assert.equal(JSON.stringify(flags).includes(sentinel), false);

  const report = await runReport(`  ${sentinel}%&+"\\`, sessionSentinel);
  assert.equal(report.status, 0);
  const combined = report.stdout + report.stderr;
  assert.equal(combined.includes(sentinel), false);
  assert.equal(combined.includes(sessionSentinel), false);
  assert.match(report.stdout, /DIAG\|ownerChildLength\|/);
  assert.match(report.stdout, /DIAG\|ownerChildLeadingSpace\|true/);
  assert.match(report.stdout, /DIAG\|sessionChildLength\|/);
  assert.equal(combined.toLowerCase().includes("sha256"), false);
});

test("a local compare reports only yes or no", async () => {
  const owner = "owner-password-value";
  const session = "session-secret-value-at-least-32";
  async function compare(candidate) {
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [script], {
        env: {
          ...process.env,
          OWNER_PASSWORD: owner,
          SESSION_SECRET: session,
          CPA_DIAG_CANDIDATE: candidate,
          CPA_DIAG_MODE: "compare",
        },
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.on("error", reject);
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
  }
  const ownerHit = await compare(owner);
  assert.equal(ownerHit.status, 0);
  assert.match(ownerHit.stdout, /DIAG\|matchesOwner\|true/);
  assert.match(ownerHit.stdout, /DIAG\|matchesSession\|false/);
  assert.equal((ownerHit.stdout + ownerHit.stderr).includes(owner), false);
  assert.equal((ownerHit.stdout + ownerHit.stderr).includes(session), false);

  const sessionHit = await compare(session);
  assert.match(sessionHit.stdout, /DIAG\|matchesOwner\|false/);
  assert.match(sessionHit.stdout, /DIAG\|matchesSession\|true/);
  assert.equal((sessionHit.stdout + sessionHit.stderr).includes(session), false);

  const miss = await compare("different-password-value");
  assert.match(miss.stdout, /DIAG\|matchesOwner\|false/);
  assert.match(miss.stdout, /DIAG\|matchesSession\|false/);
});

test("a framed browser body keeps the password exact", () => {
  const password = `a+b&c% d"'\u00e9`;
  const body = Buffer.from(`password=${encodeURIComponent(password)}\r\n`);
  const fields = parseFormFields(body, "application/x-www-form-urlencoded;charset=UTF-8");
  assert.equal(fields.get("password"), password);
  assert.equal(sameSecret(fields.get("password"), password), true);
  assert.equal(sameSecret("  exact-password-value  ", "exact-password-value"), false);
});

test("one diagnostic listen response does not echo the password", async () => {
  const port = 18080 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, [script], {
    env: {
      ...process.env,
      OWNER_PASSWORD: sentinel,
      SESSION_SECRET: sessionSentinel,
      CPA_DIAG_MODE: "listen",
      CPA_DIAG_PORT: String(port),
    },
  });
  let stdout = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  await new Promise((resolve, reject) => {
    const started = setInterval(() => {
      if (stdout.includes("DIAG|listen|")) {
        clearInterval(started);
        resolve();
      }
    }, 20);
    child.on("exit", () => {
      clearInterval(started);
      reject(new Error("diagnostic exited before listen"));
    });
  });
  const body = await new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1",
      port,
      method: "POST",
      path: "/login",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("error", reject);
    req.end(`password=${encodeURIComponent(sentinel)}\r\n`);
  });
  assert.match(body, /DIAG\|match\|true/);
  assert.equal(body.includes(sentinel), false);
  assert.equal(body.includes(sessionSentinel), false);
  await new Promise((resolve) => child.on("close", resolve));
});
