import crypto from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";

export function sameSecret(input, expected) {
  const a = crypto.createHash("sha256").update(String(input).normalize("NFC"), "utf8").digest();
  const b = crypto.createHash("sha256").update(String(expected).normalize("NFC"), "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

export function parseFormFields(body, contentType) {
  const type = String(contentType || "");
  if (/multipart\/form-data/i.test(type)) {
    const parsed = parseMultipart(body, type);
    if (parsed) return parsed;
  }
  const text = body.toString("utf8").replace(/(?:\r\n|\n|\r)+$/, "");
  return new URLSearchParams(text);
}

function parseMultipart(body, contentType) {
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(String(contentType));
  if (!boundaryMatch) return null;
  const boundary = boundaryMatch[1] || boundaryMatch[2];
  if (!boundary || boundary.length > 70) return null;
  const params = new URLSearchParams();
  for (const rawPart of body.toString("utf8").split(`--${boundary}`)) {
    let part = rawPart;
    if (part.startsWith("\r\n")) part = part.slice(2);
    else if (part.startsWith("\n")) part = part.slice(1);
    if (part === "" || part.startsWith("--")) continue;
    const crlf = part.indexOf("\r\n\r\n");
    const lf = part.indexOf("\n\n");
    const splitAt = crlf >= 0 ? crlf : lf;
    if (splitAt < 0) continue;
    const nameMatch = /name="([^"]*)"|name=([^;\s]+)/i.exec(part.slice(0, splitAt));
    if (!nameMatch) continue;
    let value = part.slice(splitAt + (crlf >= 0 ? 4 : 2));
    value = value.replace(/\r\n$/, "").replace(/\n$/, "");
    params.append(nameMatch[1] ?? nameMatch[2], value);
  }
  return params;
}

export function describeSecret(value) {
  const text = typeof value === "string" ? value : "";
  let nonAscii = false;
  let replacement = false;
  let cr = false;
  let lf = false;
  let tab = false;
  let space = false;
  let nul = false;
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code > 127) nonAscii = true;
    if (code === 0xfffd) replacement = true;
    if (code === 13) cr = true;
    if (code === 10) lf = true;
    if (code === 9) tab = true;
    if (code === 32) space = true;
    if (code === 0) nul = true;
  }
  return {
    length: text.length,
    nonAscii,
    replacement,
    cr,
    lf,
    tab,
    space,
    nul,
    leadingSpace: text.startsWith(" "),
    trailingSpace: text.endsWith(" "),
  };
}

export function formatFlags(prefix, flags) {
  return [
    ["Length", flags.length],
    ["NonAscii", flags.nonAscii],
    ["Replacement", flags.replacement],
    ["Cr", flags.cr],
    ["Lf", flags.lf],
    ["Tab", flags.tab],
    ["Space", flags.space],
    ["Nul", flags.nul],
    ["LeadingSpace", flags.leadingSpace],
    ["TrailingSpace", flags.trailingSpace],
  ].map(([name, value]) => `DIAG|${prefix}${name}|${value}`);
}

function emitLines(lines, secrets) {
  const blocked = secrets.filter((secret) => typeof secret === "string" && secret.length >= 8);
  for (const line of lines) {
    if (blocked.some((secret) => line.includes(secret))) {
      console.log("DIAG|refused|output");
      return false;
    }
  }
  for (const line of lines) console.log(line);
  return true;
}

function reportChild() {
  const owner = process.env.OWNER_PASSWORD;
  const session = process.env.SESSION_SECRET;
  const lines = [];
  if (typeof owner !== "string") lines.push("DIAG|ownerChild|missing");
  else lines.push(...formatFlags("ownerChild", describeSecret(owner)));
  if (typeof session !== "string") lines.push("DIAG|sessionChild|missing");
  else lines.push(...formatFlags("sessionChild", describeSecret(session)));
  return emitLines(lines, [owner, session]);
}

function listenOnce() {
  const owner = process.env.OWNER_PASSWORD;
  if (typeof owner !== "string") {
    console.log("DIAG|ownerChild|missing");
    process.exit(1);
  }
  const port = Number(process.env.CPA_DIAG_PORT || 8787);
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 8192) break;
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const fields = parseFormFields(body, req.headers["content-type"]);
    const submitted = fields.get("password");
    const fieldPresent = typeof submitted === "string";
    const lines = [
      "DIAG|listened|true",
      `DIAG|bodyLength|${body.length}`,
      `DIAG|fieldPresent|${fieldPresent}`,
      `DIAG|fieldLength|${fieldPresent ? submitted.length : 0}`,
      `DIAG|storedLength|${owner.length}`,
      `DIAG|lengthsEqual|${fieldPresent && submitted.length === owner.length}`,
      `DIAG|match|${fieldPresent && sameSecret(submitted, owner)}`,
      ...formatFlags("stored", describeSecret(owner)),
      ...formatFlags("submitted", describeSecret(fieldPresent ? submitted : "")),
      "DIAG|filesChanged|false",
    ];
    const safe = emitLines(lines, [owner, submitted, process.env.SESSION_SECRET]);
    const payload = Buffer.from(safe ? `${lines.join("\n")}\n` : "DIAG|refused|output\n");
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Length": payload.length,
    });
    res.end(payload);
    server.close(() => process.exit(safe ? 0 : 2));
  });
  server.on("error", () => {
    console.log("DIAG|listen|busy");
    process.exit(1);
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`DIAG|listen|127.0.0.1:${port}`);
  });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  if (process.env.CPA_DIAG_MODE === "listen") listenOnce();
  else {
    const ok = reportChild();
    process.exit(ok ? 0 : 2);
  }
}
