const SENSITIVE_KEY = /client_secret|access_token|refresh_token|password|authorization|id_token|^code$|^token$|realm.?id|session_secret|cookie/i;

export function redact(value, secrets, depth = 0) {
  if (depth > 6) return "[redacted]";
  if (typeof value === "string") {
    let out = value;
    for (const secret of secrets) {
      if (typeof secret === "string" && secret.length >= 8 && out.includes(secret)) {
        out = out.split(secret).join("[redacted]");
      }
    }
    if (/^Bearer\s+\S+/i.test(out)) return "Bearer [redacted]";
    if (/^Basic\s+\S+/i.test(out)) return "Basic [redacted]";
    return out;
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, secrets, depth + 1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : redact(item, secrets, depth + 1);
    }
    return out;
  }
  return value;
}

export function createLogger() {
  const secrets = [];
  const lines = [];
  function write(level, event, fields = {}) {
    const line = JSON.stringify({ level, event, ...redact(fields, secrets) });
    lines.push(line);
    return line;
  }
  return {
    lines,
    noteSecret(value) {
      if (typeof value === "string" && value.length >= 8) secrets.push(value);
    },
    info(event, fields) {
      return write("info", event, fields);
    },
  };
}
