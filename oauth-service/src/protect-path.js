import fs from "node:fs";
import { restrictPrivate } from "./acl.js";

const target = process.argv[2];
if (!target || !fs.existsSync(target)) {
  console.error("Refusing to protect a missing path");
  process.exit(1);
}
try {
  restrictPrivate(target, { directory: fs.statSync(target).isDirectory() });
} catch (error) {
  console.error(error instanceof Error ? error.message : "Refusing to store tokens");
  process.exit(1);
}
