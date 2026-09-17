/**
 * Dependency hygiene gate.
 *
 *   bun scripts/check-deps.ts          # no unpublishable dependency
 *   bun scripts/check-deps.ts --zero   # additionally: zero runtime deps
 *
 * A published package must not depend on `@bcts/*` (the packages this library
 * was extracted from) or use a `workspace:` protocol range; the `--zero` form
 * additionally enforces a zero-runtime-dependency policy.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Record<
  string,
  Record<string, string> | undefined
>;
const zero = process.argv.includes("--zero");

const groups = ["dependencies", "peerDependencies", "optionalDependencies", "devDependencies"];
let failed = false;

for (const group of groups) {
  for (const [name, range] of Object.entries(pkg[group] ?? {})) {
    if (name.startsWith("@bcts/")) {
      console.error(`${group}: "${name}" is an unpublished package and cannot be depended on.`);
      failed = true;
    }
    if (typeof range === "string" && range.startsWith("workspace:")) {
      console.error(`${group}: "${name}" uses the workspace: protocol ("${range}").`);
      failed = true;
    }
  }
}

if (zero) {
  const runtime = Object.keys(pkg["dependencies"] ?? {});
  if (runtime.length > 0) {
    console.error("zero-dependency policy violated:", runtime.join(", "));
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(zero ? "zero runtime dependencies" : "no unpublishable dependencies");
