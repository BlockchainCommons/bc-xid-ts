/**
 * Build the frozen baseline bundle.
 *
 *   bun scripts/build-baseline.mjs
 *
 * Bundles src/index.ts as a single ESM file with every @blockchaincommons
 * sibling INLINED, resolving each sibling to ITS frozen baseline bundle
 * (../<repo>/tests/baseline/<pkg>-baseline.mjs) when one exists, so the
 * baseline keeps the published behaviour of its dependencies even after
 * they change. Writes tests/baseline/<pkg>-baseline.mjs, the .d.mts API
 * snapshot, and README.md with the commit and sha256 pinned.
 */
import { build } from "tsdown";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  copyFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const parent = dirname(root);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const short = pkg.name.replace("@blockchaincommons/", "");
const outDir = join(root, "tests", "baseline");
mkdirSync(outDir, { recursive: true });

// The closure is the published `@bcts/*` packages installed
// under tests/baseline (see its package.json): one copy of every sibling,
// unlike the per-package frozen bundles, which each inline their own.
const alias = {};
await build({
  // Never load the package's own tsdown.config.ts: its `deps.neverBundle` /
  // `external` settings would keep the siblings external.
  config: false,
  // A package may provide tests/baseline/entry.ts to widen the bundle surface
  // (e.g. expose an inlined dependency's global store to the differential).
  entry: { [`${short}-baseline`]: join(outDir, "entry.ts") },
  outDir,
  format: ["esm"],
  dts: false,
  sourcemap: false,
  clean: false,
  target: "es2022",
  // Everything but Node builtins is inlined: the bundle is self-contained.
  noExternal: [/^(?!node:)/],
  alias,
  inputOptions: {
    onwarn(w, d) {
      if (w.code !== "SOURCEMAP_BROKEN") d(w);
    },
  },
});

const bundle = join(outDir, `${short}-baseline.mjs`);
let text = readFileSync(bundle, "utf8").replace(/\n\/\/# sourceMappingURL=.*\n?$/, "\n");
writeFileSync(bundle, text);
const sha = createHash("sha256").update(text).digest("hex");
const commit = execSync("git rev-parse HEAD", { cwd: root }).toString().trim();
if (existsSync(join(root, "api/index.d.mts")))
  copyFileSync(join(root, "api/index.d.mts"), join(outDir, `${short}-baseline.d.mts`));
writeFileSync(
  join(outDir, "README.md"),
  `# Frozen baseline build

\`${short}-baseline.mjs\` is the self-contained ESM bundle of \`${pkg.name}\` built from
commit \`${commit}\`, the wire-format reference before this package's API. It is built from
the PUBLISHED \`@bcts\` packages (\`@bcts/xid\` 1.0.0-beta.6 and its closure,
pinned by tests/baseline/package.json), so every sibling is inlined exactly
once, with the behaviour consumers had.
\`${short}-baseline.d.mts\` is the public surface at that commit.

\`tests/differential.test.ts\` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: ${commit}
Baseline sha256: ${sha}
`,
);
console.log(
  `wrote ${bundle}\nsha256 ${sha}\ncommit ${commit}\naliases: ${JSON.stringify(alias, null, 1)}`,
);
