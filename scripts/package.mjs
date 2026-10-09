import { mkdtemp, mkdir, copyFile, cp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { root } from "./harness.mjs";
const staging = await mkdtemp(join(tmpdir(), "corporate-package-"));
try {
  for (const name of ["server.js", "tui.js"]) await copyFile(join(root, name), join(staging, name));
  await copyFile(join(root, "README.md"), join(staging, "README.md"));
  await copyFile(join(root, "ROADMAP.md"), join(staging, "ROADMAP.md"));
  await cp(join(root, "community"), join(staging, "community"), { recursive: true });
  await writeFile(join(staging, "package.json"), JSON.stringify({ name: "@company/opencode-corporate", version: "0.1.0", type: "module", exports: { ".": "./server.js", "./server": "./server.js", "./tui": "./tui.js" } }, null, 2));
  await mkdir(join(root, "artifacts"), { recursive: true });
  const archive = join(root, "artifacts/company-opencode-0.1.0.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", staging, "."], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  console.log(archive);
} finally { await rm(staging, { recursive: true, force: true }); }
