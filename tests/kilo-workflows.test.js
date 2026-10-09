import { test, expect } from "bun:test";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { atomicWrite } from "../src/io.js";
import { installKiloWorkflows } from "../src/kilo-workflows.js";

const execute = promisify(execFile);

test("Kilo workflows install seven native chat commands without replacing user files", async () => {
  const root = await mkdtemp(join(tmpdir(), "corp-kilo-workflows-"));
  const options = { configPath: join(root, "kilo.jsonc"), stateDir: join(root, "corporate-state") };
  try {
    const custom = join(root, "commands", "login.md");
    await atomicWrite(custom, "Моя команда входа\n");
    expect((await installKiloWorkflows(options)).conflicts).toEqual(["login"]);
    expect(await readFile(custom, "utf8")).toBe("Моя команда входа\n");
    const names = ["refresh_config", "skills_load", "mcps_load", "logout", "corp_status", "inference_status"];
    for (const name of names) {
      const content = await readFile(join(root, "commands", `${name}.md`), "utf8");
      expect(content).toStartWith("---\n# opencode_corp managed Kilo workflow\ndescription:");
      expect(content).toContain(`workflow-command.mjs' ${name}`);
      expect(content).toContain("!`node ");
    }
    const helper = join(options.stateDir, "workflow-command.mjs");
    expect((await stat(helper)).mode & 0o077).toBe(0);
    await execute("node", ["--check", helper]);
    const offline = await execute("node", [helper, "corp_status"]);
    expect(offline.stdout).toContain("Что сделать:");
    expect(offline.stdout).toContain("Перезапустите Kilo");
    expect(offline.stderr).toBe("");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
