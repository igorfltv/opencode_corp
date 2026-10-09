import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { launch, eventually } from "./harness.mjs";
import { approveBrowser } from "../tests/helpers.js";
import { parseConfig } from "../src/config.js";

const directory = await mkdtemp(join(tmpdir(), "corporate-github-"));
let demo;
try {
  demo = await launch({ directory, pluginSpec: "github:igorfltv/opencode_corp#main", pluginTimeout: 60000, quiet: true });
  const config = await readFile(demo.configPath, "utf8");
  assert(config.includes('"github:igorfltv/opencode_corp#main"'));
  assert.equal(parseConfig(config).providers, undefined);
  const plugins = (await demo.request("/api/plugin")).data;
  assert(plugins.some((plugin) => plugin.id === "company-corporate" && plugin.state.status === "active"));
  const commands = (await demo.request("/api/command")).data.map((command) => command.name);
  for (const name of ["login", "refresh_config", "skills_load", "mcps_load", "inference_status", "corp_status", "logout"]) assert(commands.includes(name));
  console.log("PASS GitHub plugin loaded by OpenCode with all seven slash commands");
  for (const name of ["refresh_config", "skills_load", "mcps_load", "inference_status", "corp_status", "logout"]) {
    await demo.command(name);
    const form = await eventually(async () => (await demo.forms()).find((entry) => entry.title.includes(`/${name}`)));
    assert(form.fields[0].description.includes("Сначала выполните /login"), `${name} did not require login`);
    await demo.request(`/api/session/${demo.session.id}/form/${form.id}`, { method: "DELETE" });
  }
  console.log("PASS GitHub plugin blocks all non-login commands before login");
  await demo.command("login");
  const loginForm = await eventually(async () => (await demo.forms()).find((entry) => entry.title.includes("Вход в корпоративный")));
  const callback = await approveBrowser(loginForm.fields[0].url);
  assert.equal((await fetch(callback)).status, 200);
  await eventually(async () => !(await demo.forms()).some((entry) => entry.id === loginForm.id));
  assert(!(await demo.forms()).some((entry) => entry.title.includes("Вход выполнен")));
  assert(parseConfig(await readFile(demo.configPath, "utf8")).providers?.corporate);
  for (const form of await demo.forms()) await demo.request(`/api/session/${demo.session.id}/form/${form.id}`, { method: "DELETE" });
  await demo.command("logout");
  await eventually(async () => (await demo.forms()).find((entry) => entry.title.includes("Выход выполнен")));
  assert.equal(parseConfig(await readFile(demo.configPath, "utf8")).providers, undefined);
  console.log("PASS GitHub plugin adds provider only after login and removes it on logout");
} catch (error) {
  console.error(error);
  console.error(`Diagnostic profile retained at ${directory}`);
  process.exitCode = 1;
} finally {
  await demo?.stop();
  if (!process.exitCode) await rm(directory, { recursive: true, force: true });
}
