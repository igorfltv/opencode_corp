import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile, chmod, readFile } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createEmulator } from "../server/emulator.js";
import { startLogin } from "../src/login.js";
import { CorporateAPI } from "../src/api.js";
import { applyConfig, syncKiloMCP } from "../src/config.js";
import { saveMCPSelection, validateMCPCatalog, clearMCP, mcpEnvName } from "../src/mcp.js";
import { atomicWrite, random } from "../src/io.js";
import { installSkills } from "../src/skills.js";
import { approveBrowser } from "../tests/helpers.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const directory = await mkdtemp(join(tmpdir(), "corporate-kilo-integration-"));
const profile = join(directory, "config", "kilo");
const project = join(directory, "project");
const emulator = createEmulator({ port: 0 });
let child;
try {
  await mkdir(profile, { recursive: true });
  await mkdir(project, { recursive: true });
  const configPath = join(profile, "kilo.jsonc");
  const stateDir = join(profile, "corporate-state");
  await atomicWrite(configPath, JSON.stringify({ plugin: [root], model: "corporate/demo-code", share: "disabled" }, null, 2));
  const flow = await startLogin(new CorporateAPI(emulator.baseURL));
  assert.equal((await fetch(await approveBrowser(flow.url))).status, 200);
  const login = await flow.result;
  await atomicWrite(join(stateDir, "access-token"), login.accessToken);
  await atomicWrite(join(stateDir, "credential.json"), JSON.stringify({ accessToken: login.accessToken, expiresAt: login.expiresAt, user: login.user }));
  await applyConfig({ configPath, stateDir, serverURL: emulator.baseURL, envelope: login.configuration, client: "kilo" });
  const api = new CorporateAPI(emulator.baseURL);
  const catalog = validateMCPCatalog((await api.request("/api/mcps", { token: login.accessToken })).data, emulator.baseURL);
  const selection = await saveMCPSelection(stateDir, ["jira"], catalog, new Map([["jira", "demo-jira-token"]]));
  await syncKiloMCP(configPath, stateDir, selection);
  assert.equal(JSON.parse(await Bun.file(configPath).text()).mcp.corp_jira.headers.Authorization, `Bearer {env:${mcpEnvName(stateDir, "jira")}}`);
  const browserLog = join(directory, "browser-urls.log");
  const browserBin = join(directory, "browser-bin");
  await mkdir(browserBin);
  for (const name of ["open", "xdg-open"]) {
    const path = join(browserBin, name);
    await writeFile(path, '#!/bin/sh\nprintf "%s\\n" "$1" >> "$CORP_BROWSER_URL_LOG"\n');
    await chmod(path, 0o700);
  }
  const password = random();
  child = spawn(process.env.KILO_BIN ?? "kilo", ["serve", "--hostname", "127.0.0.1", "--port", "0"], {
    cwd: project, stdio: ["ignore", "pipe", "pipe"], env: {
      ...process.env, KILO_CONFIG_DIR: profile, KILO_SERVER_PASSWORD: password, KILO_DISABLE_DEFAULT_PLUGINS: "1",
      XDG_CONFIG_HOME: join(directory, "config"), XDG_DATA_HOME: join(directory, "data"),
      XDG_CACHE_HOME: join(directory, "cache"), XDG_STATE_HOME: join(directory, "state"),
      CORP_NO_BROWSER: "0", CORP_NO_NOTIFICATIONS: "1", CORP_BROWSER_URL_LOG: browserLog,
      PATH: `${browserBin}:${process.env.PATH ?? ""}`,
      CORP_SERVER_URL: emulator.baseURL,
    },
  });
  const url = await new Promise((resolveURL, reject) => {
    const timer = setTimeout(() => reject(new Error("Kilo server did not start within 20s")), 20000);
    let output = "";
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Kilo exited with code ${code}`)); });
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/kilo server listening on (http:\/\/[^\s]+)/);
      if (match) { clearTimeout(timer); resolveURL(match[1]); }
    });
    child.stderr.on("data", () => {});
  });
  const request = async (path, method = "GET") => {
    const response = await fetch(`${url}${path}`, { method, headers: {
      Authorization: `Basic ${Buffer.from(`kilo:${password}`).toString("base64")}`,
      "x-kilo-directory": project,
    }, signal: AbortSignal.timeout(60000) });
    assert.equal(response.status, 200, `Kilo ${path}: HTTP ${response.status}`);
    return response.json();
  };
  console.log("Kilo server started; checking loaded configuration");
  const config = await request("/config");
  assert.equal(config.provider.corporate.npm, "@ai-sdk/openai-compatible");
  assert.equal(config.provider.corporate.models["demo-code"].name, "Company Code Demo");
  assert.equal(config.mcp.corp_jira.type, "remote");
  assert.equal(config.mcp.corp_jira.headers.Authorization, "Bearer demo-jira-token");
  assert.deepEqual(await request("/config/warnings"), []);
  const providers = await request("/provider");
  assert(providers.all.some((item) => item.id === "corporate"));
  const eventually = async (predicate, failure) => {
    const end = Date.now() + 15000;
    while (Date.now() < end) {
      const result = await predicate();
      if (result) return result;
      await Bun.sleep(250);
    }
    throw new Error(failure);
  };
  const control = JSON.parse(await Bun.file(join(stateDir, "control.json")).text());
  const status = await fetch(`http://127.0.0.1:${control.port}/command/corp_status`, { method: "POST", headers: { Authorization: `Bearer ${control.secret}` } });
  assert.equal(status.status, 200);
  assert((await status.json()).message.includes("Engineering"));
  const command = fetch(`http://127.0.0.1:${control.port}/command/mcps_load`, { method: "POST", headers: { Authorization: `Bearer ${control.secret}` }, signal: AbortSignal.timeout(30000) });
  const formURL = await eventually(async () => (await readFile(browserLog, "utf8").catch(() => "")).split("\n").find((line) => line.includes("/form/")), "Kilo did not open MCP selection");
  assert.equal((await fetch(formURL, { method: "POST", headers: { Origin: new URL(formURL).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: "choice=jira&choice=confluence" })).status, 200);
  const tokenURL = await eventually(async () => (await readFile(browserLog, "utf8")).split("\n").find((line) => line.includes("/secret/")), "Kilo did not open token form");
  const tokenHTML = await (await fetch(tokenURL)).text();
  assert(tokenHTML.includes("Confluence"));
  assert.equal((await fetch(tokenURL, { method: "POST", headers: { Origin: new URL(tokenURL).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: "token%3Aconfluence=demo-confluence-token" })).status, 200);
  assert.equal((await command).status, 200);
  assert.equal(JSON.parse(await readFile(configPath, "utf8")).mcp.corp_confluence.headers.Authorization, `Bearer {env:${mcpEnvName(stateDir, "confluence")}}`);
  assert.equal(await Bun.file(join(stateDir, "mcp-tokens/confluence")).exists(), false);
  await eventually(async () => (await request("/config")).mcp?.corp_confluence?.headers?.Authorization === "Bearer demo-confluence-token", "Kilo did not resolve the new in-process MCP environment variable");
  console.log("PASS browser form submits a new token to the running Kilo process without writing it to disk");
  console.log("Kilo provider and MCP loaded; checking live reload");
  const updated = structuredClone(login.configuration);
  updated.revision = 2;
  updated.config.providers.corporate.models["demo-code"].name = "Company Code V2";
  await applyConfig({ configPath, stateDir, serverURL: emulator.baseURL, envelope: updated, client: "kilo" });
  await request("/instance/reload", "POST");
  await eventually(async () => (await request("/config")).provider?.corporate?.models?.["demo-code"]?.name === "Company Code V2", "Kilo did not reload the changed provider config");
  await request("/skill");
  const skills = (await api.request("/api/skills", { token: login.accessToken })).data.skills;
  await installSkills({ ids: ["corp-code-review"], catalog: skills, api, token: login.accessToken, skillsDir: join(profile, "skills") });
  await request("/instance/reload", "POST");
  await eventually(async () => (await request("/skill")).some((item) => item.name === "corp-code-review"), "Kilo did not discover the installed skill");
  console.log("PASS installed Kilo CLI loads the plugin, corporate provider and MCP configuration");
  console.log("PASS Kilo CLI reloads provider configuration through its instance API");
  console.log("PASS Kilo CLI discovers installed corporate skills after instance reload");
} catch (error) {
  console.error(error.message);
  console.error(`Diagnostic profile retained at ${directory}`);
  process.exitCode = 1;
} finally {
  child?.kill("SIGTERM");
  if (child && child.exitCode === null) await Promise.race([new Promise((done) => child.once("exit", done)), Bun.sleep(3000)]);
  if (child?.exitCode === null) child.kill("SIGKILL");
  await clearMCP(join(profile, "corporate-state"));
  emulator.stop();
  if (!process.exitCode) await rm(directory, { recursive: true, force: true });
}
