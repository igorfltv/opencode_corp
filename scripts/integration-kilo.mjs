import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile, chmod, readFile } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createEmulator } from "../server/emulator.js";
import { startLogin } from "../src/login.js";
import { CorporateAPI } from "../src/api.js";
import { applyConfig } from "../src/config.js";
import { clearMCP, mcpEnvName } from "../src/mcp.js";
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
  await atomicWrite(configPath, JSON.stringify({ plugin: [[root, { serverURL: emulator.baseURL }]], share: "disabled" }, null, 2));
  const api = new CorporateAPI(emulator.baseURL);
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
  const eventually = async (predicate, failure) => {
    const end = Date.now() + 15000;
    while (Date.now() < end) {
      const result = await predicate();
      if (result) return result;
      await Bun.sleep(250);
    }
    throw new Error(failure);
  };
  await request("/config");
  const loginURL = await eventually(async () => (await readFile(browserLog, "utf8").catch(() => "")).split("\n").find((line) => line.includes("/oauth/authorize")), "Kilo did not open login");
  assert.equal((await fetch(await approveBrowser(loginURL))).status, 200);
  await eventually(async () => JSON.parse(await readFile(configPath, "utf8")).provider?.corporate, "Kilo did not add its provider");
  const flow = await startLogin(api);
  assert.equal((await fetch(await approveBrowser(flow.url))).status, 200);
  const login = await flow.result;
  console.log("Kilo server started; checking loaded configuration");
  const config = await request("/config");
  assert.equal(config.provider.corporate.npm, "@ai-sdk/openai-compatible");
  assert.equal(config.provider.corporate.models["demo-code"].name, "Company Code Demo");
  assert.deepEqual(await request("/config/warnings"), []);
  const providers = await request("/provider");
  assert(providers.all.some((item) => item.id === "corporate"));
  const control = JSON.parse(await Bun.file(join(stateDir, "control.json")).text());
  const runCommand = async (name) => {
    const response = await fetch(`http://127.0.0.1:${control.port}/command/${name}`, { method: "POST", headers: { Authorization: `Bearer ${control.secret}` }, signal: AbortSignal.timeout(30000) });
    assert.equal(response.status, 200, `${name}: HTTP ${response.status}`);
    return response.json();
  };
  const expired = await fetch(`${emulator.baseURL}/admin/state`, {
    method: "POST", headers: { "x-demo-admin": emulator.adminToken, "Content-Type": "application/json" },
    body: JSON.stringify({ expire: true }),
  });
  assert.equal(expired.status, 200);
  const repeatedLogin = runCommand("login");
  const repeatedLoginURL = await eventually(async () => (await readFile(browserLog, "utf8")).split("\n").find((line) => line.includes("/oauth/authorize") && line !== loginURL), "Kilo /login did not reopen the browser flow");
  assert.equal((await fetch(await approveBrowser(repeatedLoginURL))).status, 200);
  await repeatedLogin;
  const session = await request("/session", "POST");
  const answer = await fetch(`${url}/session/${session.id}/message`, {
    method: "POST", headers: {
      Authorization: `Basic ${Buffer.from(`kilo:${password}`).toString("base64")}`,
      "x-kilo-directory": project, "Content-Type": "application/json",
    },
    body: JSON.stringify({ model: { providerID: "corporate", modelID: "demo-code" }, parts: [{ type: "text", text: "Проверка после повторного входа" }] }),
    signal: AbortSignal.timeout(30000),
  });
  assert.equal(answer.status, 200, `Kilo corporate message: HTTP ${answer.status}`);
  const message = await answer.json();
  assert.equal(message.info.error, undefined, `Kilo corporate message failed: ${JSON.stringify(message.info.error)}`);
  assert(message.parts.some((part) => part.type === "text" && part.text.includes("локальный эмулятор")));
  console.log("PASS Kilo model uses the new inference token after /login revokes the old session");
  const status = await fetch(`http://127.0.0.1:${control.port}/command/corp_status`, { method: "POST", headers: { Authorization: `Bearer ${control.secret}` } });
  assert.equal(status.status, 200);
  assert((await status.json()).message.includes("Engineering"));
  assert((await runCommand("inference_status")).message.includes("Инференс"));
  assert((await runCommand("refresh_config")).message.includes("Конфиг актуален"));
  const publicSkills = runCommand("skills_load");
  const skillFormURL = await eventually(async () => (await readFile(browserLog, "utf8")).split("\n").find((line) => line.includes("/form/")), "Kilo did not open skill selection");
  const skillFormHTML = await (await fetch(skillFormURL)).text();
  const skillCSRF = skillFormHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
  assert(skillCSRF);
  assert.equal((await fetch(skillFormURL, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: skillCSRF, choice: "community-grill-me" }) })).status, 200);
  await publicSkills;
  assert.equal(await Bun.file(join(profile, "skills/grill-me/SKILL.md")).exists(), true);
  const command = fetch(`http://127.0.0.1:${control.port}/command/mcps_load`, { method: "POST", headers: { Authorization: `Bearer ${control.secret}` }, signal: AbortSignal.timeout(30000) });
  const formURL = await eventually(async () => (await readFile(browserLog, "utf8").catch(() => "")).split("\n").find((line) => line.includes("/form/") && line !== skillFormURL), "Kilo did not open MCP selection");
  const formHTML = await (await fetch(formURL)).text();
  const formCSRF = formHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
  assert(formCSRF);
  assert.equal((await fetch(formURL, { method: "POST", headers: { Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams([ ["csrf", formCSRF], ["choice", "jira"], ["choice", "confluence"] ]) })).status, 200);
  const tokenURL = await eventually(async () => (await readFile(browserLog, "utf8")).split("\n").find((line) => line.includes("/secret/")), "Kilo did not open token form");
  const tokenHTML = await (await fetch(tokenURL)).text();
  assert(tokenHTML.includes("Jira") && tokenHTML.includes("Confluence"));
  const csrf = tokenHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
  assert(csrf);
  const tokenResponse = await fetch(tokenURL, { method: "POST", headers: { Origin: new URL(tokenURL).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, "token:jira": "demo-jira-token", "token:confluence": "demo-confluence-token" }) });
  assert.equal(tokenResponse.status, 200);
  assert((await tokenResponse.text()).includes("MCP добавлены в конфиг"));
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
  const catalogFlow = await startLogin(api);
  assert.equal((await fetch(await approveBrowser(catalogFlow.url))).status, 200);
  const catalogLogin = await catalogFlow.result;
  const skills = (await api.request("/api/skills", { token: catalogLogin.accessToken })).data.skills;
  await installSkills({ ids: ["corp-code-review"], catalog: skills, api, token: catalogLogin.accessToken, skillsDir: join(profile, "skills") });
  await request("/instance/reload", "POST");
  await eventually(async () => (await request("/skill")).some((item) => item.name === "corp-code-review"), "Kilo did not discover the installed skill");
  assert((await runCommand("logout")).message.includes("Выход выполнен"));
  assert.equal((await request("/config")).provider?.corporate, undefined);
  assert.equal(await readFile(join(stateDir, "access-token"), "utf8"), "");
  assert.equal(await readFile(join(stateDir, "access-token-next"), "utf8"), "");
  console.log("PASS installed Kilo CLI loads the plugin, corporate provider and MCP configuration");
  console.log("PASS Kilo CLI reloads provider configuration through its instance API");
  console.log("PASS Kilo CLI discovers installed corporate skills after instance reload");
  console.log("PASS all seven Kilo commands execute in the installed CLI");
} catch (error) {
  console.error(error.stack ?? error.message);
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
