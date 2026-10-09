import { test, expect } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createEmulator } from "../server/emulator.js";
import { CorporateRuntime, optionsFromEnv } from "../src/runtime.js";
import { KiloBridge } from "../src/kilo-bridge.js";
import { startKiloControl } from "../src/kilo-control.js";
import { parseConfig, syncKiloMCP } from "../src/config.js";
import { mcpEnvName } from "../src/mcp.js";
import { atomicWrite } from "../src/io.js";
import { approveBrowser } from "./helpers.js";
import tui from "../src/tui.js";

async function eventually(fn, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const result = await fn();
    if (result) return result;
    await Bun.sleep(30);
  }
  throw new Error("Timed out waiting for Kilo runtime");
}

test("Kilo browser flow applies provider, skills and MCP without exposing tokens in config", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-kilo-"));
  const emulator = createEmulator({ port: 0 });
  const pages = [], messages = [];
  const options = optionsFromEnv({}, { client: "kilo", profileDir: root, serverURL: emulator.baseURL, refreshMs: 3600000, loadPollMs: 30000 });
  const bridge = new KiloBridge((item) => messages.push(item), async (url) => pages.push(url));
  const runtime = new CorporateRuntime(options, {
    bridge, open: async (url) => pages.push(url), notify: async () => {},
    syncMCP: (configs) => syncKiloMCP(options.configPath, options.stateDir, configs),
  });
  try {
    await atomicWrite(options.configPath, '{\n // preserve\n "plugin": ["/tmp/company"], "provider": {"personal":{"name":"Personal"}}\n}\n');
    await runtime.start();
    await runtime.login("kilo-test");
    const login = await eventually(() => pages.find((url) => url.includes("/oauth/authorize")));
    expect((await fetch(await approveBrowser(login))).status).toBe(200);
    await eventually(async () => parseConfig(await readFile(options.configPath, "utf8")).provider?.corporate);
    const openedBefore = pages.length;
    expect(await runtime.autoLogin()).toBe(false);
    expect(pages).toHaveLength(openedBefore);
    const config = parseConfig(await readFile(options.configPath, "utf8"));
    expect(config.provider.personal.name).toBe("Personal");
    expect(config.provider.corporate.npm).toBe("@ai-sdk/openai-compatible");
    expect(config.provider.corporate.options.apiKey).toContain("{file:");
    await runtime.skills("kilo-test", async () => {});
    const selection = await eventually(() => pages.find((url) => url.includes("/form/")));
    const selectionHTML = await (await fetch(selection)).text();
    const selectionCSRF = selectionHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(selectionCSRF).toBeTruthy();
    expect((await fetch(selection, { method: "POST", headers: { Origin: "https://wrong.test", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: selectionCSRF, choice: "corp-code-review" }) })).status).toBe(403);
    expect((await fetch(selection, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "choice=corp-code-review" })).status).toBe(403);
    expect((await fetch(selection, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: selectionCSRF, choice: "corp-code-review" }) })).status).toBe(200);
    await eventually(async () => (await readFile(join(options.skillsDir, "corp-code-review/SKILL.md"), "utf8").catch(() => "")).includes("corp-code-review"));
    await runtime.mcps("kilo-test");
    const mcpSelection = await eventually(() => pages.find((url) => url.includes("/form/") && url !== selection));
    const mcpSelectionHTML = await (await fetch(mcpSelection)).text();
    const mcpSelectionCSRF = mcpSelectionHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(mcpSelectionCSRF).toBeTruthy();
    expect((await fetch(mcpSelection, { method: "POST", headers: { Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: mcpSelectionCSRF, choice: "jira" }) })).status).toBe(200);
    const secret = await eventually(() => pages.find((url) => url.includes("/secret/")));
    const secretHTML = await (await fetch(secret)).text();
    const csrf = secretHTML.match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(csrf).toBeTruthy();
    const connected = await fetch(secret, { method: "POST", headers: { Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, "token:jira": "demo-jira-token" }) });
    expect(connected.status).toBe(200);
    expect((await connected.text()).includes("MCP добавлены в конфиг")).toBe(true);
    await eventually(async () => Boolean(parseConfig(await readFile(options.configPath, "utf8")).mcp?.corp_jira));
    const text = await readFile(options.configPath, "utf8");
    expect(text).toContain("// preserve");
    expect(text).not.toContain("demo-jira-token");
    expect(text).toContain(`{env:${mcpEnvName(options.stateDir, "jira")}}`);
    expect(process.env[mcpEnvName(options.stateDir, "jira")]).toBe("demo-jira-token");
    expect(await Bun.file(join(options.stateDir, "mcp-tokens/jira")).exists()).toBe(false);
    expect(messages.some((item) => item.title === "MCP добавлены")).toBe(true);
    await runtime.logout();
    const clean = parseConfig(await readFile(options.configPath, "utf8"));
    expect(clean.provider).toEqual({ personal: { name: "Personal" } });
    expect(clean.mcp).toBeUndefined();
    expect(process.env[mcpEnvName(options.stateDir, "jira")]).toBeUndefined();
  } finally {
    runtime.dispose(); bridge.dispose(); emulator.stop();
    await rm(root, { recursive: true, force: true });
  }
});

test("Kilo TUI registers seven direct slash commands", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-kilo-tui-"));
  const toasts = [];
  let commands, dispose;
  try {
    await atomicWrite(join(root, "kilo.jsonc"), '{"plugin":["/tmp/company"]}');
    await tui.tui({
      command: { register: (callback) => { commands = callback(); return () => {}; } },
      ui: { toast: (item) => toasts.push(item) },
      lifecycle: { onDispose: (fn) => { dispose = fn; } },
    }, { profileDir: root, serverURL: "http://127.0.0.1:4310" });
    expect(commands.map((item) => item.slash.name)).toEqual(["login", "refresh_config", "skills_load", "mcps_load", "logout", "corp_status", "inference_status"]);
  } finally { dispose?.(); await rm(root, { recursive: true, force: true }); }
});

test("Kilo VS Code opens login on startup and lets /login reopen it", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-kilo-control-"));
  const emulator = createEmulator({ port: 0 });
  const pages = [];
  let control;
  try {
    await atomicWrite(join(root, "kilo.jsonc"), '{"plugin":["git:github.com/igorfltv/opencode_corp@main"]}');
    control = await startKiloControl({ profileDir: root, serverURL: emulator.baseURL, refreshMs: 3600000 }, {
      open: async (url) => pages.push(url), notify: async () => {},
    });
    const endpoint = `http://127.0.0.1:${control.server.address().port}`;
    const state = JSON.parse(await readFile(join(root, "corporate-state/control.json"), "utf8"));
    expect(state.port).toBe(control.server.address().port);
    const ownState = JSON.parse(await readFile(join(root, `corporate-state/control-${process.pid}.json`), "utf8"));
    expect(ownState.port).toBe(state.port);
    const request = (command, token = state.secret) => fetch(`${endpoint}/command/${command}`, {
      method: "POST", headers: { Authorization: `Bearer ${token}` },
    });
    expect((await fetch(`${endpoint}/health`, { headers: { Authorization: `Bearer ${state.secret}` } })).status).toBe(200);
    expect((await request("corp_status", "wrong")).status).toBe(403);
    expect((await (await request("corp_status")).json()).message).toContain("Сначала выполните /login");
    const page = await eventually(() => pages.find((url) => url.includes("/oauth/authorize")));
    const login = request("login");
    await eventually(() => pages.filter((url) => url === page).length === 2);
    expect((await fetch(await approveBrowser(page))).status).toBe(200);
    const result = await (await login).json();
    expect(result.reload).toBe(true);
    expect(result.message).toContain("Вход открыт");
    await eventually(() => control.runtime.authenticated());
    expect((await (await request("corp_status")).json()).message).toContain("Engineering");
    let menu;
    const toasts = [];
    await tui.tui({
      command: { register: (callback) => { menu = callback(); return () => {}; } },
      client: { instance: { reload: async () => ({}) } },
      ui: { toast: (item) => toasts.push(item) },
      lifecycle: { onDispose: () => {} },
    }, { profileDir: root, serverURL: emulator.baseURL });
    await menu.find((item) => item.slash.name === "corp_status").onSelect();
    expect(toasts.at(-1).message).toContain("Engineering");
    expect((await (await request("logout")).json()).reload).toBe(true);
    expect((await (await request("corp_status")).json()).message).toContain("Сначала выполните /login");
  } finally {
    control?.runtime.dispose(); control?.bridge.dispose();
    control?.server.closeAllConnections();
    if (control) await new Promise((done) => control.server.close(done));
    emulator.stop(); await rm(root, { recursive: true, force: true });
  }
});
