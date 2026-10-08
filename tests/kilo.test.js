import { test, expect } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createEmulator } from "../server/emulator.js";
import { CorporateRuntime, optionsFromEnv } from "../src/runtime.js";
import { KiloBridge } from "../src/kilo-bridge.js";
import { startKiloControl } from "../src/kilo-control.js";
import { parseConfig, syncKiloMCP } from "../src/config.js";
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
    const config = parseConfig(await readFile(options.configPath, "utf8"));
    expect(config.provider.personal.name).toBe("Personal");
    expect(config.provider.corporate.npm).toBe("@ai-sdk/openai-compatible");
    expect(config.provider.corporate.options.apiKey).toContain("{file:");
    await runtime.skills("kilo-test", async () => {});
    const selection = await eventually(() => pages.find((url) => url.includes("/form/")));
    expect((await fetch(selection)).status).toBe(200);
    expect((await fetch(selection, { method: "POST", headers: { Origin: "https://wrong.test", "Content-Type": "application/x-www-form-urlencoded" }, body: "choice=corp-code-review" })).status).toBe(403);
    expect((await fetch(selection, { method: "POST", headers: { Origin: new URL(selection).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: "choice=corp-code-review" })).status).toBe(200);
    await eventually(async () => (await readFile(join(options.skillsDir, "corp-code-review/SKILL.md"), "utf8").catch(() => "")).includes("corp-code-review"));
    await runtime.mcps("kilo-test");
    const mcpSelection = await eventually(() => pages.find((url) => url.includes("/form/") && url !== selection));
    expect((await fetch(mcpSelection, { method: "POST", headers: { Origin: new URL(mcpSelection).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: "choice=jira" })).status).toBe(200);
    const secret = await eventually(() => pages.find((url) => url.includes("/secret/")));
    expect((await fetch(secret, { method: "POST", headers: { Origin: new URL(secret).origin, "Content-Type": "application/x-www-form-urlencoded" }, body: "token=demo-jira-token" })).status).toBe(200);
    await eventually(async () => Boolean(parseConfig(await readFile(options.configPath, "utf8")).mcp?.corp_jira));
    const text = await readFile(options.configPath, "utf8");
    expect(text).toContain("// preserve");
    expect(text).not.toContain("demo-jira-token");
    expect(messages.some((item) => item.title === "MCP настроены")).toBe(true);
    await runtime.logout();
    const clean = parseConfig(await readFile(options.configPath, "utf8"));
    expect(clean.provider).toEqual({ personal: { name: "Personal" } });
    expect(clean.mcp).toBeUndefined();
  } finally {
    runtime.dispose(); bridge.dispose(); emulator.stop();
    await rm(root, { recursive: true, force: true });
  }
});

test("Kilo TUI registers seven direct slash commands and requires login", async () => {
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
    await commands.find((item) => item.slash.name === "corp_status").onSelect();
    expect(toasts.at(-1).message).toContain("Сначала выполните /login");
  } finally { dispose?.(); await rm(root, { recursive: true, force: true }); }
});

test("Kilo VS Code control executes login and status through an authenticated loopback bridge", async () => {
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
    const request = (command, token = state.secret) => fetch(`${endpoint}/command/${command}`, {
      method: "POST", headers: { Authorization: `Bearer ${token}` },
    });
    expect((await fetch(`${endpoint}/health`, { headers: { Authorization: `Bearer ${state.secret}` } })).status).toBe(200);
    expect((await request("corp_status", "wrong")).status).toBe(403);
    expect((await (await request("corp_status")).json()).message).toContain("Сначала выполните /login");
    const login = request("login");
    const page = await eventually(() => pages.find((url) => url.includes("/oauth/authorize")));
    expect((await fetch(await approveBrowser(page))).status).toBe(200);
    const result = await (await login).json();
    expect(result.reload).toBe(true);
    expect(result.message).toContain("Вход выполнен");
    expect((await (await request("corp_status")).json()).message).toContain("Engineering");
    expect((await (await request("logout")).json()).reload).toBe(true);
    expect((await (await request("corp_status")).json()).message).toContain("Сначала выполните /login");
  } finally {
    control?.runtime.dispose(); control?.bridge.dispose();
    control?.server.closeAllConnections();
    if (control) await new Promise((done) => control.server.close(done));
    emulator.stop(); await rm(root, { recursive: true, force: true });
  }
});
