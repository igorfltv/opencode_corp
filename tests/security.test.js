import { test, expect, afterEach } from "bun:test";
import { mkdtemp, readFile, rm, stat, mkdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { createEmulator } from "../server/emulator.js";
import { CorporateAPI, Unauthorized } from "../src/api.js";
import { startLogin } from "../src/login.js";
import { applyConfig, parseConfig, removeProvider, rotateProviderTokenReference, syncKiloMCP, syncOpenCodeMCP, validateConfig } from "../src/config.js";
import { installSkills, validateCatalog } from "../src/skills.js";
import { optionsFromEnv, CorporateRuntime } from "../src/runtime.js";
import { atomicWrite, digest, exists, random } from "../src/io.js";
import { validateMCPCatalog, saveMCPSelection, readMCPState, clearMCP, mcpEnvName } from "../src/mcp.js";
import { captureSecrets } from "../src/secret-page.js";
import { approveBrowser } from "./helpers.js";

const cleanups = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });
function server(options = {}) { const result = createEmulator({ port: 0, ...options }); cleanups.push(() => result.stop()); return result; }
async function folder() { const dir = await mkdtemp(join(tmpdir(), "corporate-test-")); cleanups.push(() => rm(dir, { force: true, recursive: true })); return dir; }
async function signIn(emulator, account = "engineer") {
  const api = new CorporateAPI(emulator.baseURL);
  const flow = await startLogin(api); cleanups.push(flow.cancel);
  const callback = await approveBrowser(flow.url, account);
  const response = await fetch(callback);
  expect(response.status).toBe(200);
  return flow.result;
}
function envelope(baseURL) { return { revision: 1, config: { providers: { corporate: { name: "Corp", settings: { baseURL: `${baseURL}/v1` }, models: { code: { name: "Code", limit: { context: 16000, output: 4000 } } } } } } }; }

test("browser login checks state and completes PKCE without a token in the URL", async () => {
  const emulator = server(), api = new CorporateAPI(emulator.baseURL);
  const flow = await startLogin(api); cleanups.push(flow.cancel);
  const callback = await approveBrowser(flow.url, "engineer", true);
  const wrong = new URL(callback); wrong.searchParams.set("state", random());
  expect((await fetch(wrong)).status).toBe(400);
  wrong.searchParams.set("state", "я".repeat(43));
  expect((await fetch(wrong)).status).toBe(400);
  expect((await fetch(callback)).status).toBe(200);
  const result = await flow.result;
  expect(result.accessToken.length).toBe(43);
  expect(result.inferenceToken.length).toBe(43);
  expect(result.refreshToken.length).toBe(43);
  expect(result.inferenceExpiresAt - Date.now()).toBeLessThanOrEqual(5 * 60000);
  expect(callback).not.toContain(result.accessToken);
  expect(callback).not.toContain(result.refreshToken);
  expect(result.configuration.revision).toBe(1);
  expect(JSON.stringify(emulator.state.audit)).not.toContain(result.accessToken);
});

test("inference token has a separate audience, expires, and cannot refresh", async () => {
  const emulator = server({ inferenceTokenMs: 120, apiTokenMs: 1000 }), api = new CorporateAPI(emulator.baseURL);
  const login = await signIn(emulator);
  expect((await api.request("/api/config", { token: login.accessToken })).data.revision).toBe(1);
  expect((await api.request("/v1/models", { token: login.inferenceToken })).data.data[0].id).toBe("demo-code");
  await expect(api.request("/v1/models", { token: login.accessToken })).rejects.toThrow("/login");
  await expect(api.request("/api/config", { token: login.inferenceToken })).rejects.toThrow("/login");
  await expect(api.request("/oauth/refresh", { method: "POST", body: { refreshToken: login.inferenceToken } })).rejects.toThrow("/login");
  await Bun.sleep(150);
  await expect(api.request("/v1/models", { token: login.inferenceToken })).rejects.toThrow("/login");
  const renewed = (await api.request("/oauth/refresh", { method: "POST", body: { refreshToken: login.refreshToken } })).data;
  expect(renewed.refreshToken).not.toBe(login.refreshToken);
  expect((await api.request("/v1/models", { token: renewed.inferenceToken })).data.data[0].id).toBe("demo-code");
  await expect(api.request("/oauth/refresh", { method: "POST", body: { refreshToken: login.refreshToken } })).rejects.toThrow("/login");
  await expect(api.request("/v1/models", { token: renewed.inferenceToken })).rejects.toThrow("/login");
});

test("the gateway enforces model allowlist and per-session inference quota", async () => {
  const emulator = server({ inferenceRequestsPerMinute: 1 }), login = await signIn(emulator);
  const request = (model) => fetch(`${emulator.baseURL}/v1/chat/completions`, { method: "POST",
    headers: { Authorization: `Bearer ${login.inferenceToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "Hi" }] }),
  });
  expect((await request("other-model")).status).toBe(403);
  expect((await request("demo-code")).status).toBe(200);
  expect((await request("demo-code")).status).toBe(429);
});

test("runtime rotates inference token without writing the refresh token", async () => {
  const emulator = server(), root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "corporate-state");
  await atomicWrite(configPath, "{}");
  const login = await signIn(emulator);
  let reloads = 0;
  const runtime = new CorporateRuntime(optionsFromEnv({}, { profileDir: root, serverURL: emulator.baseURL }), {
    reloadProvider: async () => { reloads++; }, notify: async () => {},
  });
  try {
    runtime.credential = login;
    await atomicWrite(join(stateDir, "access-token"), login.inferenceToken);
    await runtime.ensureFreshTokens(true);
    const current = await readFile(join(stateDir, "access-token"), "utf8");
    expect(current).not.toBe(login.inferenceToken);
    expect(current).toBe(runtime.credential.inferenceToken);
    expect(reloads).toBe(1);
    expect(await exists(join(stateDir, "credential.json"))).toBeNull();
    expect(await readFile(join(stateDir, "access-token"), "utf8")).not.toContain(runtime.credential.refreshToken);
  } finally { runtime.dispose(); }
});

test("a late refresh response cannot restore credentials after logout", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "corporate-state");
  await atomicWrite(configPath, "{}");
  const old = { accessToken: random(), expiresAt: Date.now() + 60000, inferenceToken: random(), inferenceExpiresAt: Date.now() + 60000, refreshToken: random(), refreshExpiresAt: Date.now() + 3600000, user: { name: "Test" } };
  const renewed = { ...old, accessToken: random(), inferenceToken: random(), refreshToken: random() };
  let resolveRefresh, refreshStarted;
  const started = new Promise((resolve) => { refreshStarted = resolve; });
  const runtime = new CorporateRuntime({ configPath, stateDir }, { api: { request: async (path) => {
    if (path === "/oauth/refresh") { refreshStarted(); return new Promise((resolve) => { resolveRefresh = resolve; }); }
    return { data: { revoked: true } };
  } }, notify: async () => {}, reloadProvider: async () => {} });
  try {
    runtime.credential = old;
    await atomicWrite(join(stateDir, "access-token"), old.inferenceToken);
    const pending = runtime.ensureFreshTokens(true);
    await started;
    await runtime.logout();
    resolveRefresh({ data: renewed });
    await pending;
    expect(runtime.credential).toBeNull();
    expect(await readFile(join(stateDir, "access-token"), "utf8")).toBe("");
  } finally { runtime.dispose(); }
});

test("authorization codes cannot be replayed or exchanged without the verifier", async () => {
  const emulator = server(), api = new CorporateAPI(emulator.baseURL);
  const verifier = random(), redirectURI = "http://127.0.0.1:12345/callback";
  const { data } = await api.request("/oauth/requests", { method: "POST", body: { state: random(), challenge: createHash("sha256").update(verifier).digest("base64url"), redirectURI } });
  const code = new URL(await approveBrowser(data.authorizationURL)).searchParams.get("code");
  await expect(api.request("/oauth/token", { method: "POST", body: { code, verifier: random(), redirectURI } })).rejects.toThrow("400");
  await api.request("/oauth/token", { method: "POST", body: { code, verifier, redirectURI } });
  await expect(api.request("/oauth/token", { method: "POST", body: { code, verifier, redirectURI } })).rejects.toThrow("400");
});

test("protects admin changes, callback destinations, private API and cross-origin requests", async () => {
  const emulator = server(), api = new CorporateAPI(emulator.baseURL);
  await expect(api.request("/api/config")).rejects.toThrow("/login");
  expect((await fetch(`${emulator.baseURL}/admin/state`, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"level":"red"}' })).status).toBe(403);
  expect((await fetch(`${emulator.baseURL}/health`, { headers: { Origin: "https://untrusted.example" } })).status).toBe(403);
  await expect(api.request("/oauth/requests", { method: "POST", body: { state: random(), challenge: random(), redirectURI: "https://untrusted.example/callback" } })).rejects.toThrow("400");
});

test("scopes the skill catalogue by account and enforces revocation", async () => {
  const emulator = server(), api = new CorporateAPI(emulator.baseURL);
  const { accessToken: token } = await signIn(emulator, "analyst");
  expect((await api.request("/api/skills", { token })).data.skills.map((s) => s.id)).toEqual(["corp-data-quality"]);
  await expect(api.request("/api/skills/corp-code-review", { token })).rejects.toThrow("403");
  await api.request("/oauth/revoke", { token, method: "POST", body: {} });
  await expect(api.request("/api/config", { token })).rejects.toThrow("/login");
});

test("MCP catalog is role-scoped and cannot redirect personal tokens", async () => {
  const emulator = server(), api = new CorporateAPI(emulator.baseURL);
  const { accessToken: token } = await signIn(emulator, "analyst");
  const catalog = validateMCPCatalog((await api.request("/api/mcps", { token })).data, emulator.baseURL);
  expect(catalog.map((item) => item.id)).toEqual(["confluence"]);
  expect(() => validateMCPCatalog({ servers: [{ ...catalog[0], url: "https://attacker.example/mcp/confluence" }] }, emulator.baseURL)).toThrow();
  const root = await folder();
  const configs = await saveMCPSelection(root, ["confluence"], catalog, new Map([["confluence", "demo-confluence-token"]]));
  expect(configs[0].config.headers.Authorization).toBe(`Bearer {env:${mcpEnvName(root, "confluence")}}`);
  expect(process.env[mcpEnvName(root, "confluence")]).toBe("demo-confluence-token");
  expect(await exists(join(root, "mcp-tokens/confluence"))).toBeNull();
  expect(readMCPState(root, catalog)).toEqual(configs);
  const response = await fetch(`${emulator.baseURL}/mcp/confluence`, { method: "POST", headers: { Authorization: `Bearer ${process.env[mcpEnvName(root, "confluence")]}`, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  expect((await response.json()).result.tools[0].name).toBe("find_pages");
  await clearMCP(root);
  expect(await exists(join(root, "mcp-tokens/confluence"))).toBeNull();
  expect(process.env[mcpEnvName(root, "confluence")]).toBeUndefined();
});

test("one browser form captures only requested MCP tokens and never echoes them", async () => {
  const page = await captureSecrets([{ id: "jira", name: "Jira", description: "Задачи" }, { id: "confluence", name: "Confluence", description: "Страницы" }], { timeoutMs: 2000 });
  try {
    expect(new URL(page.url).hostname).toBe("127.0.0.1");
    const html = await (await fetch(page.url)).text();
    expect(html).toContain("Jira");
    expect(html).toContain("Confluence");
    expect(html).not.toContain("demo-jira-token");
    const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(csrf).toBeTruthy();
    const incompleteBody = new URLSearchParams({ csrf, "token:jira": "demo-jira-token" });
    const completeBody = new URLSearchParams({ csrf, "token:jira": "demo-jira-token", "token:confluence": "demo-confluence-token" });
    const invalid = await fetch(page.url, { method: "POST", headers: { Origin: "https://attacker.example", "Content-Type": "application/x-www-form-urlencoded" }, body: completeBody });
    expect(invalid.status).toBe(403);
    const missingCSRF = await fetch(page.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "token%3Ajira=demo-jira-token&token%3Aconfluence=demo-confluence-token" });
    expect(missingCSRF.status).toBe(403);
    const incomplete = await fetch(page.url, { method: "POST", headers: { Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: incompleteBody });
    expect(incomplete.status).toBe(400);
    const response = await fetch(page.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: completeBody });
    expect(response.status).toBe(200);
    expect(await response.text()).not.toContain("demo-jira-token");
    expect([...await page.result]).toEqual([["jira", "demo-jira-token"], ["confluence", "demo-confluence-token"]]);
  } finally { page.cancel(); }
});

test("browser waits for MCP setup and shows a safe result page", async () => {
  let submitted = false;
  const page = await captureSecrets([{ id: "jira", name: "Jira", description: "Задачи" }], {
    timeoutMs: 2000,
    onSubmit: async (tokens) => {
      expect(tokens.get("jira")).toBe("private-token");
      await new Promise((resolve) => setTimeout(resolve, 30));
      submitted = true;
      return { kind: "error", title: "Не все MCP подключились", message: "Попробуйте снова", items: [{ name: "<Jira>", status: "failed", detail: "Токен отклонён (HTTP 401)" }] };
    },
  });
  try {
    const html = await (await fetch(page.url)).text();
    const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
    const response = await fetch(page.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, "token:jira": "private-token" }) });
    expect(response.status).toBe(200);
    const result = await response.text();
    expect(submitted).toBe(true);
    expect(result).toContain("Не все MCP подключились");
    expect(result).toContain("&lt;Jira&gt;");
    expect(result).toContain("Токен отклонён (HTTP 401)");
    expect(result).not.toContain("private-token");
    expect([...await page.result]).toEqual([["jira", "private-token"]]);
  } finally { page.cancel(); }
});

test("patches only its provider, preserves JSONC comments and stores no token in config", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "state"), serverURL = "http://127.0.0.1:4310";
  const original = '{\n // Keep my comment\n "model": "personal/code",\n "providers": { "personal": { "name": "Personal" } },\n "share": "manual",\n}\n';
  await atomicWrite(configPath, original);
  const first = await applyConfig({ configPath, stateDir, serverURL, envelope: envelope(serverURL) });
  const text = await readFile(configPath, "utf8"), config = parseConfig(text);
  expect(text).toContain("// Keep my comment");
  expect(config.model).toBe("personal/code");
  expect(config.providers.personal.name).toBe("Personal");
  expect(config.share).toBe("manual");
  expect(config.providers.corporate.settings.apiKey).toBe(`{file:${join(stateDir, "access-token")}}`);
  expect(await readFile(`${configPath}.before-corporate.bak`, "utf8")).toBe(original);
  expect((await stat(configPath)).mode & 0o777).toBe(0o600);
  const before = (await stat(configPath)).mtimeMs;
  expect((await applyConfig({ configPath, stateDir, serverURL, envelope: envelope(serverURL), previous: first })).changed).toBe(false);
  expect((await stat(configPath)).mtimeMs).toBe(before);
});

test("provider token reference changes on renewal and survives config sync", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "state"), serverURL = "http://127.0.0.1:4310";
  await atomicWrite(configPath, "{}");
  const first = await applyConfig({ configPath, stateDir, serverURL, envelope: envelope(serverURL) });
  expect(await rotateProviderTokenReference(configPath, stateDir)).toBe(true);
  expect(parseConfig(await readFile(configPath, "utf8")).providers.corporate.settings.apiKey).toBe(`{file:${join(stateDir, "access-token-next")}}`);
  expect((await applyConfig({ configPath, stateDir, serverURL, envelope: envelope(serverURL), previous: first })).changed).toBe(false);
  expect(await rotateProviderTokenReference(configPath, stateDir)).toBe(true);
  expect(parseConfig(await readFile(configPath, "utf8")).providers.corporate.settings.apiKey).toBe(`{file:${join(stateDir, "access-token")}}`);
});

test("Kilo config keeps other providers and MCPs while managing only corporate entries", async () => {
  const root = await folder(), configPath = join(root, "kilo.jsonc"), stateDir = join(root, "corporate-state"), serverURL = "http://127.0.0.1:4310";
  const original = '{\n // keep this\n "plugin": ["/tmp/company"],\n "model": "corporate/code", "small_model": "personal/small",\n "provider": {"personal":{"name":"Personal"}},\n "mcp": {"personal":{"type":"remote","url":"https://example.test/mcp"}}\n}\n';
  await atomicWrite(configPath, original);
  await applyConfig({ configPath, stateDir, serverURL, envelope: envelope(serverURL), client: "kilo" });
  const provider = parseConfig(await readFile(configPath, "utf8")).provider;
  expect(provider.personal.name).toBe("Personal");
  expect(provider.corporate.npm).toBe("@ai-sdk/openai-compatible");
  expect(provider.corporate.options.apiKey).toBe(`{file:${join(stateDir, "access-token")}}`);
  expect(provider.corporate.options.baseURL).toBe(`${serverURL}/v1`);
  expect(await readFile(`${configPath}.before-corporate.bak`, "utf8")).toBe(original);
  await syncKiloMCP(configPath, stateDir, [{ name: "corp_jira", config: { url: `${serverURL}/mcp/jira`, headers: { Authorization: `Bearer {env:${mcpEnvName(stateDir, "jira")}}` } } }]);
  const text = await readFile(configPath, "utf8"), config = parseConfig(text);
  expect(text).toContain("// keep this");
  expect(config.mcp.personal.url).toBe("https://example.test/mcp");
  expect(config.mcp.corp_jira.headers.Authorization).toBe(`Bearer {env:${mcpEnvName(stateDir, "jira")}}`);
  await syncKiloMCP(configPath, stateDir, []);
  await removeProvider(configPath, "kilo");
  const clean = parseConfig(await readFile(configPath, "utf8"));
  expect(clean.provider).toEqual({ personal: { name: "Personal" } });
  expect(clean.mcp).toEqual({ personal: { type: "remote", url: "https://example.test/mcp" } });
  expect(clean.model).toBeUndefined();
  expect(clean.small_model).toBe("personal/small");
});

test("OpenCode config stores only MCP environment references", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "corporate-state");
  await atomicWrite(configPath, '{\n // keep this\n "mcp":{"servers":{"personal":{"type":"remote","url":"https://example.test/mcp"}}}\n}\n');
  const catalog = [{ id: "jira", name: "Jira", description: "Задачи", url: "http://127.0.0.1:4310/mcp/jira", auth: "personal_token" }];
  const configs = saveMCPSelection(stateDir, ["jira"], catalog, new Map([["jira", "demo-jira-token"]]));
  await syncOpenCodeMCP(configPath, stateDir, configs);
  const text = await readFile(configPath, "utf8");
  expect(text).toContain("// keep this");
  expect(text).not.toContain("demo-jira-token");
  expect(parseConfig(text).mcp.servers.corp_jira.headers.Authorization).toBe(`Bearer {env:${mcpEnvName(stateDir, "jira")}}`);
  await clearMCP(stateDir);
  await syncOpenCodeMCP(configPath, stateDir, []);
  expect(parseConfig(await readFile(configPath, "utf8")).mcp.servers.personal.url).toBe("https://example.test/mcp");
  expect(parseConfig(await readFile(configPath, "utf8")).mcp.servers.corp_jira).toBeUndefined();
});

test("removes the whole corporate provider block when it is the only provider", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc");
  await atomicWrite(configPath, '{\n  // Keep the plugin\n  "plugins": ["github:igorfltv/opencode_corp#main"],\n  "providers": { "corporate": { "name": "Demo" } }\n}\n');
  await removeProvider(configPath);
  const text = await readFile(configPath, "utf8");
  expect(text).toContain("// Keep the plugin");
  expect(parseConfig(text)).toEqual({ plugins: ["github:igorfltv/opencode_corp#main"] });
  await atomicWrite(configPath, '{"providers":{"personal":{"name":"Personal"},"corporate":{"name":"Demo"}}}');
  await removeProvider(configPath);
  expect(parseConfig(await readFile(configPath, "utf8")).providers).toEqual({ personal: { name: "Personal" } });
  await atomicWrite(configPath, '{"plugins":["github:igorfltv/opencode_corp#main"],"providers":{}}');
  await removeProvider(configPath);
  expect(parseConfig(await readFile(configPath, "utf8"))).toEqual({ plugins: ["github:igorfltv/opencode_corp#main"] });
});

test("startup without a valid login clears stale provider and credentials", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), stateDir = join(root, "corporate-state");
  await atomicWrite(configPath, '{"plugins":["github:igorfltv/opencode_corp#main"],"providers":{"corporate":{"name":"Demo"}}}');
  await atomicWrite(join(stateDir, "credential.json"), JSON.stringify({ accessToken: random(), expiresAt: Date.now() - 1000, user: { name: "Expired" } }));
  await atomicWrite(join(stateDir, "access-token"), "stale-token");
  await atomicWrite(join(stateDir, "access-token-next"), "stale-token");
  await atomicWrite(join(stateDir, "sync.json"), JSON.stringify({ revision: 1 }));
  const runtime = new CorporateRuntime(optionsFromEnv({}, { profileDir: root, serverURL: "http://127.0.0.1:4310" }), { notify: async () => {} });
  try {
    await runtime.start();
    expect(runtime.status().authenticated).toBe(false);
    expect(parseConfig(await readFile(configPath, "utf8"))).toEqual({ plugins: ["github:igorfltv/opencode_corp#main"] });
    expect(await readFile(join(stateDir, "access-token"), "utf8")).toBe("");
    expect(await readFile(join(stateDir, "access-token-next"), "utf8")).toBe("");
    expect(await exists(join(stateDir, "credential.json"))).toBeNull();
    expect(await exists(join(stateDir, "sync.json"))).toBeNull();
  } finally { runtime.dispose(); }
});

test("rejects executable settings, unapproved hosts, malformed JSONC and config rollback", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), serverURL = "http://127.0.0.1:4310";
  const dangerous = envelope(serverURL); dangerous.config.plugins = ["evil"];
  expect(() => validateConfig(dangerous, serverURL)).toThrow();
  const forwarded = envelope(serverURL); forwarded.config.providers.corporate.settings.baseURL = "https://other.example/v1";
  expect(() => validateConfig(forwarded, serverURL)).toThrow();
  const interpolated = envelope(serverURL); interpolated.config.providers.corporate.name = "{file:/private/file}";
  expect(() => validateConfig(interpolated, serverURL)).toThrow();
  await atomicWrite(configPath, "{ broken");
  await expect(applyConfig({ configPath, stateDir: root, serverURL, envelope: envelope(serverURL) })).rejects.toThrow("не изменён");
  expect(await readFile(configPath, "utf8")).toBe("{ broken");
  await atomicWrite(configPath, "{}");
  await expect(applyConfig({ configPath, stateDir: root, serverURL, envelope: envelope(serverURL), previous: { revision: 2 } })).rejects.toThrow("старую");
});

test("validates every skill and preserves modified local skills", async () => {
  const root = await folder();
  const content = "---\nname: corp-safe\ndescription: safe\n---\nSafe instructions";
  const catalog = validateCatalog({ skills: [{ id: "corp-safe", name: "Safe", description: "Safe", version: "1", sha256: digest(content) }] });
  const api = { request: async () => ({ data: { content } }) };
  const input = { ids: ["corp-safe"], catalog, api, token: "test", skillsDir: root };
  expect(await installSkills(input)).toEqual(["corp-safe"]);
  await atomicWrite(join(root, "corp-safe", "SKILL.md"), "Local edits");
  await expect(installSkills(input)).rejects.toThrow("изменён локально");
  expect(await readFile(join(root, "corp-safe", "SKILL.md"), "utf8")).toBe("Local edits");
  expect(() => validateCatalog({ skills: [{ ...catalog[0], id: "../escape" }] })).toThrow();
  await expect(installSkills({ ...input, ids: ["corp-other"] })).rejects.toThrow("вне доступного");
  await expect(installSkills({ ...input, api: { request: async () => ({ data: { content: "tampered" } }) } })).rejects.toThrow("Контрольная сумма");
});

test("does not write skills through a symlink", async () => {
  const root = await folder(), outside = await folder();
  await symlink(outside, join(root, "corp-safe"));
  const content = "---\nname: corp-safe\ndescription: safe\n---\nSafe";
  const catalog = [{ id: "corp-safe", sha256: digest(content) }];
  await expect(installSkills({ ids: ["corp-safe"], catalog, api: { request: async () => ({ data: { content } }) }, skillsDir: root })).rejects.toThrow("ссылку");
});

test("load traffic light notifies on transitions only, including an unavailable server", async () => {
  const root = await folder(), notices = [];
  let level = "green", fail = false;
  const runtime = new CorporateRuntime({ stateDir: root }, { api: { request: async () => { if (fail) throw Error("offline"); return { data: { level, message: level, queue: 1, observedAt: Date.now() } }; } }, notify: async (text) => notices.push(text) });
  runtime.credential = { accessToken: random(), expiresAt: Date.now() + 100000, user: { name: "Test" } };
  await runtime.pollLoad(); await runtime.pollLoad();
  level = "red"; await runtime.pollLoad(); await runtime.pollLoad();
  fail = true; await runtime.pollLoad(); await runtime.pollLoad();
  expect(notices).toHaveLength(3);
  expect(notices[0]).toContain("🟢"); expect(notices[1]).toContain("🔴"); expect(notices[2]).toContain("⚪");
  expect(runtime.status().load.level).toBe("unknown"); runtime.dispose();
});

test("defaults to an hourly configuration refresh", () => {
  expect(optionsFromEnv({}).refreshMs).toBe(3600000);
  expect(optionsFromEnv({}).loadPollMs).toBe(30000);
  expect(() => optionsFromEnv({ CORP_SERVER_URL: "http://public.example" })).toThrow("HTTPS");
  const configured = optionsFromEnv({}, { profileDir: "/tmp/corporate-main", connectionFile: "/tmp/opencode/service.json", serverURL: "http://127.0.0.1:4310" });
  expect(configured.configPath).toBe("/tmp/corporate-main/opencode.jsonc");
  expect(configured.connectionFile).toBe("/tmp/opencode/service.json");
  const github = optionsFromEnv({ XDG_CONFIG_HOME: "/tmp/github-config", XDG_STATE_HOME: "/tmp/github-state" });
  expect(github.configPath).toBe("/tmp/github-config/opencode/opencode.jsonc");
  expect(github.connectionFile).toBe("/tmp/github-state/opencode/service.json");
  expect(optionsFromEnv({ OPENCODE_CONFIG_DIR: "/tmp/custom-opencode" }).configPath).toBe("/tmp/custom-opencode/opencode.jsonc");
  const kilo = optionsFromEnv({ XDG_CONFIG_HOME: "/tmp/config", KILO_CONFIG_DIR: "/tmp/kilo-profile", CORP_KILO_PROFILE_DIR: "/tmp/corp-kilo" }, { client: "kilo" });
  expect(kilo.configPath).toBe("/tmp/corp-kilo/kilo.jsonc");
  expect(kilo.skillsDir).toBe("/tmp/corp-kilo/skills");
});

test("an old load response cannot invalidate a newly logged-in account", async () => {
  const root = await folder(); let reject;
  const runtime = new CorporateRuntime({ stateDir: root }, { api: { request: () => new Promise((_, no) => { reject = no; }) }, notify: async () => {} });
  runtime.credential = { accessToken: random(), expiresAt: Date.now() + 10000, user: { name: "Old" } };
  const pending = runtime.pollLoad();
  while (!reject) await Bun.sleep(0);
  const replacement = { accessToken: random(), expiresAt: Date.now() + 10000, user: { name: "New" } };
  runtime.authGeneration++;
  runtime.credential = replacement;
  runtime.load = { level: "green", message: "New account", checkedAt: Date.now() };
  reject(new Unauthorized()); await pending;
  expect(runtime.credential).toEqual(replacement);
  expect(runtime.load.level).toBe("green");
  let resolve;
  runtime.api.request = () => new Promise((yes) => { resolve = yes; });
  const late = runtime.pollLoad();
  while (!resolve) await Bun.sleep(0);
  runtime.authGeneration++;
  runtime.credential = null;
  runtime.load = { level: "unknown", message: "Logged out", checkedAt: null };
  resolve({ data: { level: "red", message: "Late response", observedAt: Date.now() } });
  await late;
  expect(runtime.load.message).toBe("Logged out"); runtime.dispose();
});

test("logout still revokes the token when local JSONC is malformed", async () => {
  const root = await folder(), configPath = join(root, "opencode.jsonc"), revoked = [];
  await atomicWrite(configPath, "{ malformed");
  const runtime = new CorporateRuntime({ stateDir: root, configPath }, { api: { request: async (path) => revoked.push(path) } });
  runtime.credential = { accessToken: random(), refreshToken: random(), expiresAt: Date.now() + 10000, user: { name: "Test" } };
  await expect(runtime.logout()).rejects.toThrow("не изменён");
  expect(runtime.credential).toBeNull(); expect(revoked).toEqual(["/oauth/revoke"]);
  expect(await readFile(configPath, "utf8")).toBe("{ malformed"); runtime.dispose();
});
