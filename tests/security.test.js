import { test, expect, afterEach } from "bun:test";
import { mkdtemp, readFile, rm, stat, mkdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { createEmulator } from "../server/emulator.js";
import { CorporateAPI, Unauthorized } from "../src/api.js";
import { startLogin } from "../src/login.js";
import { applyConfig, parseConfig, removeProvider, validateConfig } from "../src/config.js";
import { installSkills, validateCatalog } from "../src/skills.js";
import { optionsFromEnv, CorporateRuntime } from "../src/runtime.js";
import { atomicWrite, digest, exists, random } from "../src/io.js";
import { approveBrowser } from "./helpers.js";

const cleanups = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });
function server() { const result = createEmulator({ port: 0 }); cleanups.push(() => result.stop()); return result; }
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
  expect(callback).not.toContain(result.accessToken);
  expect(result.configuration.revision).toBe(1);
  expect(JSON.stringify(emulator.state.audit)).not.toContain(result.accessToken);
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
  await atomicWrite(join(stateDir, "sync.json"), JSON.stringify({ revision: 1 }));
  const runtime = new CorporateRuntime(optionsFromEnv({}, { profileDir: root, serverURL: "http://127.0.0.1:4310" }), { notify: async () => {} });
  try {
    await runtime.start();
    expect(runtime.status().authenticated).toBe(false);
    expect(parseConfig(await readFile(configPath, "utf8"))).toEqual({ plugins: ["github:igorfltv/opencode_corp#main"] });
    expect(await readFile(join(stateDir, "access-token"), "utf8")).toBe("");
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
});

test("an old load response cannot invalidate a newly logged-in account", async () => {
  const root = await folder(); let reject;
  const runtime = new CorporateRuntime({ stateDir: root }, { api: { request: () => new Promise((_, no) => { reject = no; }) }, notify: async () => {} });
  runtime.credential = { accessToken: random(), expiresAt: Date.now() + 10000, user: { name: "Old" } };
  const pending = runtime.pollLoad();
  const replacement = { accessToken: random(), expiresAt: Date.now() + 10000, user: { name: "New" } };
  runtime.credential = replacement;
  runtime.load = { level: "green", message: "New account", checkedAt: Date.now() };
  reject(new Unauthorized()); await pending;
  expect(runtime.credential).toEqual(replacement);
  expect(runtime.load.level).toBe("green");
  let resolve;
  runtime.api.request = () => new Promise((yes) => { resolve = yes; });
  const late = runtime.pollLoad();
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
  runtime.credential = { accessToken: random(), expiresAt: Date.now() + 10000, user: { name: "Test" } };
  await expect(runtime.logout()).rejects.toThrow("не изменён");
  expect(runtime.credential).toBeNull(); expect(revoked).toEqual(["/oauth/revoke"]);
  expect(await readFile(configPath, "utf8")).toBe("{ malformed"); runtime.dispose();
});
