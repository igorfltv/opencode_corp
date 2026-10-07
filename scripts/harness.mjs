import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { atomicWrite, exists, sleep } from "../src/io.js";
import { createEmulator } from "../server/emulator.js";

export const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export async function eventually(fn, timeout = 12000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { const result = await fn(); if (result) return result; } catch (error) { last = error; }
    await sleep(150);
  }
  throw new Error(`Timed out${last ? `: ${last.message}` : ""}`);
}
export async function launch({ directory, port = 0, refreshMs = 3600000, loadPollMs = 30000, quiet = true } = {}) {
  directory = resolve(directory ?? join(root, ".demo"));
  const profile = join(directory, "config", "opencode");
  const project = join(directory, "project");
  await mkdir(profile, { recursive: true, mode: 0o700 });
  await mkdir(project, { recursive: true });
  const configPath = join(profile, "opencode.jsonc");
  if (!await exists(configPath)) await atomicWrite(configPath, `{
  // Изолированный корпоративный демопрофиль. Рабочий конфиг не меняется.
  "model": "corporate/demo-code",
  "share": "disabled",
  "plugins": [${JSON.stringify(root)}]
}\n`);
  if (!await exists(join(project, "README.md"))) await writeFile(join(project, "README.md"), "# Корпоративный OpenCode\n\nНачните с /login. Это отдельная папка для демонстрации.\n");
  const emulator = createEmulator({ port });
  const connectionFile = join(profile, "opencode-connection.json");
  const environment = {
    ...process.env, XDG_CONFIG_HOME: join(directory, "config"), XDG_DATA_HOME: join(directory, "data"),
    XDG_CACHE_HOME: join(directory, "cache"), XDG_STATE_HOME: join(directory, "state"),
    CORP_PROFILE_DIR: profile, CORP_SERVER_URL: emulator.baseURL, CORP_OPENCODE_CONNECTION_FILE: connectionFile,
    CORP_REFRESH_INTERVAL_MS: String(refreshMs), CORP_LOAD_INTERVAL_MS: String(loadPollMs),
    CORP_NO_BROWSER: quiet ? "1" : (process.env.CORP_NO_BROWSER ?? "0"), CORP_NO_NOTIFICATIONS: quiet ? "1" : (process.env.CORP_NO_NOTIFICATIONS ?? "0"),
  };
  const binary = process.env.OPENCODE_BIN ?? "/Applications/OpenCode.app/Contents/Resources/opencode-cli";
  const processHandle = spawn(binary, ["serve", "--hostname", "127.0.0.1", "--port", "0"], { cwd: project, env: environment, stdio: ["ignore", "pipe", "pipe"] });
  let connection;
  try {
    connection = await new Promise((resolve, reject) => {
      let output = "";
      const timer = setTimeout(() => reject(new Error("OpenCode did not start within 10s")), 10000);
      processHandle.on("error", (error) => { clearTimeout(timer); reject(error); });
      processHandle.on("exit", (code) => { clearTimeout(timer); reject(new Error(`OpenCode exited: ${code}`)); });
      processHandle.stderr.on("data", () => {});
      processHandle.stdout.on("data", (chunk) => {
        output += chunk;
        const url = output.match(/server listening on (http:\/\/[^\s]+)/)?.[1];
        const password = output.match(/server password ([^\s]+)/)?.[1];
        if (url && password) { clearTimeout(timer); resolve({ url, password }); output = ""; }
      });
    });
    await atomicWrite(connectionFile, JSON.stringify(connection));
  } catch (error) { processHandle.kill(); emulator.stop(); throw error; }
  const request = async (path, { method = "GET", body } = {}) => {
    const response = await fetch(`${connection.url}${path}`, {
      method, signal: AbortSignal.timeout(12000), headers: { Authorization: `Basic ${Buffer.from(`opencode:${connection.password}`).toString("base64")}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) throw new Error(`OpenCode ${path}: HTTP ${response.status} ${await response.text()}`);
    return response.status === 204 ? null : response.json();
  };
  const stop = async () => {
    processHandle.kill("SIGTERM");
    const timeout = setTimeout(() => processHandle.kill("SIGKILL"), 3000);
    timeout.unref();
    if (processHandle.exitCode === null) await new Promise((done) => processHandle.once("exit", done));
    clearTimeout(timeout); emulator.stop();
  };
  try {
    await eventually(async () => (await request("/api/command")).data?.some((c) => c.name === "login"));
    const { data: session } = await request("/api/session", { method: "POST", body: { title: "Корпоративный плагин · демо", location: { directory: project }, model: { providerID: "corporate", id: "demo-code" } } });
    return { directory, profile, project, configPath, connectionFile, emulator, request, stop, session, url: connection.url,
      command: (name) => request(`/api/session/${session.id}/command`, { method: "POST", body: { name, text: "" } }),
      forms: async () => (await request(`/api/session/${session.id}/form`)).data,
      pair: async () => { const result = await request("/api/pair", { method: "POST" }); return `${connection.url}/auth/connect/${result.code}`; },
    };
  } catch (error) { await stop(); throw error; }
}
