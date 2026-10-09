import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { launch, eventually, root } from "./harness.mjs";
import { createEmulator } from "../server/emulator.js";
import { approveBrowser } from "../tests/helpers.js";
import { parseConfig } from "../src/config.js";
import { atomicWrite, random } from "../src/io.js";

const directory = await mkdtemp(join(tmpdir(), "corporate-auto-login-"));
const browserBin = join(directory, "bin");
const browserLog = join(directory, "browser-urls.log");
await mkdir(browserBin);
for (const name of ["open", "xdg-open"]) {
  const path = join(browserBin, name);
  await writeFile(path, '#!/bin/sh\nprintf "%s\\n" "$1" >> "$CORP_BROWSER_URL_LOG"\n');
  await chmod(path, 0o700);
}
const browserEnv = { PATH: `${browserBin}:${process.env.PATH ?? ""}`, CORP_BROWSER_URL_LOG: browserLog, CORP_NO_BROWSER: "0", CORP_NO_NOTIFICATIONS: "1" };
const firstURL = (offset = 0) => eventually(async () => {
  const lines = (await readFile(browserLog, "utf8").catch(() => "")).split("\n");
  return lines.slice(offset).find((line) => line.includes("/oauth/authorize"));
});

let demo, kilo, emulator;
try {
  demo = await launch({ directory: join(directory, "opencode"), quiet: false, envOverrides: browserEnv });
  const openCodeURL = await firstURL();
  assert.equal((await fetch(await approveBrowser(openCodeURL))).status, 200);
  await eventually(async () => parseConfig(await readFile(demo.configPath, "utf8")).providers?.corporate);
  assert.equal((await demo.request("/api/plugin")).data.find((entry) => entry.id === "company-corporate")?.state.status, "active");
  console.log("PASS installed OpenCode opens SSO automatically and loads its provider without /login");
  await demo.stop(); demo = null;

  emulator = createEmulator({ port: 0, inferenceTokenMs: 2500, apiTokenMs: 60000 });
  const profile = join(directory, "kilo", "config", "kilo");
  const project = join(directory, "kilo", "project");
  await mkdir(profile, { recursive: true });
  await mkdir(project, { recursive: true });
  const configPath = join(profile, "kilo.jsonc");
  await atomicWrite(configPath, JSON.stringify({ plugin: [root], share: "disabled" }, null, 2));
  const password = random();
  const logBefore = (await readFile(browserLog, "utf8")).split("\n").length - 1;
  kilo = spawn(process.env.KILO_BIN ?? "kilo", ["serve", "--hostname", "127.0.0.1", "--port", "0"], {
    cwd: project, stdio: ["ignore", "pipe", "pipe"], env: {
      ...process.env, ...browserEnv, KILO_CONFIG_DIR: profile, KILO_SERVER_PASSWORD: password, KILO_DISABLE_DEFAULT_PLUGINS: "1",
      XDG_CONFIG_HOME: join(directory, "kilo", "config"), XDG_DATA_HOME: join(directory, "kilo", "data"),
      XDG_CACHE_HOME: join(directory, "kilo", "cache"), XDG_STATE_HOME: join(directory, "kilo", "state"),
      CORP_SERVER_URL: emulator.baseURL,
    },
  });
  const kiloURL = await new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error("Kilo did not start within 20s")), 20000);
    kilo.once("error", (error) => { clearTimeout(timer); reject(error); });
    kilo.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Kilo exited: ${code}`)); });
    kilo.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/kilo server listening on (http:\/\/[^\s]+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    kilo.stderr.on("data", () => {});
  });
  const headers = {
    Authorization: `Basic ${Buffer.from(`kilo:${password}`).toString("base64")}`,
    "x-kilo-directory": project,
  };
  assert.equal((await fetch(`${kiloURL}/config`, { headers, signal: AbortSignal.timeout(15000) })).status, 200);
  const kiloLoginURL = await firstURL(logBefore);
  assert.equal((await fetch(await approveBrowser(kiloLoginURL))).status, 200);
  await eventually(async () => parseConfig(await readFile(configPath, "utf8")).provider?.corporate);
  const config = await eventually(async () => {
    const response = await fetch(`${kiloURL}/config`, { headers, signal: AbortSignal.timeout(5000) });
    if (!response.ok) return null;
    return (await response.json()).provider?.corporate ?? null;
  }, 15000);
  assert.equal(config.npm, "@ai-sdk/openai-compatible");
  const tokenPath = join(profile, "corporate-state", "access-token");
  const firstToken = await readFile(tokenPath, "utf8");
  const rotatedToken = await eventually(async () => {
    const current = await readFile(tokenPath, "utf8");
    return current !== firstToken ? current : null;
  }, 10000);
  assert.equal((await fetch(`${emulator.baseURL}/v1/models`, { headers: { Authorization: `Bearer ${rotatedToken}` } })).status, 200);
  const renewedConfig = await (await fetch(`${kiloURL}/config`, { headers, signal: AbortSignal.timeout(5000) })).json();
  assert(renewedConfig.provider.corporate.options.apiKey === rotatedToken, "Kilo did not reload the rotated provider token");
  assert.equal(await Bun.file(join(profile, "corporate-state", "credential.json")).exists(), false);
  console.log("PASS installed Kilo opens SSO automatically and reloads its provider without /login");
  console.log("PASS installed Kilo rotates its inference token without a persisted refresh token");
} catch (error) {
  console.error(error);
  console.error(`Diagnostic profile retained at ${directory}`);
  process.exitCode = 1;
} finally {
  if (demo) await demo.stop();
  kilo?.kill("SIGTERM");
  if (kilo && kilo.exitCode === null) await Promise.race([new Promise((done) => kilo.once("exit", done)), Bun.sleep(3000)]);
  if (kilo?.exitCode === null) kilo.kill("SIGKILL");
  emulator?.stop();
  if (!process.exitCode) await rm(directory, { recursive: true, force: true });
}
