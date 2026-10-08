import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { CorporateRuntime, optionsFromEnv, lights } from "./runtime.js";
import { KiloBridge } from "./kilo-bridge.js";
import { syncKiloMCP } from "./config.js";
import { atomicWrite, random, serial } from "./io.js";

const key = Symbol.for("company.kilo.corporate.control.v4");
const legacyKeys = [Symbol.for("company.kilo.corporate.control.v3"), Symbol.for("company.kilo.corporate.control.v2"), Symbol.for("company.kilo.corporate.control.v1")];
const commands = new Set(["login", "refresh_config", "skills_load", "mcps_load", "logout", "corp_status", "inference_status"]);

export async function startKiloControl(settings = {}, adapters = {}) {
  const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
  const name = `${options.configPath}|${options.serverURL}`;
  for (const legacyKey of legacyKeys) {
    const legacy = globalThis[legacyKey];
    if (!legacy?.has(name)) continue;
    const previous = await legacy.get(name).catch(() => null);
    legacy.delete(name);
    previous?.runtime.dispose();
    previous?.bridge.dispose();
    previous?.server.closeAllConnections();
    previous?.server.close();
  }
  const registry = globalThis[key] ??= new Map();
  if (registry.has(name)) return registry.get(name);
  const ready = boot(options, adapters).catch((error) => { registry.delete(name); throw error; });
  registry.set(name, ready);
  return ready;
}

async function boot(options, adapters) {
  let messages = [];
  const bridge = new KiloBridge(({ title, message }) => messages.push(`${title}: ${message}`), adapters.open);
  const runtime = new CorporateRuntime(options, {
    bridge,
    open: adapters.open,
    notify: adapters.notify,
    syncMCP: (configs) => syncKiloMCP(options.configPath, options.stateDir, configs),
  });
  await runtime.start();
  const secret = random();
  const queue = serial();
  const execute = (command) => queue(async () => {
    messages = [];
    if (command !== "login" && !runtime.authenticated()) return { message: "Сначала выполните /login.", reload: false };
    if (command === "login") await runtime.login("kilo-vscode");
    if (command === "refresh_config") {
      const state = await runtime.refresh();
      await bridge.message(null, "Конфиг актуален", `Версия ${state.revision}. Проверено: ${state.checkedAt}`);
    }
    if (command === "skills_load") await runtime.skills("kilo-vscode", async () => {});
    if (command === "mcps_load") await runtime.mcps("kilo-vscode");
    if (command === "logout") {
      await runtime.logout();
      await bridge.message(null, "Выход выполнен", "Корпоративные токены и провайдер удалены.");
    }
    if (command === "corp_status") {
      const status = runtime.status();
      await bridge.message(null, "Корпоративный статус", `${status.user.name}\nКонфиг: ${status.config.revision ?? "не загружен"}\n${lights[status.load.level]} ${status.load.message}`);
    }
    if (command === "inference_status") {
      await runtime.pollLoad();
      await bridge.message(null, `${lights[runtime.load.level]} Инференс`, runtime.load.message);
    }
    const jobs = await Promise.allSettled([...runtime.jobs]);
    const failure = jobs.find((item) => item.status === "rejected");
    if (failure) throw failure.reason;
    return { message: messages.at(-1) ?? "Команда выполнена.", reload: ["login", "refresh_config", "skills_load", "mcps_load", "logout"].includes(command) };
  });
  const server = createServer(async (request, response) => {
    const port = server.address().port;
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Type": "application/json; charset=utf-8" };
    const credential = Buffer.from(request.headers.authorization?.replace(/^Bearer /, "") ?? "");
    const expected = Buffer.from(secret);
    if (request.headers.host !== `127.0.0.1:${port}` || request.headers.origin || credential.length !== expected.length || !timingSafeEqual(credential, expected)) {
      response.writeHead(403, headers).end(JSON.stringify({ error: "Forbidden" }));
      return;
    }
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, headers).end(JSON.stringify({ ok: true }));
      return;
    }
    const command = request.url?.match(/^\/command\/([a-z_]+)$/)?.[1];
    if (request.method !== "POST" || !commands.has(command)) {
      response.writeHead(404, headers).end(JSON.stringify({ error: "Unknown command" }));
      return;
    }
    try {
      const result = await execute(command);
      response.writeHead(200, headers).end(JSON.stringify(result));
    } catch (error) {
      response.writeHead(500, headers).end(JSON.stringify({ error: error.message ?? "Команда не выполнена" }));
    }
  });
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    server.unref();
    const state = JSON.stringify({ port: server.address().port, secret });
    const ownFile = join(options.stateDir, `control-${process.pid}.json`);
    server.on("close", () => { try { rmSync(ownFile, { force: true }); } catch {} });
    process.once("exit", () => { try { rmSync(ownFile, { force: true }); } catch {} });
    await atomicWrite(ownFile, state);
    await atomicWrite(join(options.stateDir, "control.json"), state);
    void runtime.autoLogin();
    return { runtime, server, bridge };
  } catch (error) {
    server.close(); runtime.dispose(); bridge.dispose();
    throw error;
  }
}
