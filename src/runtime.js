import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { rm } from "node:fs/promises";
import { atomicWrite, exists, readJSON, serial, trustedURL } from "./io.js";
import { CorporateAPI, Unauthorized } from "./api.js";
import { applyConfig, removeProvider, validateConfig } from "./config.js";
import { validateCatalog, installSkills } from "./skills.js";
import { validateMCPCatalog, readMCPState, saveMCPSelection, clearMCP } from "./mcp.js";
import { captureSecret } from "./secret-page.js";
import { startLogin } from "./login.js";
import { openBrowser, notifyDesktop } from "./desktop.js";
import { OpenCodeBridge } from "./bridge.js";

export const lights = { green: "🟢", yellow: "🟡", red: "🔴", unknown: "⚪" };
const validCredential = (value) => value && typeof value.accessToken === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value.accessToken) && Number.isFinite(value.expiresAt) && typeof value.user?.name === "string";
export class CorporateRuntime {
  constructor(options, adapters = {}) {
    this.options = options;
    this.api = adapters.api ?? new CorporateAPI(options.serverURL);
    this.bridge = adapters.bridge ?? new OpenCodeBridge(options.connectionFile);
    this.applyConfig = adapters.applyConfig ?? applyConfig;
    this.removeProvider = adapters.removeProvider ?? removeProvider;
    this.syncMCP = adapters.syncMCP;
    this.open = adapters.open ?? openBrowser;
    this.desktop = adapters.notify ?? notifyDesktop;
    this.queue = serial();
    this.listeners = new Set();
    this.jobs = new Set();
    this.forms = new Map();
    this.abort = new AbortController();
    this.state = {};
    this.authGeneration = 0;
    this.load = { level: "unknown", message: "Нет свежих данных", checkedAt: null };
    this.mcpCatalog = [];
    this.mcpConfigs = [];
    this.mcpReloaders = new Set();
  }
  async start() {
    this.credential = await readJSON(join(this.options.stateDir, "credential.json"));
    if (!validCredential(this.credential) || this.credential.expiresAt <= Date.now()) this.credential = null;
    this.state = await readJSON(join(this.options.stateDir, "sync.json"), {});
    if (!this.credential) {
      await rm(join(this.options.stateDir, "credential.json"), { force: true });
      await rm(join(this.options.stateDir, "sync.json"), { force: true });
      const tokenPath = join(this.options.stateDir, "access-token");
      if (await exists(tokenPath)) await atomicWrite(tokenPath, "");
      await this.removeProvider(this.options.configPath, this.options.client);
      await clearMCP(this.options.stateDir);
      await this.syncMCP?.([]);
      this.state = {};
    }
    if (this.authenticated()) await this.refreshMCPCatalog().catch(() => {});
    this.configTimer = setInterval(() => this.backgroundRefresh(), this.options.refreshMs);
    this.loadTimer = setInterval(() => this.pollLoad().catch(() => {}), this.options.loadPollMs);
    this.configTimer.unref(); this.loadTimer.unref();
    if (this.authenticated()) { this.backgroundRefresh(); this.pollLoad().catch(() => {}); }
  }
  authenticated() { return Boolean(this.credential && this.credential.expiresAt > Date.now()); }
  token() { if (!this.authenticated()) throw new Unauthorized(); return this.credential.accessToken; }
  status() {
    return { authenticated: this.authenticated(), user: this.authenticated() ? this.credential.user : null,
      expiresAt: this.authenticated() ? this.credential.expiresAt : null,
      config: { revision: this.state.revision ?? null, checkedAt: this.state.checkedAt ?? null, lastError: this.state.lastError ?? null },
      load: { ...this.load }, refreshMinutes: this.options.refreshMs / 60000 };
  }
  async notice(message, level = "info") {
    if (this.abort.signal.aborted) return;
    const event = { message, level, at: Date.now() };
    await Promise.allSettled([this.desktop(message), ...[...this.listeners].map((listener) => Promise.resolve().then(() => listener(event)))]);
  }
  async persistState() { await atomicWrite(join(this.options.stateDir, "sync.json"), JSON.stringify(this.state, null, 2)); }
  async refresh() {
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.queue(async () => {
      const token = this.token();
      try {
        const response = await this.api.request("/api/config", { token, etag: this.state.etag, signal: this.abort.signal });
        if (response.unchanged) this.state = { ...this.state, checkedAt: new Date().toISOString(), lastError: null };
        else {
          const applied = await this.applyConfig({ ...this.options, envelope: response.data, previous: this.state.revision ? this.state : null });
          this.state = { ...applied, etag: response.etag, lastError: null };
          if (applied.changed) await this.notice(`Корпоративный конфиг обновлён: версия ${applied.revision}`, "success");
        }
        await this.persistState();
        await this.refreshMCPCatalog().catch(() => {});
        return this.state;
      } catch (error) {
        if (error instanceof Unauthorized) await this.invalidate();
        this.state.lastError = error instanceof Unauthorized ? error.message : "Не удалось обновить конфиг; сохранена предыдущая версия";
        await this.persistState();
        throw error;
      }
    }).finally(() => { this.refreshing = null; });
    return this.refreshing;
  }
  async backgroundRefresh() {
    if (!this.credential) return;
    try { await this.refresh(); this.syncFailed = false; }
    catch { if (!this.syncFailed) { this.syncFailed = true; await this.notice(this.state.lastError ?? "Нужен повторный /login", "warning"); } }
  }
  async invalidate() {
    this.credential = null;
    await Promise.all([rm(join(this.options.stateDir, "credential.json"), { force: true }), atomicWrite(join(this.options.stateDir, "access-token"), "")]);
    await clearMCP(this.options.stateDir);
    this.mcpConfigs = [];
    await this.reloadMCP();
  }
  async reloadMCP() { await this.syncMCP?.(this.mcpConfigs); await Promise.all([...this.mcpReloaders].map((reload) => reload())); }
  async refreshMCPCatalog() {
    const { data } = await this.api.request("/api/mcps", { token: this.token(), signal: this.abort.signal });
    const catalog = validateMCPCatalog(data, this.options.serverURL);
    const configs = await readMCPState(this.options.stateDir, catalog);
    this.mcpCatalog = catalog;
    this.mcpConfigs = configs;
    await this.reloadMCP();
    return catalog;
  }
  async pollLoad() {
    if (this.polling || !this.credential) return;
    this.polling = true;
    const polledToken = this.credential?.accessToken;
    let next;
    try {
      const { data } = await this.api.request("/api/load", { token: this.token(), signal: this.abort.signal });
      if (!["green", "yellow", "red"].includes(data?.level) || typeof data.message !== "string" || data.message.length > 250 || !Number.isFinite(data.observedAt) || Math.abs(Date.now() - data.observedAt) > 90000) throw new Error("Нет свежих данных нагрузки");
      next = { level: data.level, message: data.message, queue: data.queue, checkedAt: data.observedAt };
    } catch (error) {
      next = { level: "unknown", message: error instanceof Unauthorized ? "Требуется /login" : "Сервер нагрузки недоступен", checkedAt: Date.now() };
      if (error instanceof Unauthorized) await this.queue(() => this.credential?.accessToken === polledToken ? this.invalidate() : undefined);
    } finally { this.polling = false; }
    if (this.abort.signal.aborted) return;
    if (this.credential && this.credential.accessToken !== polledToken) return;
    if (!this.credential && next.level !== "unknown") return;
    const changed = next.level !== this.load.level;
    this.load = next;
    if (changed) await this.notice(`${lights[next.level]} Инференс: ${next.message}`, { green: "success", yellow: "warning", red: "error", unknown: "warning" }[next.level]);
  }
  track(promise, sessionID) {
    this.jobs.add(promise);
    promise.catch(async (error) => {
      if (!this.abort.signal.aborted) {
        await this.bridge.message(sessionID, "Корпоративный плагин", error.message).catch(() => {});
        await this.notice(error.message, "error");
      }
    }).finally(() => this.jobs.delete(promise));
  }
  async login(sessionID, reload = async () => {}) {
    if (this.loginFlow || this.loginPending) throw new Error("Вход уже открыт в браузере");
    this.loginPending = true;
    const generation = this.authGeneration;
    let flow;
    try { flow = await startLogin(this.api); } finally { this.loginPending = false; }
    if (generation !== this.authGeneration || this.abort.signal.aborted) { flow.cancel(); return; }
    this.loginFlow = flow;
    const clientName = this.options.client === "kilo" ? "Kilo" : "OpenCode";
    const form = await this.bridge.form(sessionID, `Вход в корпоративный ${clientName}`, [
      { type: "external", key: "login", title: "Открыть страницу входа", url: flow.url },
      { type: "string", key: "waiting", title: `Вход в корпоративный ${clientName}`, description: `В открывшемся браузере выберите тестовую учётную запись. Пароль не нужен. Если браузер не открылся, скопируйте адрес: ${flow.url}`, custom: false, options: [{ value: "waiting", label: "Ожидаю входа в браузере" }] },
    ]).catch((error) => { flow.cancel(); this.loginFlow = null; throw error; });
    this.open(flow.url).catch(() => this.notice(`Откройте ссылку входа в форме ${clientName}`, "info"));
    const cancellation = new AbortController();
    this.bridge.wait(sessionID, form.id, AbortSignal.any([this.abort.signal, cancellation.signal])).then((answer) => { if (answer === null) flow.cancel(); }).catch(() => {});
    this.track((async () => {
      try {
        const result = await flow.result;
        if (!validCredential(result) || result.expiresAt <= Date.now()) throw new Error("Сервер вернул некорректную авторизацию");
        validateConfig(result.configuration, this.options.serverURL);
        await this.queue(async () => {
          if (generation !== this.authGeneration || this.abort.signal.aborted) throw new Error("Вход отменён");
          this.credential = { accessToken: result.accessToken, expiresAt: result.expiresAt, user: result.user };
          await clearMCP(this.options.stateDir);
          this.mcpConfigs = [];
          await this.reloadMCP();
          await atomicWrite(join(this.options.stateDir, "credential.json"), JSON.stringify(this.credential));
          await atomicWrite(join(this.options.stateDir, "access-token"), this.credential.accessToken);
          this.state = { ...(await this.applyConfig({ ...this.options, envelope: result.configuration })), lastError: null };
          await this.persistState();
        });
        await reload();
        await this.bridge.message(sessionID, "Вход выполнен", `${result.user.name}. Конфиг версии ${this.state.revision} применён. Доступны /refresh_config и /skills_load.`);
        await this.notice("Вход выполнен; корпоративный конфиг применён", "success");
        await this.pollLoad();
      } finally {
        cancellation.abort();
        await this.bridge.cancel(sessionID, form.id);
        this.loginFlow = null;
      }
    })(), sessionID);
  }
  async skills(sessionID, reload) {
    if (this.forms.has(sessionID)) throw new Error("Форма выбора skills уже открыта");
    const token = this.token();
    const { data } = await this.api.request("/api/skills", { token, signal: this.abort.signal });
    const catalog = validateCatalog(data);
    if (!catalog.length) return this.bridge.message(sessionID, "Корпоративные skills", "Для вашей учётной записи нет доступных skills.");
    const form = await this.bridge.form(sessionID, "Загрузить корпоративные skills", [{
      type: "multiselect", key: "skills", title: "Выберите нужные skills", description: "Загрузятся только отмеченные skills. Уже установленные останутся на месте.",
      custom: false, minItems: 0, default: [], options: catalog.map((skill) => ({ value: skill.id, label: `${skill.name} · ${skill.version}`, description: skill.description })),
    }]);
    const controller = new AbortController();
    this.forms.set(sessionID, { form, controller });
    this.track((async () => {
      try {
        const signal = AbortSignal.any([this.abort.signal, controller.signal, AbortSignal.timeout(300000)]);
        const answer = await this.bridge.wait(sessionID, form.id, signal);
        if (answer === null) return;
        const installed = await this.queue(async () => {
          if (this.token() !== token) throw new Error("Учётная запись изменилась; откройте /skills_load снова");
          return installSkills({ ids: answer.skills ?? [], catalog, api: this.api, token, skillsDir: this.options.skillsDir, signal });
        });
        await reload();
        await this.bridge.message(sessionID, "Skills загружены", installed.length ? installed.join("\n") : "Ничего не выбрано.");
      } finally { this.forms.delete(sessionID); await this.bridge.cancel(sessionID, form.id); }
    })(), sessionID);
  }
  async mcps(sessionID, reload = async () => {}) {
    if (this.forms.has(sessionID)) throw new Error("Форма выбора уже открыта");
    const token = this.token();
    const catalog = await this.refreshMCPCatalog();
    if (!catalog.length) return this.bridge.message(sessionID, "Корпоративные MCP", "Для вашей учётной записи нет доступных MCP.");
    const selected = this.mcpConfigs.map(({ name }) => name.slice(5));
    const form = await this.bridge.form(sessionID, "Подключить корпоративные MCP", [{
      type: "multiselect", key: "mcps", title: "Выберите MCP", description: `Личные токены вводятся отдельно в локальном браузере, не в чате ${this.options.client === "kilo" ? "Kilo" : "OpenCode"}.`,
      custom: false, minItems: 0, default: selected,
      options: catalog.map((item) => ({ value: item.id, label: item.name, description: item.description })),
    }]);
    const controller = new AbortController();
    this.forms.set(sessionID, { form, controller });
    this.track((async () => {
      try {
        const signal = AbortSignal.any([this.abort.signal, controller.signal, AbortSignal.timeout(300000)]);
        const answer = await this.bridge.wait(sessionID, form.id, signal);
        if (answer === null) return;
        const ids = answer.mcps ?? [];
        const tokens = new Map();
        for (const id of ids) {
          const item = catalog.find((entry) => entry.id === id);
          if (!item) throw new Error("Выбран MCP вне доступного каталога");
          if (selected.includes(id)) continue;
          const page = await captureSecret(`Личный токен для ${item.name}`);
          const cancel = () => page.cancel();
          signal.addEventListener("abort", cancel, { once: true });
          let notice;
          try {
            notice = await this.bridge.form(sessionID, `Токен ${item.name}`, [{ type: "external", key: "token", title: "Открыть защищённую локальную форму", url: page.url }]);
            await this.open(page.url).catch(() => {});
            tokens.set(id, await page.result);
          } finally {
            signal.removeEventListener("abort", cancel);
            page.cancel();
            if (notice) await this.bridge.cancel(sessionID, notice.id);
          }
        }
        await this.queue(async () => {
          if (this.token() !== token) throw new Error("Учётная запись изменилась; откройте /mcps_load снова");
          this.mcpConfigs = await saveMCPSelection(this.options.stateDir, ids, catalog, tokens);
          await this.reloadMCP();
        });
        await reload();
        await this.bridge.message(sessionID, "MCP настроены", ids.length ? `${ids.map((id) => catalog.find((item) => item.id === id).name).join("\n")}\nПроверьте подключение через /mcps.` : "Все корпоративные MCP отключены.");
      } finally { this.forms.delete(sessionID); await this.bridge.cancel(sessionID, form.id); }
    })(), sessionID);
  }
  async logout() {
    this.authGeneration++;
    this.loginFlow?.cancel();
    for (const { controller } of this.forms.values()) controller.abort();
    await this.queue(async () => {
      const token = this.credential?.accessToken;
      await this.invalidate();
      this.state = {}; await this.persistState();
      this.load = { level: "unknown", message: "Вход не выполнен", checkedAt: null };
      try { await this.removeProvider(this.options.configPath, this.options.client); }
      finally { if (token) await this.api.request("/oauth/revoke", { token, method: "POST", body: {} }).catch(() => {}); }
    });
  }
  dispose() {
    clearInterval(this.configTimer); clearInterval(this.loadTimer);
    this.abort.abort(); this.loginFlow?.cancel();
  }
}

export function optionsFromEnv(env = process.env, settings = {}) {
  const client = settings.client === "kilo" ? "kilo" : "opencode";
  const profile = resolve((client === "kilo" ? env.CORP_KILO_PROFILE_DIR : undefined) ?? env.CORP_PROFILE_DIR ?? settings.profileDir ?? (client === "kilo" ? env.KILO_CONFIG_DIR : env.OPENCODE_CONFIG_DIR) ?? join(env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), client));
  const serviceFile = join(env.XDG_STATE_HOME ?? join(homedir(), ".local", "state"), "opencode", "service.json");
  const interval = (value, fallback) => { const n = Number(value ?? fallback); if (!Number.isFinite(n) || n < 50) throw new Error("Некорректный интервал опроса"); return n; };
  return { client, serverURL: trustedURL(env.CORP_SERVER_URL ?? settings.serverURL ?? "http://127.0.0.1:4310"), configPath: join(profile, client === "kilo" ? "kilo.jsonc" : "opencode.jsonc"), stateDir: join(profile, "corporate-state"), skillsDir: join(profile, "skills"),
    connectionFile: env.CORP_OPENCODE_CONNECTION_FILE ?? settings.connectionFile ?? serviceFile,
    refreshMs: interval(env.CORP_REFRESH_INTERVAL_MS ?? settings.refreshMs, 3600000), loadPollMs: interval(env.CORP_LOAD_INTERVAL_MS ?? settings.loadPollMs, 30000) };
}
