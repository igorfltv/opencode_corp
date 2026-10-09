import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { rm } from "node:fs/promises";
import { atomicWrite, exists, serial, sleep, trustedURL } from "./io.js";
import { CorporateAPI, Unauthorized } from "./api.js";
import { applyConfig, removeProvider, rotateProviderTokenReference, validateConfig } from "./config.js";
import { validateCatalog, installSkills } from "./skills.js";
import { communityCatalog, installCommunity } from "./community.js";
import { validateMCPCatalog, readMCPState, saveMCPSelection, clearMCP, clearMCPEnv } from "./mcp.js";
import { captureSecrets } from "./secret-page.js";
import { startLogin } from "./login.js";
import { openBrowser, notifyDesktop } from "./desktop.js";
import { OpenCodeBridge } from "./bridge.js";

export const lights = { green: "🟢", yellow: "🟡", red: "🔴", unknown: "⚪" };
const validToken = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value);
const validCredential = (value) => value && validToken(value.accessToken) && validToken(value.inferenceToken) && validToken(value.refreshToken)
  && Number.isFinite(value.expiresAt) && Number.isFinite(value.inferenceExpiresAt) && Number.isFinite(value.refreshExpiresAt)
  && typeof value.user?.name === "string";
export class CorporateRuntime {
  constructor(options, adapters = {}) {
    this.options = options;
    this.api = adapters.api ?? new CorporateAPI(options.serverURL);
    this.bridge = adapters.bridge ?? new OpenCodeBridge(options.connectionFile);
    this.applyConfig = adapters.applyConfig ?? applyConfig;
    this.removeProvider = adapters.removeProvider ?? removeProvider;
    this.syncMCP = adapters.syncMCP;
    this.reloadProvider = adapters.reloadProvider ?? (() => rotateProviderTokenReference(this.options.configPath, this.options.stateDir, this.options.client));
    this.open = adapters.open ?? openBrowser;
    this.desktop = adapters.notify ?? notifyDesktop;
    this.queue = serial();
    this.configWrites = serial();
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
    // A previous release persisted MCP PATs. Never import them into this session.
    await Promise.all([
      rm(join(this.options.stateDir, "mcp-selection.json"), { force: true }),
      rm(join(this.options.stateDir, "mcp-tokens"), { force: true, recursive: true }),
    ]);
    // The old credential.json contained a reusable backend token. A restart
    // requires a fresh login; only the short-lived inference token reaches disk.
    this.credential = null;
    await rm(join(this.options.stateDir, "credential.json"), { force: true });
    await rm(join(this.options.stateDir, "sync.json"), { force: true });
    const tokenPath = join(this.options.stateDir, "access-token");
    if (await exists(tokenPath)) await atomicWrite(tokenPath, "");
    const alternatePath = join(this.options.stateDir, "access-token-next");
    if (await exists(alternatePath)) await atomicWrite(alternatePath, "");
    await this.removeProvider(this.options.configPath, this.options.client);
    await clearMCP(this.options.stateDir);
    await this.syncMCP?.([]);
    this.state = {};
    this.configTimer = setInterval(() => this.backgroundRefresh(), this.options.refreshMs);
    this.loadTimer = setInterval(() => this.pollLoad().catch(() => {}), this.options.loadPollMs);
    this.configTimer.unref(); this.loadTimer.unref();
  }
  authenticated() { return Boolean(this.credential && (this.credential.refreshExpiresAt ?? this.credential.expiresAt) > Date.now()); }
  token() { if (!this.authenticated() || this.credential.expiresAt <= Date.now()) throw new Unauthorized(); return this.credential.accessToken; }
  async apiToken() { await this.ensureFreshTokens(); return this.token(); }
  async inferenceToken() {
    await this.ensureFreshTokens();
    if (!this.authenticated() || this.credential.inferenceExpiresAt <= Date.now()) throw new Unauthorized();
    return this.credential.inferenceToken;
  }
  scheduleTokenRenewal(retryMs) {
    clearTimeout(this.tokenTimer);
    if (!this.authenticated() || !this.credential.refreshToken) return;
    const remaining = Math.min(this.credential.expiresAt, this.credential.inferenceExpiresAt) - Date.now();
    const delay = retryMs ?? Math.max(100, Math.floor(remaining * 0.8));
    this.tokenRenewAt = Date.now() + delay;
    this.tokenTimer = setTimeout(async () => {
      try { await this.ensureFreshTokens(true); }
      catch (error) {
        if (error instanceof Unauthorized) await this.invalidate();
        else { await this.notice("Не удалось обновить доступ к модели; повторяем попытку", "warning"); this.scheduleTokenRenewal(5000); }
      }
    }, delay);
    this.tokenTimer.unref();
  }
  async ensureFreshTokens(force = false) {
    if (!this.authenticated()) throw new Unauthorized();
    if (!this.credential.refreshToken || (!force && this.tokenRenewAt > Date.now() && this.credential.expiresAt > Date.now() && this.credential.inferenceExpiresAt > Date.now())) return;
    if (this.renewing) return this.renewing;
    const generation = this.authGeneration;
    const old = this.credential;
    this.renewing = (async () => {
      const { data } = await this.api.request("/oauth/refresh", { method: "POST", body: { refreshToken: old.refreshToken }, signal: this.abort.signal });
      if (!validCredential(data) || data.refreshExpiresAt <= Date.now()) throw new Error("Сервер вернул некорректные токены");
      if (generation !== this.authGeneration || this.credential !== old || this.abort.signal.aborted) return;
      await atomicWrite(join(this.options.stateDir, "access-token"), data.inferenceToken);
      await atomicWrite(join(this.options.stateDir, "access-token-next"), data.inferenceToken);
      if (generation !== this.authGeneration || this.credential !== old || this.abort.signal.aborted) {
        await Promise.all([atomicWrite(join(this.options.stateDir, "access-token"), ""), atomicWrite(join(this.options.stateDir, "access-token-next"), "")]);
        return;
      }
      this.credential = data;
      this.scheduleTokenRenewal();
      await this.configWrites(() => this.reloadProvider());
    })().finally(() => { this.renewing = null; });
    return this.renewing;
  }
  status() {
    return { authenticated: this.authenticated(), user: this.authenticated() ? this.credential.user : null,
      expiresAt: this.authenticated() ? this.credential.refreshExpiresAt ?? this.credential.expiresAt : null,
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
      const token = await this.apiToken();
      try {
        const response = await this.api.request("/api/config", { token, etag: this.state.etag, signal: this.abort.signal });
        if (response.unchanged) this.state = { ...this.state, checkedAt: new Date().toISOString(), lastError: null };
        else {
          const applied = await this.configWrites(() => this.applyConfig({ ...this.options, envelope: response.data, previous: this.state.revision ? this.state : null }));
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
    this.authGeneration++;
    clearTimeout(this.tokenTimer);
    this.credential = null;
    await Promise.all([rm(join(this.options.stateDir, "credential.json"), { force: true }), atomicWrite(join(this.options.stateDir, "access-token"), ""), atomicWrite(join(this.options.stateDir, "access-token-next"), "")]);
    await clearMCP(this.options.stateDir);
    this.mcpConfigs = [];
    await this.reloadMCP();
  }
  async reloadMCP() { await this.syncMCP?.(this.mcpConfigs); await Promise.all([...this.mcpReloaders].map((reload) => reload())); }
  async mcpConnectionStates(ids) {
    if (!ids.length || this.options.client !== "opencode" || typeof this.bridge.request !== "function") return null;
    let states = [];
    for (let attempt = 0; attempt < 12; attempt++) {
      const { data } = await this.bridge.request("/api/mcp");
      states = ids.map((id) => {
        const state = data.find((entry) => entry.name === `corp_${id}`)?.status;
        return { id, status: state?.status ?? "pending", rejected: state?.status === "failed" && /HTTP 401\b/.test(state.error ?? "") };
      });
      if (states.every((entry) => entry.status === "connected")) break;
      if (attempt < 11) await sleep(250, this.abort.signal);
    }
    return states;
  }
  async refreshMCPCatalog() {
    const { data } = await this.api.request("/api/mcps", { token: await this.apiToken(), signal: this.abort.signal });
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
    const polledGeneration = this.authGeneration;
    let next;
    try {
      const { data } = await this.api.request("/api/load", { token: await this.apiToken(), signal: this.abort.signal });
      if (!["green", "yellow", "red"].includes(data?.level) || typeof data.message !== "string" || data.message.length > 250 || !Number.isFinite(data.observedAt) || Math.abs(Date.now() - data.observedAt) > 90000) throw new Error("Нет свежих данных нагрузки");
      next = { level: data.level, message: data.message, queue: data.queue, checkedAt: data.observedAt };
    } catch (error) {
      next = { level: "unknown", message: error instanceof Unauthorized ? "Требуется /login" : "Сервер нагрузки недоступен", checkedAt: Date.now() };
      if (error instanceof Unauthorized) await this.queue(() => this.authGeneration === polledGeneration ? this.invalidate() : undefined);
    } finally { this.polling = false; }
    if (this.abort.signal.aborted) return;
    if (this.authGeneration !== polledGeneration) return;
    if (!this.credential && next.level !== "unknown") return;
    const changed = next.level !== this.load.level;
    this.load = next;
    if (changed) await this.notice(`${lights[next.level]} Инференс: ${next.message}`, { green: "success", yellow: "warning", red: "error", unknown: "warning" }[next.level]);
  }
  track(promise, sessionID, interactiveError = true) {
    this.jobs.add(promise);
    promise.catch(async (error) => {
      if (!this.abort.signal.aborted) {
        if (interactiveError) await this.bridge.message(sessionID, "Корпоративный плагин", error.message).catch(() => {});
        await this.notice(error.message, "error");
      }
    }).finally(() => this.jobs.delete(promise));
  }
  async autoLogin() {
    if (this.authenticated() || this.abort.signal.aborted || process.env.CORP_NO_BROWSER === "1") return false;
    try { await this.login(null); return true; }
    catch (error) {
      await this.notice(`Не удалось открыть вход автоматически: ${error.message}. Выполните /login.`, "warning");
      return false;
    }
  }
  async login(sessionID, reload = async () => {}) {
    if (this.loginFlow) {
      if (sessionID) {
        await this.open(this.loginFlow.url);
        await this.bridge.message(sessionID, "Вход открыт", "Страница входа повторно открыта в браузере. Завершите авторизацию там.");
      }
      return;
    }
    if (this.loginPending) {
      await this.loginPending.catch(() => {});
      return this.login(sessionID, reload);
    }
    this.loginPending = startLogin(this.api);
    const generation = this.authGeneration;
    let flow;
    try { flow = await this.loginPending; } finally { this.loginPending = null; }
    if (generation !== this.authGeneration || this.abort.signal.aborted) { flow.cancel(); return; }
    this.loginFlow = flow;
    const clientName = this.options.client === "kilo" ? "Kilo" : "OpenCode";
    let form = sessionID ? await this.bridge.form(sessionID, `Вход в корпоративный ${clientName}`, [
      { type: "external", key: "login", title: "Открыть страницу входа", url: flow.url },
      { type: "string", key: "waiting", title: `Вход в корпоративный ${clientName}`, description: `В открывшемся браузере выберите тестовую учётную запись. Пароль не нужен. Если браузер не открылся, скопируйте адрес: ${flow.url}`, custom: false, options: [{ value: "waiting", label: "Ожидаю входа в браузере" }] },
    ]).catch((error) => { flow.cancel(); this.loginFlow = null; throw error; }) : null;
    try { await this.open(flow.url); }
    catch {
      if (form) await this.notice(`Откройте ссылку входа в форме ${clientName}`, "info");
      else {
        flow.cancel(); this.loginFlow = null;
        throw new Error("браузер не открылся");
      }
    }
    const cancellation = new AbortController();
    if (form) this.bridge.wait(sessionID, form.id, AbortSignal.any([this.abort.signal, cancellation.signal])).then((answer) => { if (answer === null) flow.cancel(); }).catch(() => {});
    this.track((async () => {
      try {
        const result = await flow.result;
        if (!validCredential(result) || result.refreshExpiresAt <= Date.now()) throw new Error("Сервер вернул некорректную авторизацию");
        validateConfig(result.configuration, this.options.serverURL);
        await this.queue(async () => {
          if (generation !== this.authGeneration || this.abort.signal.aborted) throw new Error("Вход отменён");
          this.authGeneration++;
          this.credential = { accessToken: result.accessToken, expiresAt: result.expiresAt, inferenceToken: result.inferenceToken, inferenceExpiresAt: result.inferenceExpiresAt, refreshToken: result.refreshToken, refreshExpiresAt: result.refreshExpiresAt, user: result.user };
          await clearMCP(this.options.stateDir);
          this.mcpConfigs = [];
          await this.reloadMCP();
          await atomicWrite(join(this.options.stateDir, "access-token"), this.credential.inferenceToken);
          await atomicWrite(join(this.options.stateDir, "access-token-next"), this.credential.inferenceToken);
          this.scheduleTokenRenewal();
          this.state = { ...(await this.configWrites(() => this.applyConfig({ ...this.options, envelope: result.configuration }))), lastError: null };
          await this.persistState();
        });
        await reload();
        if (form) { await this.bridge.cancel(sessionID, form.id); form = null; }
        await this.notice(`Вход выполнен: ${result.user.name}. Конфиг версии ${this.state.revision} применён. Доступны /refresh_config и /skills_load.`, "success");
        await this.pollLoad();
      } finally {
        cancellation.abort();
        if (form) await this.bridge.cancel(sessionID, form.id);
        this.loginFlow = null;
      }
    })(), sessionID);
  }
  async skills(sessionID, reload) {
    if (this.forms.has(sessionID)) throw new Error("Форма выбора skills уже открыта");
    const accountGeneration = this.authGeneration;
    const token = this.authenticated() ? await this.apiToken() : null;
    let catalog = [];
    if (token) {
      const { data } = await this.api.request("/api/skills", { token, signal: this.abort.signal });
      catalog = validateCatalog(data);
    }
    const community = communityCatalog(this.options.client);
    if (!catalog.length && !community.length) return this.bridge.message(sessionID, "Skills", "Нет доступных skills.");
    const form = await this.bridge.form(sessionID, "Загрузить skills и плагины", [{
      type: "multiselect", key: "skills", title: "Выберите нужные пакеты", description: "Community пакеты доступны без /login. Корпоративные skills видны после входа. Уже установленные пакеты сохраняются.",
      custom: false, minItems: 0, default: [], options: [
        ...community.map((item) => ({ value: item.id, label: `${item.name} · ${item.kind} · ${item.version}`, description: item.description })),
        ...catalog.map((skill) => ({ value: skill.id, label: `${skill.name} · corporate · ${skill.version}`, description: skill.description })),
      ],
    }]);
    const controller = new AbortController();
    this.forms.set(sessionID, { form, controller });
    this.track((async () => {
      try {
        const signal = AbortSignal.any([this.abort.signal, controller.signal, AbortSignal.timeout(300000)]);
        const answer = await this.bridge.wait(sessionID, form.id, signal);
        if (answer === null) return;
        const installed = await this.queue(async () => {
          if (token && (this.authGeneration !== accountGeneration || !this.authenticated())) throw new Error("Учётная запись изменилась; откройте /skills_load снова");
          const chosen = answer.skills ?? [];
          if (!Array.isArray(chosen) || new Set(chosen).size !== chosen.length) throw new Error("Некорректный выбор skills");
          const known = new Set([...community.map((item) => item.id), ...catalog.map((item) => item.id)]);
          if (chosen.some((id) => !known.has(id))) throw new Error("Выбран skill вне доступного каталога");
          const communityIDs = chosen.filter((id) => id.startsWith("community-"));
          const corporateIDs = chosen.filter((id) => id.startsWith("corp-"));
          const added = await installCommunity({ ids: communityIDs, client: this.options.client, skillsDir: this.options.skillsDir, configPath: this.options.configPath });
          const corporate = corporateIDs.length ? await installSkills({ ids: corporateIDs, catalog, api: this.api, token: await this.apiToken(), skillsDir: this.options.skillsDir, signal }) : [];
          return [...added, ...corporate];
        });
        await reload();
        await this.bridge.message(sessionID, "Skills загружены", installed.length ? installed.join("\n") : "Ничего не выбрано.");
      } finally { this.forms.delete(sessionID); await this.bridge.cancel(sessionID, form.id); }
    })(), sessionID);
  }
  async mcps(sessionID, reload = async () => {}) {
    if (this.forms.has(sessionID)) throw new Error("Форма выбора уже открыта");
    await this.apiToken();
    const accountGeneration = this.authGeneration;
    const catalog = await this.refreshMCPCatalog();
    if (!catalog.length) return this.options.client === "kilo" ? this.bridge.message(sessionID, "Корпоративные MCP", "Для вашей учётной записи нет доступных MCP.") : this.notice("Для вашей учётной записи нет доступных MCP.", "info");
    const selected = this.mcpConfigs.map(({ name }) => name.slice(5));
    const form = await this.bridge.form(sessionID, "Подключить корпоративные MCP", [{
      type: "multiselect", key: "mcps", title: "Выберите MCP", description: `Для отмеченных MCP откроется локальная форма ввода или замены токенов, не в чате ${this.options.client === "kilo" ? "Kilo" : "OpenCode"}.`,
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
        const requested = ids.map((id) => {
          const item = catalog.find((entry) => entry.id === id);
          if (!item) throw new Error("Выбран MCP вне доступного каталога");
          return item;
        });
        const apply = async (tokens) => {
          await this.queue(async () => {
            if (signal.aborted || this.authGeneration !== accountGeneration || !this.authenticated()) throw new Error("Учётная запись изменилась; откройте /mcps_load снова");
            this.mcpConfigs = await saveMCPSelection(this.options.stateDir, ids, catalog, tokens);
            await this.reloadMCP();
          });
          await reload();
          if (!ids.length) {
            if (this.options.client === "kilo") await this.bridge.message(sessionID, "MCP отключены", "Все корпоративные MCP отключены.");
            else await this.notice("Все корпоративные MCP отключены.", "info");
            return { kind: "success", title: "MCP отключены", message: "Все корпоративные MCP отключены." };
          }
          let states = null;
          try { states = await this.mcpConnectionStates(ids); } catch { /* The configuration is applied; show an unverified state. */ }
          const items = requested.map((item) => {
            const state = states?.find((entry) => entry.id === item.id);
            return { name: item.name, status: state?.status ?? "pending", detail: state?.status === "connected" ? "Подключён" : state?.rejected ? "Токен отклонён (HTTP 401)" : state?.status === "failed" ? "Соединение не установлено" : "Проверьте подключение в приложении" };
          });
          const failed = items.filter((item) => item.status !== "connected");
          if (states && failed.length) {
            const summary = failed.map((item) => `${item.name}: ${item.detail}`).join("; ");
            if (this.options.client === "kilo") await this.bridge.message(sessionID, "MCP не подключены", summary);
            else await this.notice(`MCP не подключены. ${summary}`, "warning");
            return { kind: "error", title: "Не все MCP подключились", message: "Настройки сохранены. Повторите /mcps_load, чтобы заменить токены.", items };
          }
          const names = requested.map((item) => item.name).join(", ");
          if (this.options.client === "kilo") await this.bridge.message(sessionID, "MCP добавлены", names);
          else await this.notice(`${states ? "MCP подключены" : "MCP добавлены в конфиг"}: ${names}`, "success");
          return { kind: states ? "success" : "warning", title: states ? "MCP подключены" : "MCP добавлены в конфиг", message: states ? "Системы доступны в OpenCode." : "Проверьте соединение в Kilo.", items };
        };
        if (requested.length) {
          const page = await captureSecrets(requested, { onSubmit: apply });
          const cancel = () => page.cancel();
          signal.addEventListener("abort", cancel, { once: true });
          let notice;
          try {
            if (process.env.CORP_NO_BROWSER === "1") notice = await this.bridge.form(sessionID, "Токены выбранных MCP", [{ type: "external", key: "tokens", title: "Открыть локальную форму для токенов", url: page.url }]);
            else await this.open(page.url).catch(async () => { notice = await this.bridge.form(sessionID, "Токены выбранных MCP", [{ type: "external", key: "tokens", title: "Открыть локальную форму для токенов", url: page.url }]); });
            await page.result;
          } finally {
            signal.removeEventListener("abort", cancel);
            page.cancel();
            if (notice) await this.bridge.cancel(sessionID, notice.id);
          }
        } else await apply(new Map());
      } finally { this.forms.delete(sessionID); await this.bridge.cancel(sessionID, form.id); }
    })(), sessionID, false);
  }
  async logout() {
    this.authGeneration++;
    this.loginFlow?.cancel();
    for (const { controller } of this.forms.values()) controller.abort();
    await this.queue(async () => {
      const refreshToken = this.credential?.refreshToken;
      const accessToken = this.credential?.accessToken;
      await this.invalidate();
      this.state = {}; await this.persistState();
      this.load = { level: "unknown", message: "Вход не выполнен", checkedAt: null };
      try { await this.configWrites(() => this.removeProvider(this.options.configPath, this.options.client)); }
      finally {
        if (refreshToken) {
          try { await this.api.request("/oauth/revoke", { method: "POST", body: { refreshToken } }); }
          catch { if (accessToken) await this.api.request("/oauth/revoke", { method: "POST", token: accessToken, body: {} }).catch(() => {}); }
        } else if (accessToken) await this.api.request("/oauth/revoke", { method: "POST", token: accessToken, body: {} }).catch(() => {});
      }
    });
  }
  dispose() {
    clearInterval(this.configTimer); clearInterval(this.loadTimer); clearTimeout(this.tokenTimer);
    this.abort.abort(); this.loginFlow?.cancel();
    clearMCPEnv(this.options.stateDir);
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
