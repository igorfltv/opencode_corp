import { CorporateRuntime, optionsFromEnv, lights } from "./runtime.js";
import { startKiloControl } from "./kilo-control.js";

const rpc = {
  id: "company.corporate",
  methods: { status: { input: { type: "object", properties: {}, additionalProperties: false }, output: { type: "object" } } },
  events: { notice: { schema: { type: "object", properties: { message: { type: "string" }, level: { type: "string" }, at: { type: "number" } }, required: ["message", "level", "at"] } } },
};
// A changed runtime shape must not reuse an instance left by a hot-reloaded package.
const registryKey = Symbol.for("company.opencode.corporate.runtime.v2");
export default {
  id: "company-corporate",
  // Kilo's VS Code client calls the loopback control bridge; OpenCode keeps
  // its existing setup() entrypoint below.
  async server(_context, settings) { await startKiloControl(settings); return {}; },
  async setup(context) {
    const options = optionsFromEnv(process.env, context.options);
    const registry = globalThis[registryKey] ??= new Map();
    const key = `${options.configPath}|${options.serverURL}`;
    let entry = registry.get(key);
    if (!entry) {
      const runtime = new CorporateRuntime(options);
      entry = { runtime, ready: runtime.start(), refs: 0 };
      registry.set(key, entry);
    }
    entry.refs++;
    await entry.ready;
    const runtime = entry.runtime;
    const reloadMCP = () => context.mcp.reload();
    runtime.mcpReloaders.add(reloadMCP);
    const mcpRegistration = await context.mcp.transform((editor) => {
      for (const [name] of editor.list()) if (name.startsWith("corp_")) editor.remove(name);
      if (runtime.authenticated()) for (const { name, config } of runtime.mcpConfigs) editor.set(name, config);
    });
    const registration = await context.rpc.register(rpc, { status: async () => runtime.status() });
    const listener = (event) => registration.events.emit("notice", event);
    runtime.listeners.add(listener);
    const definitions = [
      ["login", "Войти в корпоративный OpenCode через браузер", (id) => runtime.login(id)],
      ["refresh_config", "Получить и применить корпоративный конфиг", async (id) => { const state = await runtime.refresh(); await runtime.bridge.message(id, "Конфиг актуален", `Версия ${state.revision}. Проверено: ${state.checkedAt}`); }],
      ["skills_load", "Выбрать и загрузить корпоративные skills", (id) => runtime.skills(id, () => context.skill.reload())],
      ["mcps_load", "Выбрать корпоративные MCP и ввести личные токены", (id) => runtime.mcps(id)],
      ["logout", "Выйти из корпоративной учётной записи", async (id) => { await runtime.logout(); await runtime.bridge.message(id, "Выход выполнен", "Токен удалён, корпоративный провайдер отключён. Скачанные skills сохранены."); }],
      ["corp_status", "Учётная запись, версия конфига и состояние инференса", async (id) => { const status = runtime.status(); await runtime.bridge.message(id, "Корпоративный статус", `${status.authenticated ? status.user.name : "Не выполнен вход — /login"}\nКонфиг: ${status.config.revision ?? "не загружен"}\nПоследняя проверка: ${status.config.checkedAt ?? "ещё не было"}\n${lights[status.load.level]} ${status.load.message}\nАвтообновление: ${status.refreshMinutes} мин.${status.config.lastError ? `\n${status.config.lastError}` : ""}`); }],
      ["inference_status", "Светофор нагрузки на инференс", async (id) => { runtime.token(); await runtime.pollLoad(); await runtime.bridge.message(id, `${lights[runtime.load.level]} Инференс`, runtime.load.message); }],
    ];
    await context.command.transform((commands) => {
      for (const [name, description, execute] of definitions) commands.add({ name, description, async execute({ sessionID }) {
        try {
          if (name !== "login" && !runtime.authenticated()) {
            await runtime.bridge.message(sessionID, `/${name}`, "Сначала выполните /login, чтобы войти в корпоративный OpenCode.");
            return;
          }
          await execute(sessionID);
        }
        catch (error) { await runtime.bridge.message(sessionID, `/${name}`, error.message); }
      } });
    });
    return () => {
      runtime.mcpReloaders.delete(reloadMCP);
      mcpRegistration.dispose?.();
      runtime.listeners.delete(listener);
      if (--entry.refs === 0) { runtime.dispose(); registry.delete(key); }
    };
  },
};
