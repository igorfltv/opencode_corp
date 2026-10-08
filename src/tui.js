import { CorporateRuntime, optionsFromEnv, lights } from "./runtime.js";
import { syncKiloMCP } from "./config.js";
import { KiloBridge } from "./kilo-bridge.js";

export default {
  id: "company-corporate-ui",
  setup(context) {
    return context.data.listen(({ details }) => {
      if (details.type !== "rpc.company.corporate.notice") return;
      const location = context.location ?? context.data.location.default();
      if (details.location?.directory !== location.directory) return;
      const { message, level } = details.data;
      context.ui.toast.show({ title: "Company OpenCode", message, variant: level, duration: 7000 });
    });
  },
  async tui(api, settings = {}) {
    if (!api.command?.register) throw new Error("Для корпоративных команд нужен Kilo CLI 7.x с TUI plugin API");
    const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
    const bridge = new KiloBridge((item) => api.ui.toast(item));
    const runtime = new CorporateRuntime(options, {
      bridge,
      syncMCP: (configs) => syncKiloMCP(options.configPath, options.stateDir, configs),
    });
    await runtime.start();
    const notice = ({ message, level }) => api.ui.toast({ title: "Company Kilo", message, variant: level, duration: 7000 });
    runtime.listeners.add(notice);
    const reloadKilo = async () => {
      const result = await api.client.instance.reload();
      if (result.error) throw new Error("Kilo не смог обновить конфигурацию. Повторите действие после завершения активной сессии.");
    };
    const commands = [
      ["login", "Войти в корпоративный сервис", (id) => runtime.login(id, reloadKilo)],
      ["refresh_config", "Обновить корпоративный конфиг", async () => { const state = await runtime.refresh(); await reloadKilo(); await bridge.message(null, "Конфиг актуален", `Версия ${state.revision}. Проверено: ${state.checkedAt}`); }],
      ["skills_load", "Загрузить корпоративные skills", (id) => runtime.skills(id, reloadKilo)],
      ["mcps_load", "Подключить корпоративные MCP", (id) => runtime.mcps(id, reloadKilo)],
      ["logout", "Выйти из корпоративной учётной записи", async () => { await runtime.logout(); await reloadKilo(); await bridge.message(null, "Выход выполнен", "Корпоративные токены и провайдер удалены."); }],
      ["corp_status", "Показать корпоративный статус", async () => { const status = runtime.status(); await bridge.message(null, "Корпоративный статус", `${status.authenticated ? status.user.name : "Не выполнен вход — /login"}\nКонфиг: ${status.config.revision ?? "не загружен"}\n${lights[status.load.level]} ${status.load.message}`); }],
      ["inference_status", "Показать нагрузку инференса", async () => { runtime.token(); await runtime.pollLoad(); await bridge.message(null, `${lights[runtime.load.level]} Инференс`, runtime.load.message); }],
    ];
    const unregister = api.command.register(() => commands.map(([name, description, execute]) => ({
      title: `/${name}`, value: `company.${name}`, description, category: "Company", slash: { name },
      async onSelect() {
        try {
          if (name !== "login" && !runtime.authenticated()) { await bridge.message(null, `/${name}`, "Сначала выполните /login."); return; }
          await execute("kilo-tui");
        } catch (error) { await bridge.message(null, `/${name}`, error.message); }
      },
    })));
    api.lifecycle.onDispose(() => { unregister(); runtime.listeners.delete(notice); runtime.dispose(); bridge.dispose(); });
  },
};
