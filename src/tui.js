import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { optionsFromEnv } from "./runtime.js";
import { commands } from "./commands.js";
import { NOTIFICATION_TITLE } from "./desktop.js";

async function invokeControl(stateDir, command) {
  const files = (await readdir(stateDir)).filter((file) => /^control-\d+\.json$/.test(file));
  files.sort((a, b) => Number(b.match(/\d+/)[0]) - Number(a.match(/\d+/)[0]));
  files.unshift("control.json");
  for (const file of files) {
    let state;
    try {
      const path = join(stateDir, file);
      if ((await stat(path)).mode & 0o077) continue;
      state = JSON.parse(await readFile(path, "utf8"));
      if (!Number.isInteger(state.port) || state.port < 1 || state.port > 65535 || typeof state.secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(state.secret)) continue;
      const health = await fetch(`http://127.0.0.1:${state.port}/health`, { headers: { Authorization: `Bearer ${state.secret}` }, signal: AbortSignal.timeout(1000) });
      if (!health.ok) continue;
    } catch { continue; }
    const response = await fetch(`http://127.0.0.1:${state.port}/command/${command}`, {
      method: "POST", headers: { Authorization: `Bearer ${state.secret}` }, signal: AbortSignal.timeout(310000),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Команда не выполнена");
    return result;
  }
  throw new Error("Корпоративный плагин Kilo не запущен");
}

export default {
  id: "company-corporate-ui",
  setup(context) {
    return context.data.listen(({ details }) => {
      if (details.type !== "rpc.company.corporate.notice") return;
      const location = context.location ?? context.data.location.default();
      if (details.location?.directory !== location.directory) return;
      const { message, level } = details.data;
      context.ui.toast.show({ title: NOTIFICATION_TITLE, message, variant: level, duration: 7000 });
    });
  },
  async tui(api, settings = {}) {
    if (!api.command?.register) throw new Error("Для корпоративных команд нужен Kilo CLI 7.x с TUI plugin API");
    const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
    const unregister = api.command.register(() => commands.map(({ name, kiloDescription }) => ({
      title: `/${name}`, value: `company.${name}`, description: kiloDescription, category: "Company", slash: { name },
      async onSelect() {
        try {
          const result = await invokeControl(options.stateDir, name);
          if (result.reload) {
            const updated = await api.client.instance.reload();
            if (updated.error) throw new Error("Kilo не смог обновить конфигурацию");
          }
          api.ui.toast({ title: `/${name}`, message: result.message, variant: "info", duration: 10000 });
        } catch (error) {
          api.ui.toast({ title: `/${name}`, message: error.message, variant: "error", duration: 10000 });
        }
      },
    })));
    api.lifecycle.onDispose(unregister);
  },
};
