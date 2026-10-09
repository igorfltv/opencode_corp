import { lights } from "./runtime.js";
import { userError } from "./user-errors.js";

export const commands = Object.freeze([
  { name: "login", description: "Войти в корпоративный OpenCode через браузер", kiloDescription: "Войти в корпоративный сервис", reload: true },
  { name: "refresh_config", description: "Получить и применить корпоративный конфиг", kiloDescription: "Обновить корпоративный конфиг", reload: true },
  { name: "skills_load", description: "Выбрать community skills, плагины и корпоративные skills", kiloDescription: "Загрузить skills из каталога", reload: true },
  { name: "mcps_load", description: "Выбрать корпоративные MCP и ввести личные токены", kiloDescription: "Подключить корпоративные MCP", reload: true },
  { name: "logout", description: "Выйти из корпоративной учётной записи", kiloDescription: "Выйти из корпоративного сервиса", reload: true },
  { name: "corp_status", description: "Учётная запись, версия конфига и состояние инференса", kiloDescription: "Показать корпоративный статус", reload: false },
  { name: "inference_status", description: "Светофор нагрузки на инференс", kiloDescription: "Показать нагрузку инференса", reload: false },
]);

export const commandByName = new Map(commands.map((command) => [command.name, command]));

export async function runOpenCodeCommand(runtime, context, name, sessionID) {
  switch (name) {
    case "login": return runtime.login(sessionID);
    case "refresh_config": {
      const state = await runtime.refresh();
      return runtime.bridge.message(sessionID, "Конфиг актуален", `Версия ${state.revision}. Проверено: ${state.checkedAt}`);
    }
    case "skills_load": return runtime.skills(sessionID, () => context.skill.reload());
    case "mcps_load": return runtime.mcps(sessionID);
    case "logout": {
      await runtime.logout();
      return runtime.bridge.message(sessionID, "Выход выполнен", "Токен удалён, корпоративный провайдер отключён. Скачанные skills сохранены.");
    }
    case "corp_status": {
      const status = runtime.status();
      return runtime.bridge.message(sessionID, "Корпоративный статус", `${status.authenticated ? status.user.name : "Не выполнен вход — /login"}\nКонфиг: ${status.config.revision ?? "не загружен"}\nПоследняя проверка: ${status.config.checkedAt ?? "ещё не было"}\n${lights[status.load.level]} ${status.load.message}\nАвтообновление: ${status.refreshMinutes} мин.${status.config.lastError ? `\n${status.config.lastError}` : ""}`);
    }
    case "inference_status": {
      await runtime.apiToken();
      await runtime.pollLoad();
      return runtime.bridge.message(sessionID, `${lights[runtime.load.level]} Инференс`, runtime.load.message);
    }
    default: throw new Error("Неизвестная корпоративная команда");
  }
}

export function registerOpenCodeCommands(context, runtime) {
  return context.command.transform((registry) => {
    for (const { name, description } of commands) registry.add({ name, description, async execute({ sessionID }) {
      try {
        if (name !== "login" && name !== "skills_load" && !runtime.authenticated()) {
          await runtime.bridge.message(sessionID, `/${name}`, "Сначала выполните /login, чтобы войти в корпоративный OpenCode.");
          return;
        }
        await runOpenCodeCommand(runtime, context, name, sessionID);
      } catch (error) {
        const message = userError(error, name);
        await runtime.bridge.message(sessionID, `/${name}`, message).catch(() => runtime.notice(message, "error"));
      }
    } });
  });
}
