import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { atomicWrite, exists } from "./io.js";
import { commands } from "./commands.js";

const marker = "# opencode_corp managed Kilo workflow";
const legacyMarker = "<!-- opencode_corp managed Kilo workflow -->";
const helper = String.raw`import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const names = new Set(${JSON.stringify(commands.map(({ name }) => name))});
const name = process.argv[2];
if (!names.has(name)) { console.log("Неизвестная корпоративная команда. Выберите команду из списка Kilo."); process.exit(0); }
try {
const directory = dirname(fileURLToPath(import.meta.url));
const files = (await readdir(directory)).filter((file) => /^control-\d+\.json$/.test(file));
files.sort((a, b) => Number(b.match(/\d+/)[0]) - Number(a.match(/\d+/)[0]));
files.unshift("control.json");

async function active(file) {
  try {
    const path = join(directory, file);
    if ((await stat(path)).mode & 0o077) return;
    const state = JSON.parse(await readFile(path, "utf8"));
    if (!Number.isInteger(state.port) || state.port < 1 || state.port > 65535 ||
      typeof state.secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(state.secret)) return;
    const response = await fetch("http://127.0.0.1:" + state.port + "/health", {
      headers: { Authorization: "Bearer " + state.secret }, signal: AbortSignal.timeout(1000),
    });
    if (response.ok) return state;
  } catch {}
}

let control;
for (const file of files) {
  control = await active(file);
  if (control) break;
}
if (!control) { console.log("Корпоративный плагин Kilo не запущен. Что сделать: 1. Перезапустите Kilo. 2. Проверьте загрузку плагина и повторите /" + name + "."); process.exit(0); }
const response = await fetch("http://127.0.0.1:" + control.port + "/command/" + name, {
  method: "POST", headers: { Authorization: "Bearer " + control.secret },
  signal: AbortSignal.timeout(310000),
});
const result = await response.json();
if (!response.ok) { console.log(typeof result.error === "string" && result.error.includes("Что сделать:") ? result.error : "Не удалось выполнить /" + name + ". Что сделать: 1. Повторите команду. 2. Проверьте состояние плагина."); process.exit(0); }
if (typeof result.message !== "string") throw new Error("Некорректный ответ плагина");
console.log(result.message);
} catch { console.log("Не удалось связаться с корпоративным плагином Kilo. Что сделать: 1. Перезапустите Kilo. 2. Повторите /" + name + "."); }
`;

function quote(path) {
  if (/[\r\n`]/.test(path)) throw new Error("Недопустимый путь к конфигу Kilo");
  return `'${path.replaceAll("'", `'"'"'`)}'`;
}

export async function installKiloWorkflows(options) {
  const script = join(options.stateDir, "workflow-command.mjs");
  await atomicWrite(script, helper);
  const conflicts = [];
  for (const { name, kiloDescription: description } of commands) {
    const file = join(dirname(options.configPath), "commands", `${name}.md`);
    const current = await exists(file);
    if (current) {
      if (current.isSymbolicLink()) {
        conflicts.push(name);
        continue;
      }
      const content = await readFile(file, "utf8");
      if (!content.includes(marker) && !content.includes(legacyMarker)) {
        conflicts.push(name);
        continue;
      }
    }
    const content = `---\n${marker}\ndescription: ${description}\n---\n\nВыполненная корпоративная команда /${name} вернула результат:\n\n!\`node ${quote(script)} ${name}\`\n\nОтветь пользователю кратко по-русски, используя только результат команды выше.\n`;
    await atomicWrite(file, content);
  }
  return { conflicts };
}
