import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parse, modify, applyEdits } from "jsonc-parser";
import { root } from "./harness.mjs";
import { atomicWrite, exists, readJSON } from "../src/io.js";

const profile = resolve(process.env.OPENCODE_CONFIG_DIR ?? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "opencode"));
const configPath = join(profile, "opencode.jsonc");
const serviceFile = join(process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state"), "opencode", "service.json");
const service = await readJSON(serviceFile);
if (!service || !/^http:\/\/127\.0\.0\.1:\d+$/.test(service.url) || typeof service.password !== "string" || service.password.length < 16) {
  throw new Error("Не найден работающий локальный OpenCode; сначала запустите приложение");
}
const original = await readFile(configPath, "utf8");
const errors = [];
const config = parse(original, errors, { allowTrailingComma: true });
if (errors.length || !config || typeof config !== "object" || Array.isArray(config)) throw new Error("Некорректный opencode.jsonc; файл не изменён");
if (config.plugins !== undefined && !Array.isArray(config.plugins)) throw new Error("Поле plugins должно быть массивом; файл не изменён");
const entry = { package: root, options: { profileDir: profile, serverURL: "http://127.0.0.1:4310", connectionFile: serviceFile } };
const plugins = (config.plugins ?? []).filter((item) => item !== root && item?.package !== root);
plugins.push(entry);
const next = applyEdits(original, modify(original, ["plugins"], plugins, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
if (next !== original) {
  const backup = `${configPath}.before-corporate-plugin.bak`;
  if (!await exists(backup)) await atomicWrite(backup, original);
  await atomicWrite(configPath, next);
}
console.log(`Подключён корпоративный плагин: ${configPath}`);
console.log(`Локальный сервер OpenCode: ${service.url}`);
