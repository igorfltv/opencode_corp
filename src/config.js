import { parse, modify, applyEdits } from "jsonc-parser";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite, exists, digest } from "./io.js";
import { mcpEnvName } from "./mcp.js";

function object(value) { return value && typeof value === "object" && !Array.isArray(value); }
function exactKeys(value, keys) { return object(value) && Object.keys(value).every((key) => keys.includes(key)); }
const safeLabel = (value) => typeof value === "string" && value.length > 0 && value.length <= 100 && !/\{(?:file|env):/.test(value);
export function validateConfig(envelope, serverURL) {
  if (!exactKeys(envelope, ["revision", "config"]) || !Number.isSafeInteger(envelope.revision) || envelope.revision < 1) throw new Error("Некорректная версия конфига");
  const config = envelope.config;
  if (!exactKeys(config, ["providers"]) || !exactKeys(config.providers, ["corporate"])) throw new Error("Сервер может менять только providers.corporate");
  const provider = config.providers.corporate;
  if (!exactKeys(provider, ["name", "settings", "models"]) || !safeLabel(provider.name)) throw new Error("Некорректный провайдер");
  if (!exactKeys(provider.settings, ["baseURL"]) || provider.settings.baseURL !== `${serverURL}/v1`) throw new Error("Не разрешён адрес inference API");
  if (!object(provider.models) || !Object.keys(provider.models).length || Object.keys(provider.models).length > 20) throw new Error("Некорректный список моделей");
  for (const [id, model] of Object.entries(provider.models)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(id) || !exactKeys(model, ["name", "limit"]) || !safeLabel(model.name)) throw new Error("Некорректная модель");
    if (!exactKeys(model.limit, ["context", "output"]) || !Number.isInteger(model.limit.context) || !Number.isInteger(model.limit.output) || model.limit.output < 1 || model.limit.output > model.limit.context || model.limit.context > 2000000) throw new Error("Некорректные лимиты модели");
  }
  return JSON.parse(JSON.stringify(envelope));
}
export function parseConfig(text) {
  const errors = [];
  const value = parse(text, errors, { allowTrailingComma: true });
  if (errors.length || !object(value)) throw new Error("opencode.jsonc содержит ошибку; файл не изменён");
  return value;
}
export async function applyConfig({ configPath, stateDir, envelope, serverURL, previous, client = "opencode" }) {
  const clean = validateConfig(envelope, serverURL);
  const fingerprint = digest(JSON.stringify(clean));
  if (previous && clean.revision < previous.revision) throw new Error("Сервер прислал более старую версию конфига");
  if (previous?.revision === clean.revision && previous.fingerprint !== fingerprint) throw new Error("Содержимое конфига изменилось без увеличения версии");
  let text = await readFile(configPath, "utf8");
  const current = parseConfig(text);
  const source = clean.config.providers.corporate;
  const field = client === "kilo" ? "provider" : "providers";
  const currentRef = client === "kilo" ? current[field]?.corporate?.options?.apiKey : current[field]?.corporate?.settings?.apiKey;
  const references = ["access-token", "access-token-next"].map((name) => `{file:${join(stateDir, name)}}`);
  const apiKey = references.includes(currentRef) ? currentRef : references[0];
  const provider = client === "kilo"
    ? { name: source.name, npm: "@ai-sdk/openai-compatible", options: { baseURL: source.settings.baseURL, apiKey }, models: source.models }
    : { ...source, package: "@ai-sdk/openai-compatible", settings: { ...source.settings, apiKey } };
  const changed = JSON.stringify(current[field]?.corporate) !== JSON.stringify(provider);
  if (changed) {
    const backup = `${configPath}.before-corporate.bak`;
    if (!await exists(backup)) await atomicWrite(backup, text);
    text = applyEdits(text, modify(text, [field, "corporate"], provider, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
    parseConfig(text);
    await atomicWrite(configPath, text);
  }
  return { revision: clean.revision, fingerprint, changed, checkedAt: new Date().toISOString() };
}
export async function rotateProviderTokenReference(configPath, stateDir, client = "opencode") {
  const original = await readFile(configPath, "utf8");
  const current = parseConfig(original);
  const field = client === "kilo" ? "provider" : "providers";
  const path = [field, "corporate", client === "kilo" ? "options" : "settings", "apiKey"];
  const provider = current[field]?.corporate;
  if (!provider) return false;
  const oldRef = client === "kilo" ? provider.options?.apiKey : provider.settings?.apiKey;
  const first = `{file:${join(stateDir, "access-token")}}`;
  const second = `{file:${join(stateDir, "access-token-next")}}`;
  if (oldRef !== first && oldRef !== second) throw new Error("Некорректная ссылка на токен провайдера");
  const updated = applyEdits(original, modify(original, path, oldRef === first ? second : first, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  parseConfig(updated);
  await atomicWrite(configPath, updated);
  return true;
}
export async function removeProvider(configPath, client = "opencode") {
  let text = await readFile(configPath, "utf8");
  const original = text;
  const current = parseConfig(text);
  const field = client === "kilo" ? "provider" : "providers";
  if (object(current[field])) {
    const count = Object.keys(current[field]).length;
    if (Object.hasOwn(current[field], "corporate") || count === 0) {
      const path = count <= 1 ? [field] : [field, "corporate"];
      text = applyEdits(text, modify(text, path, undefined, {}));
    }
  }
  if (client === "kilo") {
    for (const key of ["model", "small_model", "subagent_model"]) {
      if (typeof current[key] === "string" && current[key].startsWith("corporate/")) text = applyEdits(text, modify(text, [key], undefined, {}));
    }
  }
  if (text === original) return;
  parseConfig(text);
  await atomicWrite(configPath, text);
}

async function syncMCP(configPath, stateDir, configs, path) {
  const original = await readFile(configPath, "utf8");
  let text = original;
  const current = parseConfig(text);
  const existing = path.length === 1 ? current.mcp : current.mcp?.servers;
  const managedConfigs = object(existing) ? existing : {};
  const managed = Object.keys(managedConfigs).filter((name) => name.startsWith("corp_"));
  const wanted = new Map(configs.map(({ name, config }) => {
    if (!name.startsWith("corp_") || config.headers?.Authorization !== `Bearer {env:${mcpEnvName(stateDir, name.slice(5))}}`) throw new Error("Некорректная MCP конфигурация");
    return [name, { type: "remote", url: config.url, oauth: false, headers: { Authorization: config.headers.Authorization } }];
  }));
  if (managed.length === wanted.size && managed.every((name) => JSON.stringify(managedConfigs[name]) === JSON.stringify(wanted.get(name)))) return false;
  for (const name of managed) if (!wanted.has(name)) text = applyEdits(text, modify(text, [...path, name], undefined, {}));
  for (const [name, config] of wanted) text = applyEdits(text, modify(text, [...path, name], config, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  const updated = parseConfig(text);
  const section = path.length === 1 ? updated.mcp : updated.mcp?.servers;
  if (!Object.keys(object(section) ? section : {}).length) text = applyEdits(text, modify(text, path, undefined, {}));
  if (path.length > 1 && !Object.keys(parseConfig(text).mcp ?? {}).length) text = applyEdits(text, modify(text, ["mcp"], undefined, {}));
  parseConfig(text);
  const backup = `${configPath}.before-corporate.bak`;
  if (!await exists(backup)) await atomicWrite(backup, original);
  await atomicWrite(configPath, text);
  return true;
}

export function syncKiloMCP(configPath, stateDir, configs) {
  return syncMCP(configPath, stateDir, configs, ["mcp"]);
}

export function syncOpenCodeMCP(configPath, stateDir, configs) {
  return syncMCP(configPath, stateDir, configs, ["mcp", "servers"]);
}
