import { parse, modify, applyEdits } from "jsonc-parser";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite, exists, digest } from "./io.js";

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
export async function applyConfig({ configPath, stateDir, envelope, serverURL, previous }) {
  const clean = validateConfig(envelope, serverURL);
  const fingerprint = digest(JSON.stringify(clean));
  if (previous && clean.revision < previous.revision) throw new Error("Сервер прислал более старую версию конфига");
  if (previous?.revision === clean.revision && previous.fingerprint !== fingerprint) throw new Error("Содержимое конфига изменилось без увеличения версии");
  let text = await readFile(configPath, "utf8");
  const current = parseConfig(text);
  const provider = {
    ...clean.config.providers.corporate,
    package: "@ai-sdk/openai-compatible",
    settings: { ...clean.config.providers.corporate.settings, apiKey: `{file:${join(stateDir, "access-token")}}` },
  };
  const changed = JSON.stringify(current.providers?.corporate) !== JSON.stringify(provider);
  if (changed) {
    const backup = `${configPath}.before-corporate.bak`;
    if (!await exists(backup)) await atomicWrite(backup, text);
    text = applyEdits(text, modify(text, ["providers", "corporate"], provider, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
    parseConfig(text);
    await atomicWrite(configPath, text);
  }
  return { revision: clean.revision, fingerprint, changed, checkedAt: new Date().toISOString() };
}
export async function removeProvider(configPath) {
  let text = await readFile(configPath, "utf8");
  const current = parseConfig(text);
  if (current.providers?.corporate) text = applyEdits(text, modify(text, ["providers", "corporate"], undefined, {}));
  await atomicWrite(configPath, text);
}
