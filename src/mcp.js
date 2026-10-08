import { rm } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { trustedURL } from "./io.js";

const idPattern = /^[a-z][a-z0-9_-]{0,39}$/;
const text = (value, max = 200) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
const validToken = (value) => text(value, 512) && !/[\r\n]/.test(value);

export function validateMCPCatalog(data, serverURL) {
  if (!data || !Array.isArray(data.servers) || data.servers.length > 30) throw new Error("Некорректный каталог MCP");
  const ids = new Set();
  return data.servers.map((entry) => {
    if (!entry || !idPattern.test(entry.id) || ids.has(entry.id) || !text(entry.name, 100) || !text(entry.description) || entry.auth !== "personal_token") throw new Error("Некорректная запись MCP");
    ids.add(entry.id);
    const url = trustedURL(entry.url);
    if (new URL(url).origin !== new URL(serverURL).origin || new URL(url).pathname !== `/mcp/${entry.id}`) throw new Error("MCP должен находиться на корпоративном сервере");
    return { id: entry.id, name: entry.name, description: entry.description, url, auth: entry.auth };
  });
}

export function validateSelection(ids, catalog) {
  if (!Array.isArray(ids) || ids.length > catalog.length || new Set(ids).size !== ids.length || ids.some((id) => !catalog.some((entry) => entry.id === id))) throw new Error("Выбран MCP вне доступного каталога");
  return ids;
}

// Profile-specific names prevent two local profiles from sharing a credential.
// The ID is encoded without lossy dash/underscore normalization.
export function mcpEnvName(stateDir, id) {
  if (!idPattern.test(id)) throw new Error("Некорректный ID MCP");
  const profile = createHash("sha256").update(stateDir).digest("hex").slice(0, 12).toUpperCase();
  return `CORP_MCP_${profile}_${Buffer.from(id).toString("hex").toUpperCase()}_TOKEN`;
}

function configFor(stateDir, entry) {
  const env = mcpEnvName(stateDir, entry.id);
  return { name: `corp_${entry.id}`, config: {
    type: "remote", url: entry.url, oauth: false,
    headers: { Authorization: `Bearer {env:${env}}` },
  } };
}

export function readMCPState(stateDir, catalog) {
  return catalog.filter((entry) => validToken(process.env[mcpEnvName(stateDir, entry.id)])).map((entry) => configFor(stateDir, entry));
}

export function saveMCPSelection(stateDir, ids, catalog, tokens) {
  validateSelection(ids, catalog);
  if (!(tokens instanceof Map) || [...tokens.keys()].some((id) => !ids.includes(id))) throw new Error("Некорректный набор токенов MCP");
  // Validate every input before mutating the process environment.
  for (const id of ids) {
    const value = tokens.has(id) ? tokens.get(id) : process.env[mcpEnvName(stateDir, id)];
    if (!validToken(value)) throw new Error(`Требуется личный токен MCP: ${id}`);
  }
  for (const id of ids) if (tokens.has(id)) process.env[mcpEnvName(stateDir, id)] = tokens.get(id);
  for (const entry of catalog) if (!ids.includes(entry.id)) delete process.env[mcpEnvName(stateDir, entry.id)];
  return ids.map((id) => configFor(stateDir, catalog.find((entry) => entry.id === id)));
}

export function clearMCPEnv(stateDir) {
  const profile = createHash("sha256").update(stateDir).digest("hex").slice(0, 12).toUpperCase();
  for (const key of Object.keys(process.env)) if (key.startsWith(`CORP_MCP_${profile}_`) && key.endsWith("_TOKEN")) delete process.env[key];
}

export async function clearMCP(stateDir) {
  clearMCPEnv(stateDir);
  // Remove token files left by releases before the memory-only flow.
  await Promise.all([
    rm(join(stateDir, "mcp-selection.json"), { force: true }),
    rm(join(stateDir, "mcp-tokens"), { force: true, recursive: true }),
  ]);
}
