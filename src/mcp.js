import { readFile, rm, lstat, readdir } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite, trustedURL } from "./io.js";

const idPattern = /^[a-z][a-z0-9_-]{0,39}$/;
const text = (value, max = 200) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
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

export async function readMCPState(stateDir, catalog) {
  let selected;
  try { selected = JSON.parse(await readFile(join(stateDir, "mcp-selection.json"), "utf8")); }
  catch (error) { if (error.code === "ENOENT") return []; throw error; }
  if (!Array.isArray(selected)) return [];
  const allowed = selected.filter((id) => catalog.some((entry) => entry.id === id));
  const configurations = [];
  for (const id of allowed) {
    const entry = catalog.find((item) => item.id === id);
    let token;
    try {
      const path = join(stateDir, "mcp-tokens", id);
      if (!(await lstat(path)).isFile()) continue;
      token = await readFile(path, "utf8");
    }
    catch (error) { if (error.code === "ENOENT") continue; throw error; }
    if (!token || token.length > 512 || /[\r\n]/.test(token)) continue;
    configurations.push({ name: `corp_${id}`, config: { type: "remote", url: entry.url, oauth: false, headers: { Authorization: `Bearer ${token}` } } });
  }
  return configurations;
}

export async function saveMCPSelection(stateDir, ids, catalog, tokens) {
  validateSelection(ids, catalog);
  for (const id of ids) {
    const token = tokens.get(id);
    if (token !== undefined) {
      if (!text(token, 512) || /[\r\n]/.test(token)) throw new Error("Некорректный личный токен MCP");
      await atomicWrite(join(stateDir, "mcp-tokens", id), token);
    }
  }
  await atomicWrite(join(stateDir, "mcp-selection.json"), JSON.stringify(ids));
  const tokenDir = join(stateDir, "mcp-tokens");
  for (const name of await readdir(tokenDir).catch((error) => { if (error.code === "ENOENT") return []; throw error; })) {
    if (!ids.includes(name)) await rm(join(tokenDir, name), { force: true });
  }
  return readMCPState(stateDir, catalog);
}

export async function clearMCP(stateDir) {
  await Promise.all([
    rm(join(stateDir, "mcp-selection.json"), { force: true }),
    rm(join(stateDir, "mcp-tokens"), { force: true, recursive: true }),
  ]);
}
