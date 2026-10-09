import { readFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse, modify, applyEdits } from "jsonc-parser";
import manifest from "../community/manifest.json" with { type: "json" };
import { atomicWrite, digest, exists } from "./io.js";

export const SUPERPOWERS_SPEC = "superpowers@git+https://github.com/obra/superpowers.git#8ca22dba9a94f28898bbce59f2537ff4d87c747d";
const CAVEMAN_SPEC = "./community-plugins/caveman";
const packages = Object.freeze([
  { id: "community-superpowers", name: "Superpowers", kind: "plugin", client: "opencode", version: "8ca22db", description: "Методика разработки и набор skills; OpenCode V2 plugin (obra/superpowers)." },
  { id: "community-caveman", name: "Caveman", kind: "plugin", client: "opencode", version: "2e08b91", description: "Краткие ответы с сохранением фактов; OpenCode V2 адаптер, /caveman on|off." },
  { id: "community-grill-me", name: "Grill me", kind: "skill", version: "b0618bc", description: "Проверка идеи вопросами; включает зависимый grilling (mattpocock/skills)." },
  { id: "community-react-best-practices", name: "React Best Practices", kind: "skill", version: "063bee9", description: "70 правил производительности React/Next.js от Vercel; для frontend задач." },
]);

export function communityCatalog(client) {
  return packages.filter((item) => !item.client || item.client === client);
}

function packageFiles(id) {
  const prefixes = {
    "community-caveman": ["caveman/", "ultracave/", "megacave/", "caveman-plugin/"],
    "community-grill-me": ["grill-me/", "grilling/"],
    "community-react-best-practices": ["vercel-react-best-practices/"],
  }[id] ?? [];
  return Object.keys(manifest).filter((path) => prefixes.some((prefix) => path.startsWith(prefix)));
}

async function assetRoot() {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [join(here, "community"), join(here, "..", "community")]) {
    if (await exists(join(candidate, "manifest.json"))) return candidate;
  }
  throw new Error("В пакете отсутствует каталог community skills");
}

function destination(path, { skillsDir, configPath }) {
  if (path.startsWith("caveman-plugin/")) return join(dirname(configPath), "community-plugins", "caveman", path.slice("caveman-plugin/".length));
  return join(skillsDir, path);
}

function ownerFile(folder) { return join(folder, ".community-source.json"); }

async function preflightGroup(files, group, options) {
  const marker = ownerFile(group);
  const parent = await exists(group);
  if (parent?.isSymbolicLink()) throw new Error(`Символическая ссылка запрещена: ${group}`);
  let owned = null;
  if (await exists(marker)) {
    try { owned = JSON.parse(await readFile(marker, "utf8")); } catch { throw new Error(`Повреждён маркер установки: ${marker}`); }
    if (!owned || typeof owned.files !== "object") throw new Error(`Повреждён маркер установки: ${marker}`);
  } else if (parent) throw new Error(`Каталог ${group} уже существует и не управляется /skills_load`);
  for (const path of files) {
    const target = destination(path, options);
    for (let parentPath = dirname(target); parentPath !== group && parentPath.startsWith(`${group}/`); parentPath = dirname(parentPath)) {
      if ((await exists(parentPath))?.isSymbolicLink()) throw new Error(`Символическая ссылка запрещена: ${parentPath}`);
    }
    const stat = await exists(target);
    if (stat?.isSymbolicLink()) throw new Error(`Символическая ссылка запрещена: ${target}`);
    if (stat) {
      if (!owned?.files?.[path] || digest(await readFile(target)) !== owned.files[path]) throw new Error(`Файл изменён локально: ${target}`);
    } else if (owned?.files?.[path]) throw new Error(`Файл управляемого skill удалён: ${target}`);
  }
  return { group, marker, files };
}

function configPlugins(text) {
  const errors = [];
  const parsed = parse(text, errors, { allowTrailingComma: true });
  if (errors.length || !parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Некорректный opencode.jsonc");
  if (parsed.plugins !== undefined && !Array.isArray(parsed.plugins)) throw new Error("plugins должен быть массивом");
  return parsed.plugins ?? [];
}

async function addPlugins(configPath, wanted) {
  if (!wanted.length) return [];
  const text = await readFile(configPath, "utf8");
  const current = configPlugins(text);
  for (const spec of wanted) {
    const name = spec === CAVEMAN_SPEC ? "caveman" : "superpowers";
    if (current.some((entry) => JSON.stringify(entry).toLowerCase().includes(name) && entry !== spec)) {
      throw new Error(`${name} уже подключён другим способом; проверьте plugins в ${configPath}`);
    }
  }
  const added = wanted.filter((spec) => !current.includes(spec));
  if (!added.length) return [];
  const next = applyEdits(text, modify(text, ["plugins"], [...current, ...added], { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  configPlugins(next);
  const backup = `${configPath}.before-community.bak`;
  if (!await exists(backup)) await atomicWrite(backup, text);
  await atomicWrite(configPath, next);
  return added;
}

export async function installCommunity({ ids, client, skillsDir, configPath }) {
  const catalog = communityCatalog(client);
  if (!Array.isArray(ids) || ids.length > catalog.length || new Set(ids).size !== ids.length) throw new Error("Некорректный выбор community skills");
  const selected = ids.map((id) => {
    const item = catalog.find((entry) => entry.id === id);
    if (!item) throw new Error("Выбран неизвестный или несовместимый community skill");
    return item;
  });
  if (!selected.length) return [];
  if ((await exists(skillsDir))?.isSymbolicLink()) throw new Error("Каталог skills не должен быть символической ссылкой");
  const root = await assetRoot();
  const all = new Map();
  const groups = new Map();
  for (const item of selected) for (const path of packageFiles(item.id)) {
    const content = await readFile(join(root, path));
    if (digest(content) !== manifest[path]) throw new Error(`Повреждён файл поставки: ${path}`);
    const target = destination(path, { skillsDir, configPath });
    const group = path.startsWith("caveman-plugin/") ? join(dirname(configPath), "community-plugins", "caveman") : join(skillsDir, path.split("/")[0]);
    all.set(path, { target, content, group });
    groups.set(group, [...(groups.get(group) ?? []), path]);
  }
  const preflight = [];
  for (const [group, files] of groups) preflight.push(await preflightGroup(files, group, { skillsDir, configPath }));
  // Check config conflicts before writing the files. OpenCode reloads the new
  // plugin entries after all local package files have been installed.
  const wanted = client === "opencode" ? selected.filter((item) => item.kind === "plugin").map((item) => item.id === "community-caveman" ? CAVEMAN_SPEC : SUPERPOWERS_SPEC) : [];
  if (wanted.length) {
    const current = configPlugins(await readFile(configPath, "utf8"));
    for (const spec of wanted) {
      const name = spec === CAVEMAN_SPEC ? "caveman" : "superpowers";
      if (current.some((entry) => JSON.stringify(entry).toLowerCase().includes(name) && entry !== spec)) throw new Error(`${name} уже подключён другим способом`);
    }
  }
  for (const { group, marker, files } of preflight) {
    await mkdir(group, { recursive: true, mode: 0o700 });
    for (const path of files) {
      const { target, content } = all.get(path);
      await atomicWrite(target, content);
    }
    await atomicWrite(marker, JSON.stringify({ files: Object.fromEntries(files.map((path) => [path, manifest[path]])) }, null, 2));
  }
  await addPlugins(configPath, wanted);
  return selected.map((item) => `${item.name} (${item.kind === "plugin" ? "plugin" : "skill"})`);
}
