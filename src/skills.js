import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite, digest, exists } from "./io.js";

export function validateCatalog(data) {
  if (!Array.isArray(data?.skills) || data.skills.length > 40) throw new Error("Некорректный каталог skills");
  const seen = new Set();
  for (const skill of data.skills) {
    if (!/^corp-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(skill.id) || skill.id.length > 80 || seen.has(skill.id)) throw new Error("Некорректный идентификатор skill");
    seen.add(skill.id);
    if (typeof skill.name !== "string" || skill.name.length > 100 || typeof skill.description !== "string" || skill.description.length > 500 || !/^[a-f0-9]{64}$/.test(skill.sha256) || typeof skill.version !== "string") throw new Error("Некорректные метаданные skill");
  }
  return data.skills;
}
export async function installSkills({ ids, catalog, api, token, skillsDir, signal }) {
  if (!Array.isArray(ids) || new Set(ids).size !== ids.length || ids.length > 40) throw new Error("Некорректный выбор skills");
  const selected = ids.map((id) => {
    const skill = catalog.find((entry) => entry.id === id);
    if (!skill) throw new Error("Выбран skill вне доступного каталога");
    return skill;
  });
  const downloads = [];
  // Validate every download and existing file before starting the batch of writes.
  if ((await exists(skillsDir))?.isSymbolicLink()) throw new Error("Каталог skills не должен быть символической ссылкой");
  for (const skill of selected) {
    const { data } = await api.request(`/api/skills/${encodeURIComponent(skill.id)}`, { token, signal });
    if (typeof data?.content !== "string" || data.content.length > 100000 || digest(data.content) !== skill.sha256) throw new Error(`Контрольная сумма не совпала: ${skill.id}`);
    if (!data.content.startsWith(`---\nname: ${skill.id}\n`)) throw new Error("Имя в SKILL.md не совпадает с каталогом");
    const directory = join(skillsDir, skill.id);
    if ((await exists(directory))?.isSymbolicLink()) throw new Error("Отказ установки через символическую ссылку");
    const target = join(directory, "SKILL.md");
    const marker = join(directory, ".corporate-sha256");
    if (await exists(target)) {
      const ownedHash = await readFile(marker, "utf8").catch(() => "");
      if (digest(await readFile(target, "utf8")) !== ownedHash) throw new Error(`Skill ${skill.id} изменён локально; перезапись отменена`);
    }
    downloads.push({ directory, target, marker, content: data.content, hash: skill.sha256 });
  }
  for (const item of downloads) {
    await mkdir(item.directory, { recursive: true, mode: 0o700 });
    await atomicWrite(item.target, item.content);
    await atomicWrite(item.marker, item.hash);
  }
  return selected.map((skill) => skill.id);
}
