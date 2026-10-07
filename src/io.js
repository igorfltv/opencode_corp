import { mkdir, open, rename, lstat, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomBytes, createHash } from "node:crypto";

export const random = () => randomBytes(32).toString("base64url");
export const digest = (text) => createHash("sha256").update(text).digest("hex");
export const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) return reject(new Error("Операция отменена"));
  const timer = setTimeout(done, ms);
  function done() { signal?.removeEventListener("abort", cancel); resolve(); }
  function cancel() { clearTimeout(timer); signal?.removeEventListener("abort", cancel); reject(new Error("Операция отменена")); }
  signal?.addEventListener("abort", cancel, { once: true });
});
export async function exists(path) { try { return await lstat(path); } catch (e) { if (e.code === "ENOENT") return null; throw e; } }
export async function atomicWrite(path, text) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  if ((await exists(path))?.isSymbolicLink()) throw new Error("Отказ записи через символическую ссылку");
  const temp = `${path}.${random()}.tmp`;
  const handle = await open(temp, "wx", 0o600);
  try { await handle.writeFile(text); await handle.sync(); } finally { await handle.close(); }
  await rename(temp, path);
}
export async function readJSON(path, fallback = null) {
  try { return JSON.parse(await readFile(path, "utf8")); } catch (e) { if (e.code === "ENOENT") return fallback; throw e; }
}
export function trustedURL(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) throw new Error("Некорректный адрес сервера");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) {
    throw new Error("Сервер должен использовать HTTPS (HTTP разрешён только на loopback)");
  }
  return url.href.replace(/\/$/, "");
}
export function serial() {
  let tail = Promise.resolve();
  return (fn) => { const next = tail.then(fn, fn); tail = next.catch(() => {}); return next; };
}
export const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
