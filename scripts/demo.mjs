import { launch } from "./harness.mjs";
import { openBrowser } from "../src/desktop.js";
import { atomicWrite } from "../src/io.js";
import { join } from "node:path";

const demo = await launch({ port: Number(process.env.PORT ?? 4310), quiet: false,
  refreshMs: Number(process.env.CORP_REFRESH_INTERVAL_MS ?? 3600000), loadPollMs: Number(process.env.CORP_LOAD_INTERVAL_MS ?? 30000) });
const pairURL = await demo.pair();
await atomicWrite(join(demo.directory, "open-browser.url"), pairURL);
await atomicWrite(join(demo.directory, "demo-info.json"), JSON.stringify({ url: demo.url, admin: `${demo.emulator.baseURL}/admin`, profile: demo.profile, sessionID: demo.session.id }, null, 2));
console.log(`OpenCode: ${demo.url}`);
console.log(`Панель эмулятора: ${demo.emulator.baseURL}/admin`);
console.log(`Тестовый конфиг: ${demo.configPath}`);
console.log("Открывается отдельный OpenCode в браузере. Создайте/откройте сессию и введите /login.");
console.log("Повторно открыть браузер: bun run demo:open. Остановка: Ctrl+C.");
await openBrowser(pairURL).catch(() => console.log(`Откройте одноразовую ссылку из ${join(demo.directory, "open-browser.url")}`));
await openBrowser(`${demo.emulator.baseURL}/admin`).catch(() => {});
let stopping = false;
async function stop() { if (stopping) return; stopping = true; await demo.stop(); process.exit(0); }
process.on("SIGINT", stop); process.on("SIGTERM", stop);
