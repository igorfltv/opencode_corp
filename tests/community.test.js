import { test, expect } from "bun:test";
import { mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { communityCatalog, installCommunity, SUPERPOWERS_SPEC } from "../src/community.js";
import { atomicWrite } from "../src/io.js";
import { parseConfig } from "../src/config.js";
import caveman from "../community/caveman-plugin/index.js";
import { CorporateRuntime } from "../src/runtime.js";

async function profile(fn) {
  const root = await mkdtemp(join(tmpdir(), "community-skills-"));
  const options = { client: "opencode", configPath: join(root, "opencode.jsonc"), skillsDir: join(root, "skills") };
  await atomicWrite(options.configPath, '{\n // personal settings\n "plugins": ["other-plugin"]\n}\n');
  try { await fn(options); } finally { await rm(root, { recursive: true, force: true }); }
}

test("catalog separates OpenCode plugins from portable Kilo skills", () => {
  expect(communityCatalog("opencode").map((item) => item.id)).toEqual([
    "community-superpowers", "community-caveman", "community-grill-me", "community-react-best-practices",
  ]);
  expect(communityCatalog("kilo").map((item) => item.id)).toEqual(["community-grill-me", "community-react-best-practices"]);
});

test("installs complete skill bundles and pins plugin entries without replacing user config", async () => profile(async (options) => {
  const ids = communityCatalog("opencode").map((item) => item.id);
  expect(await installCommunity({ ids, ...options })).toHaveLength(4);
  const configText = await readFile(options.configPath, "utf8");
  expect(configText).toContain("// personal settings");
  const config = parseConfig(configText);
  expect(config.plugins).toContain("other-plugin");
  expect(config.plugins).toContain(SUPERPOWERS_SPEC);
  expect(config.plugins).toContain("./community-plugins/caveman");
  expect((await readFile(join(options.skillsDir, "grilling/SKILL.md"), "utf8"))).toContain("name: grilling");
  expect((await readFile(join(options.skillsDir, "vercel-react-best-practices/rules/async-parallel.md"), "utf8"))).toContain("Promise.all");
  expect((await readFile(join(options.skillsDir, "caveman/SKILL.md"), "utf8"))).toContain("name: caveman");
  expect((await readFile(join(options.skillsDir, "..", "community-plugins/caveman/index.js"), "utf8"))).toContain("community.caveman");
  await installCommunity({ ids, ...options });
  expect(parseConfig(await readFile(options.configPath, "utf8")).plugins).toHaveLength(3);
  await atomicWrite(join(options.skillsDir, "grilling/SKILL.md"), "user edited");
  await expect(installCommunity({ ids: ["community-grill-me"], ...options })).rejects.toThrow("изменён локально");
}));

test("rejects existing unowned package and symlinked intermediate directory", async () => profile(async (options) => {
  await atomicWrite(join(options.skillsDir, "grill-me/SKILL.md"), "personal");
  await expect(installCommunity({ ids: ["community-grill-me"], ...options })).rejects.toThrow("не управляется");
  await installCommunity({ ids: ["community-react-best-practices"], ...options });
  await rm(join(options.skillsDir, "vercel-react-best-practices/rules"), { recursive: true });
  await symlink(tmpdir(), join(options.skillsDir, "vercel-react-best-practices/rules"));
  await expect(installCommunity({ ids: ["community-react-best-practices"], ...options })).rejects.toThrow("Символическая ссылка");
}));

test("Kilo installs portable skills and leaves plugin configuration unchanged", async () => profile(async (options) => {
  const kilo = { ...options, client: "kilo" };
  const before = await readFile(options.configPath, "utf8");
  await installCommunity({ ids: ["community-grill-me"], ...kilo });
  expect(await readFile(options.configPath, "utf8")).toBe(before);
  expect((await readFile(join(options.skillsDir, "grilling/SKILL.md"), "utf8"))).toContain("name: grilling");
  await expect(installCommunity({ ids: ["community-superpowers"], ...kilo })).rejects.toThrow("несовместимый");
}));

test("Caveman V2 adapter registers a mode command and context hook", async () => {
  const hooks = new Map();
  let command;
  const disposed = [];
  const ctx = {
    session: {
      hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => disposed.push(name) }; },
      prompt: async () => {},
    },
    command: { transform: async (callback) => { callback({ add: (value) => { command = value; } }); return { dispose: async () => disposed.push("command") }; } },
  };
  const dispose = await caveman.setup(ctx);
  expect(command.name).toBe("caveman");
  const event = { sessionID: "one", system: [] };
  hooks.get("context")(event);
  expect(event.system).toHaveLength(0);
  await command.execute({ sessionID: "one", prompt: { text: "on" }, delivery: "steer" });
  hooks.get("context")(event);
  expect(event.system[0].text).toContain("Respond terse like smart caveman");
  hooks.get("prompt")({ sessionID: "one", prompt: { text: "stop caveman" } });
  event.system = [];
  hooks.get("context")(event);
  expect(event.system).toHaveLength(0);
  await dispose();
  expect(disposed).toHaveLength(3);
});

test("/skills_load works without login and never calls the corporate catalog", async () => profile(async (options) => {
  let form, message;
  const runtime = new CorporateRuntime(options, {
    api: { request: () => { throw new Error("corporate API must not be called"); } },
    bridge: {
      form: async (_sessionID, _title, fields) => { form = fields[0]; return { id: "one" }; },
      wait: async () => ({ skills: ["community-grill-me"] }),
      cancel: async () => {},
      message: async (_sessionID, _title, body) => { message = body; },
    },
  });
  await runtime.skills("session", async () => {});
  await Promise.all([...runtime.jobs]);
  expect(form.options.map((item) => item.value)).toContain("community-grill-me");
  expect(form.options.some((item) => item.value.startsWith("corp-"))).toBe(false);
  expect(message).toContain("Grill me");
  expect((await readFile(join(options.skillsDir, "grill-me/SKILL.md"), "utf8"))).toContain("name: grill-me");
}));
