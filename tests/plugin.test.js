import { test, expect } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import plugin from "../src/plugin.js";
import { commands } from "../src/commands.js";
import { atomicWrite } from "../src/io.js";

const registry = () => globalThis[Symbol.for("company.opencode.corporate.runtime.v9")];

function context(root, calls, failRPC = false) {
  return {
    options: { profileDir: root, serverURL: "http://127.0.0.1:4310" },
    mcp: {
      reload: async () => {},
      transform: async (callback) => {
        await callback({ list: () => [["corp_old", {}]], remove: () => calls.removed++, set: () => {} });
        return { dispose: () => calls.mcpDisposed++ };
      },
    },
    rpc: { register: async () => {
      if (failRPC) throw new Error("RPC unavailable");
      return { events: { emit: () => {} }, dispose: () => calls.rpcDisposed++ };
    } },
    command: { transform: async (callback) => callback({ add: (definition) => calls.commandNames.push(definition.name) }) },
    skill: { reload: async () => {} },
  };
}

test("OpenCode setup shares a runtime and releases every registration once", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-plugin-"));
  const key = `${join(root, "opencode.jsonc")}|http://127.0.0.1:4310`;
  const calls = { removed: 0, mcpDisposed: 0, rpcDisposed: 0, commandNames: [] };
  const previous = process.env.CORP_NO_BROWSER;
  process.env.CORP_NO_BROWSER = "1";
  let first, second;
  try {
    await atomicWrite(join(root, "opencode.jsonc"), "{}");
    first = await plugin.setup(context(root, calls));
    second = await plugin.setup(context(root, calls));
    expect(registry().get(key).refs).toBe(2);
    expect(calls.commandNames).toEqual([...commands, ...commands].map(({ name }) => name));
    first(); first();
    expect(registry().get(key).refs).toBe(1);
    second(); second();
    expect(registry().has(key)).toBe(false);
    expect(calls.mcpDisposed).toBe(2);
    expect(calls.rpcDisposed).toBe(2);
  } finally {
    first?.(); second?.();
    if (previous === undefined) delete process.env.CORP_NO_BROWSER;
    else process.env.CORP_NO_BROWSER = previous;
    await rm(root, { force: true, recursive: true });
  }
});

test("failed setup cleans up and allows a later retry", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-plugin-"));
  const key = `${join(root, "opencode.jsonc")}|http://127.0.0.1:4310`;
  const calls = { removed: 0, mcpDisposed: 0, rpcDisposed: 0, commandNames: [] };
  const previous = process.env.CORP_NO_BROWSER;
  process.env.CORP_NO_BROWSER = "1";
  let dispose;
  try {
    await atomicWrite(join(root, "opencode.jsonc"), "{}");
    await expect(plugin.setup(context(root, calls, true))).rejects.toThrow("Что сделать:");
    expect(registry().has(key)).toBe(false);
    expect(calls.mcpDisposed).toBe(1);
    dispose = await plugin.setup(context(root, calls));
    expect(registry().get(key).refs).toBe(1);
  } finally {
    dispose?.();
    if (previous === undefined) delete process.env.CORP_NO_BROWSER;
    else process.env.CORP_NO_BROWSER = previous;
    await rm(root, { force: true, recursive: true });
  }
});

test("failed runtime initialization does not poison the registry", async () => {
  const root = await mkdtemp(join(tmpdir(), "corporate-plugin-"));
  const key = `${join(root, "opencode.jsonc")}|http://127.0.0.1:4310`;
  const calls = { removed: 0, mcpDisposed: 0, rpcDisposed: 0, commandNames: [] };
  const previous = process.env.CORP_NO_BROWSER;
  process.env.CORP_NO_BROWSER = "1";
  let dispose;
  try {
    await atomicWrite(join(root, "opencode.jsonc"), "{ broken");
    await expect(plugin.setup(context(root, calls))).rejects.toThrow("Проверьте синтаксис");
    expect(registry().has(key)).toBe(false);
    await atomicWrite(join(root, "opencode.jsonc"), "{}");
    dispose = await plugin.setup(context(root, calls));
    expect(registry().get(key).refs).toBe(1);
  } finally {
    dispose?.();
    if (previous === undefined) delete process.env.CORP_NO_BROWSER;
    else process.env.CORP_NO_BROWSER = previous;
    await rm(root, { force: true, recursive: true });
  }
});
