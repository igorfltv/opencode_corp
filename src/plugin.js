import { CorporateRuntime, optionsFromEnv } from "./runtime.js";
import { startKiloControl } from "./kilo-control.js";
import { installKiloWorkflows } from "./kilo-workflows.js";
import { mcpEnvName } from "./mcp.js";
import { syncOpenCodeMCP } from "./config.js";
import { registerOpenCodeCommands } from "./commands.js";

const rpc = {
  id: "company.corporate",
  methods: { status: { input: { type: "object", properties: {}, additionalProperties: false }, output: { type: "object" } } },
  events: { notice: { schema: { type: "object", properties: { message: { type: "string" }, level: { type: "string" }, at: { type: "number" } }, required: ["message", "level", "at"] } } },
};
// A changed runtime shape must not reuse an instance left by a hot-reloaded package.
const registryKey = Symbol.for("company.opencode.corporate.runtime.v9");

function release(registry, key, entry) {
  if (--entry.refs !== 0) return;
  entry.runtime.dispose();
  if (registry.get(key) === entry) registry.delete(key);
}

export default {
  id: "company-corporate",
  // Official Kilo clients load the same server plugin. The TUI has direct
  // commands; VS Code discovers the generated workflow files.
  async server(_context, settings) {
    await startKiloControl(settings);
    const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
    const { conflicts } = await installKiloWorkflows(options);
    if (conflicts.length) console.warn(`Существующие Kilo workflows сохранены: ${conflicts.join(", ")}`);
    return {};
  },
  async setup(context) {
    const options = optionsFromEnv(process.env, context.options);
    const registry = globalThis[registryKey] ??= new Map();
    const key = `${options.configPath}|${options.serverURL}`;
    let entry = registry.get(key);
    if (!entry) {
      const runtime = new CorporateRuntime(options, { syncMCP: (configs) => syncOpenCodeMCP(options.configPath, options.stateDir, configs) });
      entry = { runtime, ready: runtime.start(), refs: 0 };
      registry.set(key, entry);
    }
    entry.refs++;
    const runtime = entry.runtime;
    let mcpRegistration, rpcRegistration, reloadMCP, listener;
    try {
      await entry.ready;
      reloadMCP = () => context.mcp.reload();
      runtime.mcpReloaders.add(reloadMCP);
      mcpRegistration = await context.mcp.transform((editor) => {
        for (const [name] of editor.list()) if (name.startsWith("corp_")) editor.remove(name);
        if (runtime.authenticated()) for (const { name, config } of runtime.mcpConfigs) {
          const value = process.env[mcpEnvName(options.stateDir, name.slice(5))];
          if (value) editor.set(name, { ...config, headers: { Authorization: `Bearer ${value}` } });
        }
      });
      rpcRegistration = await context.rpc.register(rpc, { status: async () => runtime.status() });
      listener = (event) => rpcRegistration.events.emit("notice", event);
      runtime.listeners.add(listener);
      await registerOpenCodeCommands(context, runtime);
      if (!entry.autoLoginStarted) {
        entry.autoLoginStarted = true;
        void runtime.autoLogin();
      }
    } catch (error) {
      runtime.mcpReloaders.delete(reloadMCP);
      if (listener) runtime.listeners.delete(listener);
      rpcRegistration?.dispose?.();
      mcpRegistration?.dispose?.();
      release(registry, key, entry);
      throw error;
    }
    let disposed = false;
    return () => {
      if (disposed) return;
      disposed = true;
      runtime.mcpReloaders.delete(reloadMCP);
      mcpRegistration?.dispose?.();
      runtime.listeners.delete(listener);
      rpcRegistration.dispose?.();
      release(registry, key, entry);
    };
  },
};
