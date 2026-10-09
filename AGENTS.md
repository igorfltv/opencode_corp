# Instructions for agents

These instructions apply to the whole `opencode_corp` repository. Read `README.md` and the relevant source and tests before changing behavior. This repository is the OpenCode/Kilo plugin; the parent `~/.config/kilo` directory is not its Git checkout.

## Project map

- `src/` contains the plugin logic. `src/plugin.js` is the OpenCode entrypoint, `src/tui.js` is the Kilo TUI entrypoint, and `src/commands.js` defines the shared slash commands. Keep command names and behavior consistent across OpenCode, Kilo TUI, and the generated Kilo workflows in `src/kilo-workflows.js`.
- `server/` is the local test backend and admin UI. It is a demo emulator, not a production identity provider or inference service.
- `community/` contains the curated public skill/plugin catalog, its pinned sources and licenses, and the file hashes in `community/manifest.json`.
- `tests/` contains unit and regression tests. `scripts/integration*.mjs` exercise running clients. `server.js` and `tui.js` are committed bundles built from `src/` because GitHub installations load them directly.

## Working rules

- Check `git status` before editing. Preserve unrelated worktree changes; stage and commit only files belonging to the task.
- Change source files rather than editing `server.js` or `tui.js` by hand. After a change to `src/` that affects either entrypoint, run `bun run bundle` and include the resulting bundles in the same commit. Review the generated diff, especially if bundles were already modified in the worktree.
- Keep OpenCode and Kilo configuration handling aligned while respecting their different JSONC paths and APIs. Preserve unrelated user settings and comments, reject malformed JSONC, and use atomic writes and backups where the existing code does.
- Keep credentials and MCP tokens out of repository files, JSONC literals, logs, forms returned to the model, and test output. Use only the emulator's test accounts and tokens in demos. Do not treat the emulator as production authentication.
- Preserve each community package's actual type: OpenCode plugins need a package directory with `package.json` and `index.js`; skills remain skills. Review upstream changes before updating pinned revisions, hashes, or license records. Keep installation opt-in, checksum-checked, atomic, and safe for user-modified files and symlinks.
- If runtime registration or hot reload changes, keep setup/disposal idempotent and test failed setup, retries, and cleanup. Do not assume a plugin is usable merely because it downloaded: check its active state and registered commands in the running client.
- Update `README.md` when setup, commands, supported clients, security behavior, or verification steps change.

## Verification

Install dependencies with `bun install --frozen-lockfile` when needed. For code changes, run `bun test tests` and the relevant checks below before delivery:

```sh
bun run bundle                 # required after src/ changes
bun run test:integration       # OpenCode behavior
bun run test:kilo              # Kilo behavior, when affected
bun run test:auto-login        # login or startup changes
bun run pack                   # packaging changes
```

For GitHub installation changes, use `bun run test:github` when the client and network are available. For live client checks, verify `/api/plugin` reports the plugin as `active` and `/api/command` contains all seven commands. Report which checks ran and any environment-dependent checks that could not run. A documentation-only change does not require code tests or rebuilding bundles.
