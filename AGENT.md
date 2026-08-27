# AGENT.md - mcp-remote Development Guide

## Commands

- **Build**: `pnpm build` (or `pnpm build:watch` for development)
- **Lint + type check**: `pnpm lint` (`oxfmt --check`, `oxlint`, then `tsc` over both the package and `test/`) - this is the check, and it is what CI runs
- **Format**: `pnpm format` (`oxfmt .`) - this is the one that writes
- **Unused code**: `pnpm knip` - unused files, exports and dependencies. Also gates CI
- **Test**: `pnpm test` (or `pnpm test:watch` for watch mode)
- **E2E**: `cd test && pnpm install && pnpm test` - hits live third-party MCP servers, and gates merges in CI
- **Run dev**: `pnpm dev:client` or `pnpm dev:proxy` (tsx, no build step)

## Architecture

- **Project Type**: TypeScript ESM library for MCP (Model Context Protocol) remote proxy
- **Main Binaries**: `mcp-remote` (proxy.ts), `mcp-remote-client` (client.ts)
- **Core Libraries**: `/src/lib/` contains auth coordination, OAuth client, utils, types
- **Transport**: Supports both HTTP and SSE transports with OAuth authentication
- **Config**: Credentials live in `~/.mcp-auth/mcp-remote-v{store}/`, keyed by a hash of the server URL. The subdirectory names the _store layout_, not the package version, so releases do not discard anyone's sign-ins - raise `CONFIG_STORE_VERSION` only when something already on disk would be misread. `MCP_REMOTE_CONFIG_DIR` relocates the base directory

## Code Style

- **Formatting**: oxfmt with 140 char width, single quotes, no semicolons (`.oxfmtrc.json`, migrated from the Prettier config it replaced - output is byte-identical)
- **Linting**: oxlint (`.oxlintrc.json`) at `correctness`/`suspicious`/`perf`, denying warnings. Rules that fight deliberate conventions here are off with a reason in the config
- **Pre-commit**: husky runs `pnpm lint && pnpm knip && pnpm test` over the whole repo (~5s). Don't add exports "for later" - knip fails on them
- **Types**: Strict TypeScript, ES2022 target with bundler module resolution
- **Imports**: ES modules, use `.js` extensions for SDK imports
- **Error Handling**: EventEmitter pattern for auth flow coordination
- **Naming**: kebab-case for files, camelCase for variables/functions
- **Comments**: JSDoc for main functions, inline for complex auth flows
