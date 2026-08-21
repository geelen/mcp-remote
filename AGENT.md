# AGENT.md - mcp-remote Development Guide

## Commands

- **Build**: `pnpm build` (or `pnpm build:watch` for development)
- **Type check**: `pnpm check` (runs prettier and tsc)
- **Lint/Format**: `pnpm lint-fix` (prettier with write)
- **Test**: `pnpm test:unit` (or `pnpm test:unit:watch` for watch mode)
- **Run dev**: `npx tsx src/client.ts` or `npx tsx src/proxy.ts`

## Architecture

- **Project Type**: TypeScript ESM library for MCP (Model Context Protocol) remote proxy
- **Main Binaries**: `mcp-remote` (proxy.ts), `mcp-remote-client` (client.ts)
- **Core Libraries**: `/src/lib/` contains auth coordination, OAuth client, utils, types
- **Transport**: Supports both HTTP and SSE transports with OAuth authentication
- **Config**: Uses `~/.mcp-auth/` directory for credential storage

## Code Style

- **Formatting**: Prettier with 140 char width, single quotes, no semicolons
- **Types**: Strict TypeScript, ES2022 target with bundler module resolution
- **Imports**: ES modules, use `.js` extensions for SDK imports
- **Error Handling**: EventEmitter pattern for auth flow coordination
- **Naming**: kebab-case for files, camelCase for variables/functions
- **Comments**: JSDoc for main functions, inline for complex auth flows
