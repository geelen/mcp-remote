# AGENT.md - mcp-remote Development Guide

## Commands

- **Build**: `pnpm build` (or `pnpm build:watch` for development)
- **Type check**: `pnpm check` (runs prettier and tsc)
- **Lint/Format**: `pnpm lint-fix` (prettier with write)
- **Test Unit**: `pnpm test:unit` (or `pnpm test:unit:watch` for watch mode)
- **Test E2E**: `cd test && pnpm test` (or `pnpm test:watch` for watch mode)
- **Run dev**: `npx tsx src/client.ts` or `npx tsx src/proxy.ts`

## Pre-Commit Workflow

**CRITICAL**: Always run these commands in order before committing and pushing:

1. `pnpm lint-fix` - Format all files with Prettier
2. `pnpm check` - Verify formatting and run TypeScript type checking
3. `git add <files>` - Stage your changes
4. `git commit -m "message"` - Commit with descriptive message
5. `git push` - Push to remote

**Never commit without running both `pnpm lint-fix` AND `pnpm check` first.**

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
