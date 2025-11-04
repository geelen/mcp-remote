# MCP-Remote Test Plan

## Overview

This document outlines the testing strategy for `mcp-remote`, a proxy and client for connecting to remote MCP servers with OAuth support. The goal is to provide confidence that new PRs don't break core functionality while keeping the test infrastructure maintainable.

## Testing Challenges

- **Complex Environment**: CLI tool invoked by various MCP clients connecting to diverse MCP servers
- **OAuth Flows**: Browser-based authentication that's difficult to automate
- **Multi-instance Coordination**: Lockfile-based coordination between concurrent processes
- **Transport Diversity**: SSE, HTTP, and STDIO transports with fallback logic
- **Real-world Dependencies**: Testing requires both MCP clients and servers

## Client Selection

### Recommended: Simple Test Client with MCP SDK

**Build a minimal test client using `@modelcontextprotocol/sdk`** that:
- Spawns `mcp-remote` as a stdio subprocess (testing the real CLI)
- Connects via `StdioClientTransport` (how real MCP clients use it)
- Makes multiple requests in one session (tools/list, resources/list, prompts/list)
- Provides clean assertions on responses
- ~50 lines of TypeScript

This tests the **actual user flow**: spawning the proxy via CLI and communicating over stdio.

### Why Not Existing Tools?

- **client.ts**: Tests connecting *to* remote servers, not *invoking* mcp-remote as a CLI tool
- **MCP Inspector CLI**: Requires separate invocations per method (spawns process each time, unrealistic)
- **fast-agent**: Requires Go, real inference provider (Groq), and API keys - too complex

### Test Architecture

```
┌─────────────────┐
│  Test Client    │  ← Simple Node.js script using MCP SDK
│  (stdio)        │
└────────┬────────┘
         │ stdio
         ↓
┌─────────────────┐
│  mcp-remote     │  ← Spawned as: node dist/proxy.js <server-url>
│  (proxy.ts)     │
└────────┬────────┘
         │ SSE/HTTP
         ↓
┌─────────────────┐
│  Test MCP       │  ← Local server (Bun + @hono/mcp)
│  Server         │
└─────────────────┘
```

## Server Selection

### Phase 1: Public, Stateless, Authless Servers

To enable CI without secrets:

1. **Hugging Face MCP Server** (`@huggingface/mcp-server`)
   - Public, no auth required
   - Provides tools for model/dataset search
   - SSE transport
   - Can be run locally via `npx`

2. **Local Test Server** (custom)
   - Minimal Bun + `@hono/mcp` server
   - Controllable transport types (SSE-only, HTTP-only, both)
   - Controllable responses for error testing
   - No OAuth required for basic tests

3. **Cloudflare Workers MCP** (public endpoints)
   - Multiple demo servers available
   - HTTP transport
   - No auth for basic functionality

### Phase 2: OAuth Testing Servers

Once basic tests pass:

1. **OAuth Simulator** (custom, in-repo)
   - Minimal OAuth2 server for testing dynamic registration, token exchange, refresh
   - Controllable errors and timeouts
   - Runs locally in tests

2. **Example Server** (`https://example-server.modelcontextprotocol.io/`)
   - Real OAuth flow
   - Requires investigation of auth requirements
   - Good for manual/integration testing

### Phase 3: Advanced Scenarios

As needed for comprehensive coverage:

1. **Error Injection Server** (custom)
   - TLS errors (self-signed certs)
   - Connection failures, timeouts
   - Invalid responses

## Test Architecture

### Layer 1: Unit Tests

**Coverage**: Pure functions, utilities, parsing logic

```
test/unit/
├── utils.test.ts          # CLI parsing, header substitution, pattern matching
├── coordination.test.ts   # Lockfile logic (mocked filesystem)
├── oauth-client.test.ts   # Token storage, validation (mocked filesystem)
└── message-transforms.test.ts  # Ignored tools, clientInfo rewrite
```

**No external dependencies** - use mocks and stubs.

### Layer 2: Integration Tests

**Coverage**: Transport connections, OAuth flows, proxy behavior

```
test/integration/
├── transport.test.ts      # SSE/HTTP selection, fallback logic
├── oauth-flow.test.ts     # Auth flows with minimal OAuth simulator
├── proxy.test.ts          # Bidirectional message passing, filtering
└── multi-instance.test.ts # Coordination between concurrent processes
```

**Dependencies**: Local test servers (started/stopped by tests).

### Layer 3: E2E Smoke Tests

**Coverage**: Full client.ts and proxy.ts flows

```
test/e2e/
├── client-happy-path.test.ts  # Connect, list tools/resources
├── proxy-happy-path.test.ts   # STDIO bridge to remote server
└── error-scenarios.test.ts    # Common failure modes
```

**Dependencies**: Public MCP servers or local test servers.

## Test Scenarios (from Oracle Analysis)

### Priority 1: Core Connectivity

- [ ] **HTTP-first transport** connects to HTTP-only server
- [ ] **SSE-first transport** connects to SSE-only server  
- [ ] **HTTP-first fallback** to SSE when HTTP unavailable
- [ ] **SSE-first fallback** to HTTP when SSE unavailable
- [ ] **Client mode** lists tools and resources successfully
- [ ] **Proxy mode** bridges STDIO to remote server

### Priority 2: CLI Parsing & Configuration

- [ ] HTTPS enforcement (--allow-http flag)
- [ ] Transport strategy parsing (sse-only, http-only, sse-first, http-first)
- [ ] Header parsing with environment variable substitution
- [ ] --host flag affects redirect URL
- [ ] --ignore-tool patterns (wildcards, case-insensitive)
- [ ] --enable-proxy sets global HTTP proxy
- [ ] --auth-timeout validation and conversion
- [ ] Callback port selection (specified, reused, auto-assigned)

### Priority 3: OAuth Flows

- [ ] No auth server (skips OAuth entirely)
- [ ] Dynamic client registration (DCR)
- [ ] Static client metadata merge into DCR
- [ ] Static client info (bypasses DCR)
- [ ] Valid tokens reused (no browser)
- [ ] Expired access token triggers refresh
- [ ] Expired refresh token triggers re-auth
- [ ] --resource parameter in authorize URL
- [ ] Auth timeout handling
- [ ] Browser open failure (fallback message)

### Priority 4: Multi-instance Coordination

- [ ] Secondary instance waits for primary auth completion
- [ ] Stale lockfile detection and takeover
- [ ] Primary abort allows secondary takeover
- [ ] Windows skips lockfile (always primary)
- [ ] Lockfile cleanup on exit

### Priority 5: Proxy-specific Behavior

- [ ] clientInfo name rewrite ("via mcp-remote X.Y.Z")
- [ ] Ignored tools filtered from tools/list
- [ ] Ignored tools blocked in tools/call
- [ ] Bidirectional error propagation
- [ ] Clean shutdown on both sides

### Priority 6: Error Handling

- [ ] Self-signed certificate error guidance
- [ ] UnauthorizedError triggers OAuth
- [ ] OAuthError surfaced with context
- [ ] Debug logging (--debug flag)
- [ ] SIGINT cleanup handlers

## Phase 1: Initial Implementation

**Goal**: One E2E test passing in CI that exercises basic functionality.

### Deliverables

1. **Test Infrastructure**
   - [ ] Create `test/` directory structure
   - [ ] Add test script to package.json
   - [ ] Configure TypeScript for tests
   - [ ] Add test dependencies (vitest or node:test)

2. **Minimal Test Server**
   - [ ] Implement local MCP server (Bun + @hono/mcp or Node.js)
   - [ ] Supports SSE and/or HTTP transports
   - [ ] Returns fixed tools/resources/prompts lists
   - [ ] No auth required
   - [ ] Runs on random port, reports URL
   - [ ] Start/stop from tests

3. **Simple Test Client**
   - [ ] Spawns `mcp-remote` as subprocess with server URL
   - [ ] Connects via StdioClientTransport from MCP SDK
   - [ ] Requests tools/list, resources/list, prompts/list
   - [ ] Parses JSON responses for assertions
   - [ ] Handles cleanup (kill subprocess)

4. **Basic E2E Test**
   - [ ] Build mcp-remote: `pnpm build`
   - [ ] Start local test server (get URL)
   - [ ] Spawn `node dist/proxy.js <url>` as stdio
   - [ ] Connect test client to subprocess
   - [ ] Assert tools list is correct
   - [ ] Assert resources list is correct
   - [ ] Assert prompts list is correct (if applicable)
   - [ ] Clean shutdown

5. **GitHub Actions**
   - [ ] Workflow runs `pnpm build`
   - [ ] Workflow runs `pnpm test:e2e`
   - [ ] Uses local test server (no secrets needed)
   - [ ] Runs on PRs and main branch

### Success Criteria

- ✅ One test passing that invokes the real CLI (`node dist/proxy.js`) over stdio
- ✅ Test makes multiple MCP requests in one session (realistic usage)
- ✅ Test runs in CI without manual intervention or secrets
- ✅ Foundation for adding transport variations (SSE vs HTTP) and error scenarios

## Phase 2: OAuth Coverage

**Goal**: Test OAuth flows with simulated auth server.

### Deliverables

1. **OAuth Simulator**
   - [ ] Minimal OAuth2 server (registration, authorize, token, refresh endpoints)
   - [ ] Controllable errors and delays
   - [ ] In-process for fast tests

2. **OAuth Tests**
   - [ ] Dynamic client registration flow
   - [ ] Token exchange and refresh
   - [ ] Static client metadata/info scenarios
   - [ ] Auth timeout handling

## Phase 3: Comprehensive Coverage

**Goal**: Exercise all code paths from Oracle analysis.

### Deliverables

1. **Full Test Matrix**
   - [ ] All CLI parsing scenarios
   - [ ] All transport fallback combinations
   - [ ] Multi-instance coordination
   - [ ] Proxy message filtering
   - [ ] Error injection and handling

2. **Real-world Server Tests** (optional)
   - [ ] Hugging Face server integration
   - [ ] Cloudflare endpoints
   - [ ] Example server with OAuth (if accessible)

## Test Server Specifications

### Minimal Test Server Requirements

For comprehensive testing, we need servers that can:

1. **Transport Variants**
   - SSE-only mode
   - HTTP-only mode  
   - Both SSE and HTTP (for fallback testing)

2. **Auth Variants**
   - No auth
   - OAuth with dynamic registration
   - OAuth with static client info
   - Auth errors (401, invalid tokens)

3. **Response Control**
   - Fixed tools/resources lists
   - Error responses (500, schema violations)
   - Connection drops, timeouts
   - TLS errors (self-signed certs)

4. **Lifecycle**
   - Start/stop programmatically
   - Random port assignment
   - Clean shutdown

### Known Public Servers (for reference)

| Server | Transport | Auth | Tools | Use Case |
|--------|-----------|------|-------|----------|
| Hugging Face | SSE | None | Model/dataset search | Phase 1 basic connectivity |
| Cloudflare | HTTP | None | Various | Phase 1 HTTP transport |
| Example Server | SSE | OAuth? | Unknown | Phase 2 OAuth (needs investigation) |

## Out of Scope (for now)

- Full agent integration testing (e.g., with fast-agent + real inference)
- Browser automation for OAuth flows (Playwright)
- Cross-platform OAuth coordination stress tests
- Real proxy server testing (--enable-proxy with Squid)
- Real TLS/VPN scenarios
- Performance/load testing

## Next Steps

1. ✅ Create test directory and plan (this document)
2. Create minimal local test server
3. Write first E2E test (client.ts → local server)
4. Set up GitHub Actions workflow
5. Incrementally add unit and integration tests

## Notes

- Keep Phase 1 simple: one passing test is better than ambitious plans
- Use existing `client.ts` as the test client - it's perfect for our needs
- Build test servers in-repo rather than depending on external infrastructure
- Add complexity gradually as tests prove valuable
- Prefer deterministic tests over flaky timing-dependent scenarios
