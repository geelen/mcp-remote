# MCP-Remote Test Suite

E2E tests for mcp-remote connecting to public MCP servers.

## Architecture

The test suite uses the real mcp-remote client CLI to connect to public MCP servers over the internet. This validates the complete client flow without requiring local server setup.

```
┌─────────────────┐
│  Test Suite     │  ← Vitest running e2e.test.ts
│  (Node.js)      │
└────────┬────────┘
         │ spawns
         ↓
┌─────────────────┐
│  mcp-remote     │  ← node dist/client.js <url>
│  (client.ts)    │
└────────┬────────┘
         │ SSE/HTTP
         ↓
┌─────────────────┐
│  Public MCP     │  ← Hugging Face, Cloudflare, etc.
│  Servers        │
└─────────────────┘
```

## Setup

The test directory is completely isolated from the parent project:

```bash
cd test
pnpm install
```

## Running Tests

```bash
# Run all tests (builds mcp-remote first)
pnpm test

# Watch mode
pnpm test:watch
```

## Current Test Coverage

### Public Server E2E Tests (e2e.test.ts)

Tests the mcp-remote client connecting to real public MCP servers:

- **Hugging Face MCP Server** (`https://huggingface.co/mcp`)
  - SSE transport
  - Model/dataset search tools
  - No authentication required

- **Cloudflare MCP Server** (`https://mcp.cloudflare.com`)
  - HTTP transport
  - Various Cloudflare tools
  - No authentication required

### Test Utilities (utils.ts)

Helper functions to keep tests concise:

- `createMCPClient(url, args)` - Spawns mcp-remote client and connects via stdio
- `verifyConnection(client)` - Lists all capabilities (tools/prompts/resources)
- `listTools(client)` - Safely lists tools with fallback for unsupported servers
- `listPrompts(client)` - Safely lists prompts with fallback
- `listResources(client)` - Safely lists resources with fallback

All list functions handle:
- Servers that don't support the capability (returns empty array)
- Method not found errors (-32601)
- Timeouts (5 second default)

## Implementation Details

### Build Integration

Tests automatically build the parent mcp-remote project before running:
- `pnpm build:parent` runs `cd .. && pnpm build`
- Ensures `dist/client.js` exists
- Run by both `pnpm test` and `pnpm test:watch`

### Process Management

- Tests spawn the mcp-remote client as a subprocess
- MCP SDK's `StdioClientTransport` handles communication
- `afterEach` hooks ensure cleanup of spawned processes
- No background processes required

### Error Handling

Tests gracefully handle:
- Servers that don't support tools/prompts/resources
- Network timeouts and connection failures
- Method not found errors
- Server-specific capability variations

### Timeout Configuration

E2E tests use 30-second timeouts to accommodate:
- Network latency
- OAuth flows (future)
- Server response times

## Future Enhancements

See [PLAN.md](./PLAN.md) for the full roadmap:

- **Phase 1b**: Local test server for transport fallback testing
- **Phase 2**: GitHub Actions CI integration
- **Phase 3**: OAuth flow testing with simulator
- **Phase 4**: Comprehensive unit and integration tests

## Debugging

Run tests with debug output:

```bash
# Set debug environment variable
DEBUG=* pnpm test

# Or modify specific tests to add --debug flag
createMCPClient(url, ['--debug'])
```

## Adding New Tests

1. Use `createMCPClient()` to spawn the client
2. Use helper functions from `utils.ts` for common operations
3. Always clean up in `afterEach` hook
4. Set appropriate timeouts for network operations
5. Handle capability variations gracefully

Example:

```typescript
it('connects to new server', async () => {
  client = await createMCPClient('https://example.com/mcp')
  const result = await verifyConnection(client.client)
  expect(result.hasTools).toBe(true)
}, 30000)
```
