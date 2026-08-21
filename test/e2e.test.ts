import { describe, it, expect, afterEach } from 'vitest'
import { createMCPClient, listTools } from './utils.js'
import type { MCPClient } from './utils.js'

// These tests run against live third-party MCP servers, which add and rename tools
// without notice. Assert on a single stable "canary" tool per server to prove we
// reached that server and got its real tool list — pinning the full list turns any
// vendor-side rename into a red CI run on every open PR (see #280).
describe('MCP Remote E2E', () => {
  let client: MCPClient | null = null

  afterEach(async () => {
    if (client) {
      await client.cleanup()
      client = null
    }
  })

  it('connects to Hugging Face MCP server', async () => {
    client = await createMCPClient('https://huggingface.co/mcp')
    const tools = await listTools(client.client)
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('hf_whoami')
  }, 30000)

  it('connects to Cloudflare docs MCP server', async () => {
    client = await createMCPClient('https://docs.mcp.cloudflare.com/mcp')
    const tools = await listTools(client.client)
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('search_cloudflare_documentation')
  }, 30000)

  it('lists tools from Hugging Face', async () => {
    client = await createMCPClient('https://huggingface.co/mcp')
    const tools = await listTools(client.client)
    expect(tools.length).toBeGreaterThan(0)
    for (const tool of tools) {
      expect(typeof tool.name).toBe('string')
      expect(tool.name.length).toBeGreaterThan(0)
      expect(tool).toHaveProperty('inputSchema')
    }
  }, 30000)
})
