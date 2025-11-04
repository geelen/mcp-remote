import { describe, it, expect, afterEach } from 'vitest'
import { createMCPClient, verifyConnection, listTools } from './utils.js'
import type { MCPClient } from './utils.js'

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
    const result = await verifyConnection(client.client)
    expect(result.hasTools || result.hasResources || result.hasPrompts).toBe(true)
  }, 30000)

  it('connects to Cloudflare MCP server', async () => {
    client = await createMCPClient('https://mcp.cloudflare.com')
    const result = await verifyConnection(client.client)
    expect(result.hasTools || result.hasResources || result.hasPrompts).toBe(true)
  }, 30000)

  it('lists tools from Hugging Face', async () => {
    client = await createMCPClient('https://huggingface.co/mcp')
    const tools = await listTools(client.client)
    if (tools.length > 0) {
      expect(tools[0]).toHaveProperty('name')
      expect(tools[0]).toHaveProperty('description')
    }
  }, 30000)
})
