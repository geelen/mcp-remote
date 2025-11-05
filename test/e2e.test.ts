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
    const tools = await listTools(client.client)
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('hf_whoami')
    expect(toolNames).toContain('model_search')
    expect(toolNames).toContain('dataset_search')
  }, 30000)

  it('connects to Cloudflare docs MCP server', async () => {
    client = await createMCPClient('https://docs.mcp.cloudflare.com/mcp')
    const tools = await listTools(client.client)
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('search_cloudflare_documentation')
    expect(toolNames).toContain('migrate_pages_to_workers_guide')
  }, 30000)

  it('lists tools from Hugging Face', async () => {
    client = await createMCPClient('https://huggingface.co/mcp')
    const tools = await listTools(client.client)
    expect(tools.length).toBeGreaterThan(0)
    expect(tools[0]).toHaveProperty('name')
    expect(tools[0]).toHaveProperty('description')
  }, 30000)
})
