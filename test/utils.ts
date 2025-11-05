import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { ListToolsResultSchema, ListResourcesResultSchema, ListPromptsResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export interface MCPClient {
  client: Client
  cleanup: () => Promise<void>
}

/**
 * Spawns the mcp-remote proxy and connects via stdio
 */
export async function createMCPClient(serverUrl: string, args: string[] = []): Promise<MCPClient> {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [resolve(__dirname, '../dist/proxy.js'), serverUrl, ...args],
    env: process.env as Record<string, string>,
  })

  const client = new Client(
    {
      name: 'mcp-remote-test-client',
      version: '1.0.0',
    },
    {
      capabilities: {},
    },
  )

  await client.connect(transport)

  const cleanup = async () => {
    try {
      await client.close()
    } catch (e) {
      // Ignore cleanup errors
    }
  }

  return { client, cleanup }
}

/**
 * Safely lists tools from a server, handling servers that don't support tools
 */
export async function listTools(client: Client) {
  try {
    const response = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
    return response.tools || []
  } catch (err: any) {
    if (err.message?.includes('not supported') || err.code === -32601) {
      return []
    }
    throw err
  }
}

/**
 * Safely lists prompts from a server, handling servers that don't support prompts
 */
export async function listPrompts(client: Client) {
  try {
    const response = await client.request({ method: 'prompts/list' }, ListPromptsResultSchema)
    return response.prompts || []
  } catch (err: any) {
    if (err.message?.includes('not supported') || err.code === -32601) {
      return []
    }
    throw err
  }
}

/**
 * Safely lists resources from a server, handling servers that don't support resources
 */
export async function listResources(client: Client) {
  try {
    const response = await client.request({ method: 'resources/list' }, ListResourcesResultSchema)
    return response.resources || []
  } catch (err: any) {
    if (err.message?.includes('not supported') || err.code === -32601) {
      return []
    }
    throw err
  }
}

/**
 * Helper to verify a server connection works by listing capabilities
 */
export async function verifyConnection(client: Client) {
  const [tools, prompts, resources] = await Promise.all([listTools(client), listPrompts(client), listResources(client)])

  return {
    tools,
    prompts,
    resources,
    hasTools: tools.length > 0,
    hasPrompts: prompts.length > 0,
    hasResources: resources.length > 0,
  }
}
