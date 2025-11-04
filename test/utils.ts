import { spawn } from 'child_process'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import type { ChildProcess } from 'child_process'

export interface MCPClient {
  client: Client
  process: ChildProcess
  cleanup: () => Promise<void>
}

/**
 * Spawns the mcp-remote client and connects via stdio
 */
export async function createMCPClient(serverUrl: string, args: string[] = []): Promise<MCPClient> {
  const clientProcess = spawn('node', ['../dist/client.js', serverUrl, ...args], {
    cwd: __dirname,
    stdio: ['pipe', 'pipe', 'inherit'],
  })

  const transport = new StdioClientTransport({
    command: 'node',
    args: ['../dist/client.js', serverUrl, ...args],
    env: process.env,
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
    clientProcess.kill()
  }

  return { client, process: clientProcess, cleanup }
}

/**
 * Safely lists tools from a server, handling servers that don't support tools
 */
export async function listTools(client: Client) {
  try {
    const response = await client.request({ method: 'tools/list' }, { timeout: 5000 })
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
    const response = await client.request({ method: 'prompts/list' }, { timeout: 5000 })
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
    const response = await client.request({ method: 'resources/list' }, { timeout: 5000 })
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
