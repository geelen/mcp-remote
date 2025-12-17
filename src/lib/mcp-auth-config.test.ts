import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import os from 'os'
import path from 'path'

// We need to mock the module before importing getConfigDir
// Store original env
const originalEnv = { ...process.env }

describe('Feature: Config Directory Path Resolution', () => {
  beforeEach(() => {
    // Reset modules to ensure fresh imports with new env values
    vi.resetModules()
    // Reset env to original state
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = { ...originalEnv }
  })

  it('Scenario: Returns mcp-remote subdirectory by default (version-agnostic)', async () => {
    // Given no environment variables are set for versioned config
    delete process.env.MCP_REMOTE_CONFIG_DIR
    delete process.env.MCP_REMOTE_VERSIONED_CONFIG

    // When getting the config directory
    const { getConfigDir } = await import('./mcp-auth-config')
    const result = getConfigDir()

    // Then it should return the mcp-remote subdirectory (namespaced but version-agnostic)
    expect(result).toBe(path.join(os.homedir(), '.mcp-auth', 'mcp-remote'))
  })

  it('Scenario: Returns versioned directory when MCP_REMOTE_VERSIONED_CONFIG=1', async () => {
    // Given MCP_REMOTE_VERSIONED_CONFIG is set to 1
    delete process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_VERSIONED_CONFIG = '1'

    // When getting the config directory
    const { getConfigDir } = await import('./mcp-auth-config')
    const result = getConfigDir()

    // Then it should return a version-specific directory
    expect(result).toMatch(/\.mcp-auth[/\\]mcp-remote-\d+\.\d+\.\d+/)
  })

  it('Scenario: Respects MCP_REMOTE_CONFIG_DIR with mcp-remote subdirectory', async () => {
    // Given a custom config directory is set
    process.env.MCP_REMOTE_CONFIG_DIR = '/custom/path'
    delete process.env.MCP_REMOTE_VERSIONED_CONFIG

    // When getting the config directory
    const { getConfigDir } = await import('./mcp-auth-config')
    const result = getConfigDir()

    // Then it should return the custom path with mcp-remote subdirectory
    expect(result).toBe(path.join('/custom/path', 'mcp-remote'))
  })

  it('Scenario: Combines custom dir with versioned config', async () => {
    // Given both custom config dir and versioned config are set
    process.env.MCP_REMOTE_CONFIG_DIR = '/custom/path'
    process.env.MCP_REMOTE_VERSIONED_CONFIG = '1'

    // When getting the config directory
    const { getConfigDir } = await import('./mcp-auth-config')
    const result = getConfigDir()

    // Then it should return the custom path with version suffix
    expect(result).toMatch(/[/\\]custom[/\\]path[/\\]mcp-remote-\d+\.\d+\.\d+/)
  })

  it('Scenario: MCP_REMOTE_VERSIONED_CONFIG with value other than 1 is ignored', async () => {
    // Given MCP_REMOTE_VERSIONED_CONFIG is set to something other than '1'
    delete process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_VERSIONED_CONFIG = 'true'

    // When getting the config directory
    const { getConfigDir } = await import('./mcp-auth-config')
    const result = getConfigDir()

    // Then it should return the mcp-remote subdirectory (version-agnostic default)
    expect(result).toBe(path.join(os.homedir(), '.mcp-auth', 'mcp-remote'))
  })
})
