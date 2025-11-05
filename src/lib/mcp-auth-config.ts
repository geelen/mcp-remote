import path from 'path'
import os from 'os'
import fs from 'fs/promises'
import { log, MCP_REMOTE_VERSION } from './utils'

/**
 * MCP Remote Authentication Configuration
 *
 * This module handles the storage and retrieval of authentication-related data for MCP Remote.
 *
 * Configuration directory structure:
 * - The config directory is determined by MCP_REMOTE_CONFIG_DIR env var or defaults to ~/.mcp-auth
 * - Each file is prefixed with a hash of the server URL to separate configurations for different servers
 *
 * Files stored in the config directory:
 * - {server_hash}_client_info.json: Contains OAuth client registration information
 *   - Format: OAuthClientInformation object with client_id and other registration details
 * - {server_hash}_tokens.json: Contains OAuth access and refresh tokens
 *   - Format: OAuthTokens object with access_token, refresh_token, and expiration information
 * - {server_hash}_code_verifier.txt: Contains the PKCE code verifier for the current OAuth flow
 *   - Format: Plain text string used for PKCE verification
 *
 * All JSON files are stored with 2-space indentation for readability.
 */

/**
 * Lockfile data structure
 */
export interface LockfileData {
  pid: number
  port: number
  timestamp: number
}

/**
 * Creates a lockfile for the given server
 * @param serverUrlHash The hash of the server URL
 * @param pid The process ID
 * @param port The port the server is running on
 */
export async function createLockfile(serverUrlHash: string, pid: number, port: number): Promise<void> {
  const lockData: LockfileData = {
    pid,
    port,
    timestamp: Date.now(),
  }
  await writeJsonFile(serverUrlHash, 'lock.json', lockData)
}

/**
 * Checks if a lockfile exists for the given server
 * @param serverUrlHash The hash of the server URL
 * @returns The lockfile data or null if it doesn't exist
 */
export async function checkLockfile(serverUrlHash: string): Promise<LockfileData | null> {
  try {
    const lockfile = await readJsonFile<LockfileData>(serverUrlHash, 'lock.json', {
      async parseAsync(data: any) {
        if (typeof data !== 'object' || data === null) return null
        if (typeof data.pid !== 'number' || typeof data.port !== 'number' || typeof data.timestamp !== 'number') {
          return null
        }
        return data as LockfileData
      },
    })
    return lockfile || null
  } catch {
    return null
  }
}

/**
 * Deletes the lockfile for the given server
 * @param serverUrlHash The hash of the server URL
 */
export async function deleteLockfile(serverUrlHash: string): Promise<void> {
  await deleteConfigFile(serverUrlHash, 'lock.json')
}

/**
 * Gets the configuration directory path
 * @returns The path to the configuration directory
 */
export function getConfigDir(): string {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
  // Add a version subdirectory so we don't need to worry about backwards/forwards compatibility yet
  return path.join(baseConfigDir, `mcp-remote-${MCP_REMOTE_VERSION}`)
}

/**
 * Ensures the configuration directory exists
 */
export async function ensureConfigDir(): Promise<void> {
  try {
    const configDir = getConfigDir()
    await fs.mkdir(configDir, { recursive: true })
  } catch (error) {
    log('Error creating config directory:', error)
    throw error
  }
}

/**
 * Gets the file path for a config file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file
 * @returns The absolute file path
 */
export function getConfigFilePath(serverUrlHash: string, filename: string): string {
  const configDir = getConfigDir()
  return path.join(configDir, `${serverUrlHash}_${filename}`)
}

/**
 * Deletes a config file if it exists
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to delete
 */
export async function deleteConfigFile(serverUrlHash: string, filename: string): Promise<void> {
  try {
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.unlink(filePath)
  } catch (error) {
    // Ignore if file doesn't exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      log(`Error deleting ${filename}:`, error)
    }
  }
}

/**
 * Reads a JSON file and parses it with the provided schema
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param schema The schema to validate against
 * @returns The parsed file content or undefined if the file doesn't exist
 */
export async function readJsonFile<T>(serverUrlHash: string, filename: string, schema: any): Promise<T | undefined> {
  try {
    await ensureConfigDir()

    const filePath = getConfigFilePath(serverUrlHash, filename)
    const content = await fs.readFile(filePath, 'utf-8')
    const result = await schema.parseAsync(JSON.parse(content))
    // console.log({ filename: result })
    return result
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // console.log(`File ${filename} does not exist`)
      return undefined
    }
    log(`Error reading ${filename}:`, error)
    return undefined
  }
}

/**
 * Writes a JSON object to a file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param data The data to write
 */
export async function writeJsonFile(serverUrlHash: string, filename: string, data: any): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 })
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * Reads a text file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param errorMessage Optional custom error message
 * @returns The file content as a string
 */
export async function readTextFile(serverUrlHash: string, filename: string, errorMessage?: string): Promise<string> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    return await fs.readFile(filePath, 'utf-8')
  } catch (error) {
    throw new Error(errorMessage || `Error reading ${filename}`)
  }
}

/**
 * Writes a text string to a file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param text The text to write
 */
export async function writeTextFile(serverUrlHash: string, filename: string, text: string): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, text, { encoding: 'utf-8', mode: 0o600 })
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}
