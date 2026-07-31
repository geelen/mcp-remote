import path from 'path'
import os from 'os'
import fs from 'fs/promises'
import { randomUUID } from 'node:crypto'
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
 * - {server_hash}_authorization.json: Current state-bound PKCE transaction
 *   - Format: state, verifier, and creation timestamp; only its matching callback may use it
 * - {server_hash}_code_verifier.txt: Legacy PKCE verifier retained only for migration reads
 * - {server_hash}_lock.json: Atomically claimed cross-process OAuth lease
 * - {server_hash}_authorization-completion.json: The latest completed lease,
 *   used only to let its already-waiting secondary clients consume saved tokens
 *
 * All JSON files are stored with 2-space indentation and atomically published
 * by renaming a completed same-directory temporary file.
 */

/**
 * Lockfile data structure
 */
export interface LockfileData {
  pid: number
  port: number
  timestamp: number
  /** Unique identity for this ownership round. */
  leaseId?: string
  /** Deadline for the authorization round that owns this lease. */
  expiresAt?: number
}

export interface AuthorizationCompletionData {
  leaseId: string
  completedAt: number
}

/**
 * Creates a lockfile for the given server
 * @param serverUrlHash The hash of the server URL
 * @param pid The process ID
 * @param port The port the server is running on
 */
export async function createLockfile(
  serverUrlHash: string,
  pid: number,
  port: number,
  authTimeoutMs: number = 30_000,
): Promise<LockfileData | null> {
  const timestamp = Date.now()
  const lockData: LockfileData = {
    pid,
    port,
    timestamp,
    leaseId: randomUUID(),
    expiresAt: timestamp + authTimeoutMs,
  }
  await ensureConfigDir()
  const filePath = getConfigFilePath(serverUrlHash, 'lock.json')
  const temporaryPath = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`)

  try {
    await fs.writeFile(temporaryPath, JSON.stringify(lockData, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await fs.link(temporaryPath, filePath)
    return lockData
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      return null
    }
    log('Error creating OAuth lockfile:', error)
    throw error
  } finally {
    try {
      await fs.unlink(temporaryPath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        log('Error removing temporary OAuth lockfile:', error)
      }
    }
  }
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
        if (
          typeof data.pid !== 'number' ||
          typeof data.port !== 'number' ||
          typeof data.timestamp !== 'number' ||
          (data.leaseId !== undefined && typeof data.leaseId !== 'string') ||
          (data.expiresAt !== undefined && typeof data.expiresAt !== 'number')
        ) {
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
export async function deleteLockfile(serverUrlHash: string, expectedLeaseId?: string): Promise<boolean> {
  const lockData = await checkLockfile(serverUrlHash)
  if (!lockData) {
    return true
  }

  // Never let an older owner or stale reclaimer remove a lease that was
  // created after it made its decision. Legacy leases have no identity and
  // are eligible only for legacy cleanup callers.
  if (expectedLeaseId ? lockData.leaseId !== expectedLeaseId : lockData.leaseId !== undefined) {
    return false
  }

  await deleteConfigFile(serverUrlHash, 'lock.json')
  return true
}

export async function writeAuthorizationCompletion(serverUrlHash: string, leaseId: string): Promise<void> {
  await writeJsonFile(serverUrlHash, 'authorization-completion.json', {
    leaseId,
    completedAt: Date.now(),
  } satisfies AuthorizationCompletionData)
}

export async function checkAuthorizationCompletion(serverUrlHash: string): Promise<AuthorizationCompletionData | null> {
  const completion = await readJsonFile<AuthorizationCompletionData>(serverUrlHash, 'authorization-completion.json', {
    async parseAsync(data: unknown) {
      if (!data || typeof data !== 'object') return null
      const candidate = data as Record<string, unknown>
      if (typeof candidate.leaseId !== 'string' || typeof candidate.completedAt !== 'number') return null
      return candidate as unknown as AuthorizationCompletionData
    },
  })
  return completion ?? null
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
  let temporaryPath: string | undefined
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    temporaryPath = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`)
    await fs.writeFile(temporaryPath, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await fs.rename(temporaryPath, filePath)
  } catch (error) {
    if (temporaryPath) {
      try {
        await fs.unlink(temporaryPath)
      } catch (cleanupError) {
        if ((cleanupError as NodeJS.ErrnoException).code !== 'ENOENT') {
          log(`Error removing temporary ${filename}:`, cleanupError)
        }
      }
    }
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
