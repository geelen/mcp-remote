import os from 'os'
import path from 'path'
import fs from 'fs/promises'
import { DatabaseSync } from 'node:sqlite'
import { log } from './utils'

/**
 * MCP Remote Authentication Configuration
 *
 * OAuth credentials follow the same local-storage pattern as the gcloud CLI:
 *
 * - credentials.db contains durable credentials such as refresh tokens, dynamic
 *   client registrations, and PKCE verifiers.
 * - access_tokens.db contains short-lived access tokens and their expiry.
 * - lock files and debug logs remain ordinary 0600 files because they are
 *   process-coordination data rather than reusable OAuth credentials.
 *
 * The directory defaults to ~/.config/mcp-remote and is 0700. Database files
 * and file-backed records are 0600.
 */

const CREDENTIALS_DATABASE = 'credentials.db'
const ACCESS_TOKENS_DATABASE = 'access_tokens.db'

type DatabaseRecord = {
  value: string
}

type AccessTokenRecord = {
  access_token: string
}

type OAuthTokenMetadata = {
  id_token?: string
  token_type: string
  expires_in?: number
  scope?: string
  refresh_token?: string
}

/**
 * Lockfile data structure
 */
export interface LockfileData {
  pid: number
  port: number
  timestamp: number
}

/**
 * Gets the configuration directory path.
 * MCP_REMOTE_CONFIG_DIR is an explicit directory override, not a base path.
 */
export function getConfigDir(): string {
  return process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.config', 'mcp-remote')
}

/**
 * Ensures the configuration directory exists with owner-only access.
 */
export async function ensureConfigDir(): Promise<void> {
  try {
    const configDir = getConfigDir()
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 })
    await fs.chmod(configDir, 0o700)
  } catch (error) {
    log('Error creating credential directory:', error)
    throw error
  }
}

export function getCredentialsDatabasePath(): string {
  return path.join(getConfigDir(), CREDENTIALS_DATABASE)
}

export function getAccessTokensDatabasePath(): string {
  return path.join(getConfigDir(), ACCESS_TOKENS_DATABASE)
}

/**
 * Gets the path for the remaining file-backed configuration records.
 */
export function getConfigFilePath(serverUrlHash: string, filename: string): string {
  return path.join(getConfigDir(), `${serverUrlHash}_${filename}`)
}

function isCredentialRecord(filename: string): boolean {
  return filename === 'client_info.json' || filename === 'tokens.json' || filename === 'code_verifier.txt'
}

function credentialRecordId(serverUrlHash: string, filename: string): string {
  return `${serverUrlHash}:${filename}`
}

async function withCredentialsDatabase<T>(action: (database: DatabaseSync) => T): Promise<T> {
  await ensureConfigDir()
  const databasePath = getCredentialsDatabasePath()
  const database = new DatabaseSync(databasePath)

  try {
    database.exec('CREATE TABLE IF NOT EXISTS credentials (account_id TEXT PRIMARY KEY, value BLOB NOT NULL)')
    await fs.chmod(databasePath, 0o600)
    return action(database)
  } finally {
    database.close()
  }
}

async function withAccessTokensDatabase<T>(action: (database: DatabaseSync) => T): Promise<T> {
  await ensureConfigDir()
  const databasePath = getAccessTokensDatabasePath()
  const database = new DatabaseSync(databasePath)

  try {
    database.exec(
      'CREATE TABLE IF NOT EXISTS access_tokens (account_id TEXT PRIMARY KEY, access_token TEXT NOT NULL, token_expiry INTEGER)',
    )
    await fs.chmod(databasePath, 0o600)
    return action(database)
  } finally {
    database.close()
  }
}

async function readCredentialRecord<T>(serverUrlHash: string, filename: string): Promise<T | undefined> {
  const record = await withCredentialsDatabase(
    (database) =>
      database.prepare('SELECT value FROM credentials WHERE account_id = ?').get(credentialRecordId(serverUrlHash, filename)) as
        | DatabaseRecord
        | undefined,
  )

  if (!record) {
    return undefined
  }

  try {
    return JSON.parse(record.value) as T
  } catch (error) {
    log(`Error parsing ${filename}:`, error)
    return undefined
  }
}

async function writeCredentialRecord(serverUrlHash: string, filename: string, value: unknown): Promise<void> {
  await withCredentialsDatabase((database) => {
    database
      .prepare('INSERT INTO credentials (account_id, value) VALUES (?, ?) ON CONFLICT(account_id) DO UPDATE SET value = excluded.value')
      .run(credentialRecordId(serverUrlHash, filename), JSON.stringify(value))
  })
}

async function deleteCredentialRecord(serverUrlHash: string, filename: string): Promise<void> {
  await withCredentialsDatabase((database) => {
    database.prepare('DELETE FROM credentials WHERE account_id = ?').run(credentialRecordId(serverUrlHash, filename))
  })
}

async function readTokens(serverUrlHash: string): Promise<Record<string, unknown> | undefined> {
  const [metadata, accessToken] = await Promise.all([
    readCredentialRecord<OAuthTokenMetadata>(serverUrlHash, 'tokens.json'),
    withAccessTokensDatabase(
      (database) =>
        database.prepare('SELECT access_token FROM access_tokens WHERE account_id = ?').get(serverUrlHash) as AccessTokenRecord | undefined,
    ),
  ])

  if (!metadata || !accessToken) {
    return undefined
  }

  return {
    ...metadata,
    access_token: accessToken.access_token,
  }
}

async function writeTokens(serverUrlHash: string, tokens: Record<string, unknown>): Promise<void> {
  const { access_token: accessToken, id_token, token_type: tokenType, expires_in: expiresIn, scope, refresh_token: refreshToken } = tokens

  if (typeof accessToken !== 'string' || typeof tokenType !== 'string') {
    throw new Error('OAuth tokens must include string access_token and token_type values')
  }

  const metadata: OAuthTokenMetadata = {
    token_type: tokenType,
    ...(typeof id_token === 'string' ? { id_token } : {}),
    ...(typeof expiresIn === 'number' ? { expires_in: expiresIn } : {}),
    ...(typeof scope === 'string' ? { scope } : {}),
    ...(typeof refreshToken === 'string' ? { refresh_token: refreshToken } : {}),
  }
  const tokenExpiry = typeof expiresIn === 'number' ? Date.now() + expiresIn * 1000 : null

  await writeCredentialRecord(serverUrlHash, 'tokens.json', metadata)
  await withAccessTokensDatabase((database) => {
    database
      .prepare(
        'INSERT INTO access_tokens (account_id, access_token, token_expiry) VALUES (?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET access_token = excluded.access_token, token_expiry = excluded.token_expiry',
      )
      .run(serverUrlHash, accessToken, tokenExpiry)
  })
}

async function deleteTokens(serverUrlHash: string): Promise<void> {
  await Promise.all([
    deleteCredentialRecord(serverUrlHash, 'tokens.json'),
    withAccessTokensDatabase((database) => {
      database.prepare('DELETE FROM access_tokens WHERE account_id = ?').run(serverUrlHash)
    }),
  ])
}

/**
 * Creates a lockfile for the given server.
 */
export async function createLockfile(serverUrlHash: string, pid: number, port: number): Promise<void> {
  await writeJsonFile(serverUrlHash, 'lock.json', { pid, port, timestamp: Date.now() })
}

/**
 * Checks if a lockfile exists for the given server.
 */
export async function checkLockfile(serverUrlHash: string): Promise<LockfileData | null> {
  try {
    const lockfile = await readJsonFile<LockfileData>(serverUrlHash, 'lock.json', {
      async parseAsync(data: unknown) {
        if (typeof data !== 'object' || data === null) return null
        const lock = data as Partial<LockfileData>
        if (typeof lock.pid !== 'number' || typeof lock.port !== 'number' || typeof lock.timestamp !== 'number') {
          return null
        }
        return lock as LockfileData
      },
    })
    return lockfile || null
  } catch {
    return null
  }
}

/**
 * Deletes the lockfile for the given server.
 */
export async function deleteLockfile(serverUrlHash: string): Promise<void> {
  await deleteConfigFile(serverUrlHash, 'lock.json')
}

/**
 * Deletes a config record if it exists.
 */
export async function deleteConfigFile(serverUrlHash: string, filename: string): Promise<void> {
  try {
    if (filename === 'tokens.json') {
      await deleteTokens(serverUrlHash)
      return
    }
    if (isCredentialRecord(filename)) {
      await deleteCredentialRecord(serverUrlHash, filename)
      return
    }

    await fs.unlink(getConfigFilePath(serverUrlHash, filename))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      log(`Error deleting ${filename}:`, error)
    }
  }
}

/**
 * Reads a JSON record and parses it with the provided schema.
 */
export async function readJsonFile<T>(serverUrlHash: string, filename: string, schema: any): Promise<T | undefined> {
  try {
    let data: unknown
    if (filename === 'tokens.json') {
      data = await readTokens(serverUrlHash)
    } else if (isCredentialRecord(filename)) {
      data = await readCredentialRecord(serverUrlHash, filename)
    } else {
      await ensureConfigDir()
      data = JSON.parse(await fs.readFile(getConfigFilePath(serverUrlHash, filename), 'utf-8'))
    }

    return data === undefined ? undefined : await schema.parseAsync(data)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined
    }
    log(`Error reading ${filename}:`, error)
    return undefined
  }
}

/**
 * Writes a JSON record.
 */
export async function writeJsonFile(serverUrlHash: string, filename: string, data: unknown): Promise<void> {
  try {
    if (filename === 'tokens.json') {
      await writeTokens(serverUrlHash, data as Record<string, unknown>)
      return
    }
    if (isCredentialRecord(filename)) {
      await writeCredentialRecord(serverUrlHash, filename, data)
      return
    }

    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 })
    await fs.chmod(filePath, 0o600)
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * Reads a text credential record.
 */
export async function readTextFile(serverUrlHash: string, filename: string, errorMessage?: string): Promise<string> {
  try {
    if (filename === 'code_verifier.txt') {
      const value = await readCredentialRecord<string>(serverUrlHash, filename)
      if (value === undefined) {
        throw new Error('Credential record does not exist')
      }
      return value
    }

    await ensureConfigDir()
    return await fs.readFile(getConfigFilePath(serverUrlHash, filename), 'utf-8')
  } catch {
    throw new Error(errorMessage || `Error reading ${filename}`)
  }
}

/**
 * Writes a text credential record.
 */
export async function writeTextFile(serverUrlHash: string, filename: string, text: string): Promise<void> {
  try {
    if (filename === 'code_verifier.txt') {
      await writeCredentialRecord(serverUrlHash, filename, text)
      return
    }

    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, text, { encoding: 'utf-8', mode: 0o600 })
    await fs.chmod(filePath, 0o600)
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}
