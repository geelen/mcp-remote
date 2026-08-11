import os from 'os'
import path from 'path'
import { DatabaseSync } from 'node:sqlite'
import { mkdtemp, rm, stat } from 'fs/promises'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import {
  deleteConfigFile,
  getAccessTokensDatabasePath,
  getConfigDir,
  getCredentialsDatabasePath,
  readJsonFile,
  readTextFile,
  writeJsonFile,
  writeTextFile,
} from './mcp-auth-config'

const passthroughSchema = {
  parseAsync: async (value: unknown) => value,
}

describe.sequential('MCP OAuth credential storage', () => {
  let configDirectory: string
  let originalConfigDirectory: string | undefined

  beforeEach(async () => {
    configDirectory = await mkdtemp(path.join(os.tmpdir(), 'mcp-remote-auth-'))
    originalConfigDirectory = process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_CONFIG_DIR = configDirectory
  })

  afterEach(async () => {
    if (originalConfigDirectory === undefined) {
      delete process.env.MCP_REMOTE_CONFIG_DIR
    } else {
      process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDirectory
    }
    await rm(configDirectory, { recursive: true, force: true })
  })

  it('stores durable OAuth data in credentials.db and access tokens separately', async () => {
    const serverUrlHash = 'server-one'
    const tokens = {
      access_token: 'access-token-for-test',
      refresh_token: 'refresh-token-for-test',
      id_token: 'id-token-for-test',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'license.read',
    }

    await writeJsonFile(serverUrlHash, 'tokens.json', tokens)

    await expect(readJsonFile(serverUrlHash, 'tokens.json', OAuthTokensSchema)).resolves.toEqual(tokens)

    const credentials = new DatabaseSync(getCredentialsDatabasePath())
    const credentialRecord = credentials
      .prepare('SELECT value FROM credentials WHERE account_id = ?')
      .get(`${serverUrlHash}:tokens.json`) as { value: string }
    credentials.close()

    expect(JSON.parse(credentialRecord.value)).toEqual({
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      scope: tokens.scope,
    })

    const accessTokens = new DatabaseSync(getAccessTokensDatabasePath())
    const accessTokenRecord = accessTokens
      .prepare('SELECT access_token, token_expiry FROM access_tokens WHERE account_id = ?')
      .get(serverUrlHash) as { access_token: string; token_expiry: number }
    accessTokens.close()

    expect(accessTokenRecord.access_token).toBe(tokens.access_token)
    expect(accessTokenRecord.token_expiry).toBeGreaterThan(Date.now())
  })

  it('keeps client registration and PKCE data in credentials.db', async () => {
    const serverUrlHash = 'server-two'
    const clientInfo = {
      client_id: 'test-client',
      redirect_uris: ['http://127.0.0.1:4242/oauth/callback'],
    }

    await writeJsonFile(serverUrlHash, 'client_info.json', clientInfo)
    await writeTextFile(serverUrlHash, 'code_verifier.txt', 'test-code-verifier')

    await expect(readJsonFile(serverUrlHash, 'client_info.json', passthroughSchema)).resolves.toEqual(clientInfo)
    await expect(readTextFile(serverUrlHash, 'code_verifier.txt')).resolves.toBe('test-code-verifier')

    const credentials = new DatabaseSync(getCredentialsDatabasePath())
    const records = credentials.prepare('SELECT account_id FROM credentials ORDER BY account_id').all() as Array<{ account_id: string }>
    credentials.close()

    expect(records).toEqual([{ account_id: `${serverUrlHash}:client_info.json` }, { account_id: `${serverUrlHash}:code_verifier.txt` }])
  })

  it('reuses the stored OAuth session through a new provider instance', async () => {
    const options = {
      serverUrl: 'https://auth.example.test',
      callbackPort: 4242,
      host: '127.0.0.1',
      serverUrlHash: 'server-four',
    }
    const provider = new NodeOAuthClientProvider(options)

    await provider.saveClientInformation({
      client_id: 'test-client',
      redirect_uris: ['http://127.0.0.1:4242/oauth/callback'],
    })
    await provider.saveTokens({
      access_token: 'access-token-for-test',
      refresh_token: 'refresh-token-for-test',
      token_type: 'Bearer',
      expires_in: 3600,
    })
    await provider.saveCodeVerifier('test-code-verifier')

    const reusedProvider = new NodeOAuthClientProvider(options)
    await expect(reusedProvider.clientInformation()).resolves.toMatchObject({ client_id: 'test-client' })
    await expect(reusedProvider.tokens()).resolves.toMatchObject({
      access_token: 'access-token-for-test',
      refresh_token: 'refresh-token-for-test',
    })
    await expect(reusedProvider.codeVerifier()).resolves.toBe('test-code-verifier')
  })

  it('uses owner-only permissions and deletes both token records', async () => {
    const serverUrlHash = 'server-three'
    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'access-token-for-test',
      token_type: 'Bearer',
    })

    await expect(stat(getConfigDir())).resolves.toMatchObject({ mode: expect.any(Number) })
    expect((await stat(getConfigDir())).mode & 0o777).toBe(0o700)
    expect((await stat(getCredentialsDatabasePath())).mode & 0o777).toBe(0o600)
    expect((await stat(getAccessTokensDatabasePath())).mode & 0o777).toBe(0o600)

    await deleteConfigFile(serverUrlHash, 'tokens.json')

    await expect(readJsonFile(serverUrlHash, 'tokens.json', OAuthTokensSchema)).resolves.toBeUndefined()
    const credentials = new DatabaseSync(getCredentialsDatabasePath())
    const credentialRecord = credentials.prepare('SELECT value FROM credentials WHERE account_id = ?').get(`${serverUrlHash}:tokens.json`)
    credentials.close()
    const accessTokens = new DatabaseSync(getAccessTokensDatabasePath())
    const accessTokenRecord = accessTokens.prepare('SELECT access_token FROM access_tokens WHERE account_id = ?').get(serverUrlHash)
    accessTokens.close()

    expect(credentialRecord).toBeUndefined()
    expect(accessTokenRecord).toBeUndefined()
  })
})
