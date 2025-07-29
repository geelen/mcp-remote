import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { parseCommandLineArgs, connectToRemoteServer } from './utils'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'

// All sanitizeUrl tests have been moved to the strict-url-sanitise package

describe('parseCommandLineArgs', () => {
  it('should parse --insecure flag correctly', async () => {
    const args = ['https://example.com', '--insecure']
    const result = await parseCommandLineArgs(args, 'Test usage')

    expect(result.insecure).toBe(true)
    expect(result.serverUrl).toBe('https://example.com')
  })

  it('should default insecure to false when not provided', async () => {
    const args = ['https://example.com']
    const result = await parseCommandLineArgs(args, 'Test usage')

    expect(result.insecure).toBe(false)
    expect(result.serverUrl).toBe('https://example.com')
  })

  it('should work with multiple flags including --insecure', async () => {
    const args = ['https://example.com', '--debug', '--insecure', '--allow-http']
    const result = await parseCommandLineArgs(args, 'Test usage')

    expect(result.insecure).toBe(true)
    expect(result.debug).toBe(true)
    expect(result.serverUrl).toBe('https://example.com')
  })
})

describe('connectToRemoteServer insecure flag', () => {
  let originalTlsReject: string | undefined
  let mockExit: any
  let mockLog: any

  beforeEach(() => {
    // Save original environment variable
    originalTlsReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED
    
    // Mock process.exit to prevent actual exits during tests
    mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called')
    })
    
    // Mock console.error to capture log messages
    mockLog = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    // Restore original environment variable
    if (originalTlsReject !== undefined) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTlsReject
    } else {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
    }
    
    // Restore mocks
    mockExit.mockRestore()
    mockLog.mockRestore()
  })

  it('should fail when --insecure conflicts with NODE_TLS_REJECT_UNAUTHORIZED=1', async () => {
    // Set environment variable to enable cert verification (conflicts with --insecure)
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1'
    
    const mockAuthProvider = {} as OAuthClientProvider
    const mockAuthInitializer = async () => ({ waitForAuthCode: async () => 'test', skipBrowserAuth: false })

    await expect(
      connectToRemoteServer(
        null,
        'https://example.com',
        mockAuthProvider,
        {},
        mockAuthInitializer,
        'http-first',
        new Set(),
        true // insecure flag
      )
    ).rejects.toThrow('process.exit called')

    // Check that error message was logged
    expect(mockLog).toHaveBeenCalledWith(
      expect.stringContaining('Cannot use --insecure flag while NODE_TLS_REJECT_UNAUTHORIZED')
    )
  })

  it('should fail when --insecure conflicts with NODE_TLS_REJECT_UNAUTHORIZED=true', async () => {
    // Set environment variable to enable cert verification (conflicts with --insecure)
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = 'true'
    
    const mockAuthProvider = {} as OAuthClientProvider
    const mockAuthInitializer = async () => ({ waitForAuthCode: async () => 'test', skipBrowserAuth: false })

    await expect(
      connectToRemoteServer(
        null,
        'https://example.com',
        mockAuthProvider,
        {},
        mockAuthInitializer,
        'http-first',
        new Set(),
        true // insecure flag
      )
    ).rejects.toThrow('process.exit called')

    // Check that error message was logged
    expect(mockLog).toHaveBeenCalledWith(
      expect.stringContaining('Cannot use --insecure flag while NODE_TLS_REJECT_UNAUTHORIZED')
    )
  })

  it('should proceed when --insecure is compatible with NODE_TLS_REJECT_UNAUTHORIZED=0', async () => {
    // Set environment variable to disable cert verification (compatible with --insecure)
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    
    const mockAuthProvider = {} as OAuthClientProvider
    const mockAuthInitializer = async () => ({ waitForAuthCode: async () => 'test', skipBrowserAuth: false })

    // This test will likely fail due to network issues, but we're just testing that
    // the conflict detection doesn't trigger process.exit
    try {
      await connectToRemoteServer(
        null,
        'https://example.com',
        mockAuthProvider,
        {},
        mockAuthInitializer,
        'http-first',
        new Set(),
        true // insecure flag
      )
    } catch (error) {
      // We expect this to fail due to network/connection issues, not conflict detection
      expect(error).not.toEqual(new Error('process.exit called'))
    }

    // Should not have called process.exit
    expect(mockExit).not.toHaveBeenCalled()
  })

  it('should set and restore NODE_TLS_REJECT_UNAUTHORIZED when unset with --insecure', async () => {
    // Ensure environment variable is unset
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
    
    const mockAuthProvider = {} as OAuthClientProvider
    const mockAuthInitializer = async () => ({ waitForAuthCode: async () => 'test', skipBrowserAuth: false })

    // This test will likely fail due to network issues, but we're testing env var handling
    try {
      await connectToRemoteServer(
        null,
        'https://example.com',
        mockAuthProvider,
        {},
        mockAuthInitializer,
        'http-first',
        new Set(),
        true // insecure flag
      )
    } catch (error) {
      // We expect this to fail due to network/connection issues
      expect(error).not.toEqual(new Error('process.exit called'))
    }

    // Environment variable should be restored to unset state
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBeUndefined()
    
    // Should not have called process.exit
    expect(mockExit).not.toHaveBeenCalled()
    
    // Should have logged that we're setting the env var
    expect(mockLog).toHaveBeenCalledWith(
      expect.stringContaining('Setting NODE_TLS_REJECT_UNAUTHORIZED=0 for --insecure connection')
    )
  })

  it('should not modify NODE_TLS_REJECT_UNAUTHORIZED when --insecure is false', async () => {
    // Set a specific value
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1'
    const originalValue = process.env.NODE_TLS_REJECT_UNAUTHORIZED
    
    const mockAuthProvider = {} as OAuthClientProvider
    const mockAuthInitializer = async () => ({ waitForAuthCode: async () => 'test', skipBrowserAuth: false })

    // This test will likely fail due to network issues
    try {
      await connectToRemoteServer(
        null,
        'https://example.com',
        mockAuthProvider,
        {},
        mockAuthInitializer,
        'http-first',
        new Set(),
        false // insecure flag is false
      )
    } catch (error) {
      // We expect this to fail due to network/connection issues
      expect(error).not.toEqual(new Error('process.exit called'))
    }

    // Environment variable should remain unchanged
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBe(originalValue)
    
    // Should not have called process.exit
    expect(mockExit).not.toHaveBeenCalled()
  })
})
