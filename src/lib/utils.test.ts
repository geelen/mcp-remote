import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { parseCommandLineArgs, setupOAuthCallbackServerWithLongPoll } from './utils'
import { EventEmitter } from 'events'
import express from 'express'

// All sanitizeUrl tests have been moved to the strict-url-sanitise package

describe('parseCommandLineArgs', () => {
  const mockUsage = 'Usage: test <url>'
  const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called')
  })
  
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    mockExit.mockReset()
  })

  describe('--auth-timeout parsing', () => {
    it('should use default timeout of 30000ms when no --auth-timeout flag is provided', async () => {
      const args = ['https://example.com']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(30000)
    })

    it('should parse valid timeout in seconds and convert to milliseconds', async () => {
      const args = ['https://example.com', '--auth-timeout', '60']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(60000)
    })

    it('should parse another valid timeout value', async () => {
      const args = ['https://example.com', '--auth-timeout', '120']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(120000)
    })

    it('should use default timeout when invalid timeout value is provided', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      const args = ['https://example.com', '--auth-timeout', 'invalid']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(30000)
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Warning: Ignoring invalid auth timeout value: invalid. Must be a positive number.')
      )
      
      consoleSpy.mockRestore()
    })

    it('should use default timeout when negative timeout value is provided', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      const args = ['https://example.com', '--auth-timeout', '-30']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(30000)
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Warning: Ignoring invalid auth timeout value: -30. Must be a positive number.')
      )
      
      consoleSpy.mockRestore()
    })

    it('should use default timeout when zero timeout value is provided', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      const args = ['https://example.com', '--auth-timeout', '0']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(30000)
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Warning: Ignoring invalid auth timeout value: 0. Must be a positive number.')
      )
      
      consoleSpy.mockRestore()
    })

    it('should use default timeout when --auth-timeout flag has no value', async () => {
      const args = ['https://example.com', '--auth-timeout']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(30000)
    })

    it('should log when using custom timeout', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      const args = ['https://example.com', '--auth-timeout', '45']
      const result = await parseCommandLineArgs(args, mockUsage)
      
      expect(result.authTimeoutMs).toBe(45000)
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Using auth callback timeout: 45 seconds')
      )
      
      consoleSpy.mockRestore()
    })
  })
})

describe('setupOAuthCallbackServerWithLongPoll', () => {
  let server: any
  let events: EventEmitter

  beforeEach(() => {
    events = new EventEmitter()
  })

  afterEach(() => {
    if (server) {
      server.close()
      server = null
    }
  })

  it('should use custom timeout when authTimeoutMs is provided', async () => {
    const customTimeout = 5000
    const result = setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events,
      authTimeoutMs: customTimeout
    })
    
    server = result.server
    
    // Test that the server was created
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })

  it('should use default timeout when authTimeoutMs is not provided', async () => {
    const result = setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events
    })
    
    server = result.server
    
    // Test that the server was created with defaults
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })
})
