import { describe, it, expect, afterEach } from 'vitest'
import { setGlobalDispatcher, getGlobalDispatcher, Agent } from 'undici'
import express from 'express'
import { type Server } from 'http'
import { type AddressInfo } from 'net'
import { isLockValid, waitForAuthentication } from './coordination'

describe('coordination fetches bypass global dispatcher', () => {
  let server: Server
  const originalDispatcher = getGlobalDispatcher()

  afterEach(() => {
    setGlobalDispatcher(originalDispatcher)
    server?.close()
  })

  it('isLockValid succeeds even when global dispatcher rejects connections', async () => {
    // Start a real HTTP server that responds to the coordination endpoint
    const app = express()
    app.get('/wait-for-auth', (_req, res) => {
      res.status(200).send('ok')
    })

    server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s))
    })
    const port = (server.address() as AddressInfo).port

    // Set global dispatcher to one that always fails (simulating an
    // unreachable SOCKS proxy). If coordination fetches go through
    // this dispatcher, isLockValid will return false.
    const brokenAgent = new Agent({
      connect: (_opts: any, callback: any) => {
        callback(new Error('global dispatcher should not be used for coordination'), null)
      },
    })
    setGlobalDispatcher(brokenAgent)

    const result = await isLockValid({
      pid: process.pid,
      port,
      timestamp: Date.now(),
    })

    expect(result).toBe(true)
  })

  it('waitForAuthentication succeeds even when global dispatcher rejects connections', async () => {
    const app = express()
    // Return 200 immediately so waitForAuthentication resolves without polling
    app.get('/wait-for-auth', (_req, res) => {
      res.status(200).send('ok')
    })

    server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s))
    })
    const port = (server.address() as AddressInfo).port

    const brokenAgent = new Agent({
      connect: (_opts: any, callback: any) => {
        callback(new Error('global dispatcher should not be used for coordination'), null)
      },
    })
    setGlobalDispatcher(brokenAgent)

    const result = await waitForAuthentication(port)

    expect(result).toBe(true)
  })
})
