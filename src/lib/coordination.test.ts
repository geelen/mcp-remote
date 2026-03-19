import { describe, it, expect, afterEach } from 'vitest'
import { setGlobalDispatcher, getGlobalDispatcher, Agent, buildConnector } from 'undici'
import express from 'express'
import { type Server } from 'http'
import { type AddressInfo } from 'net'
import { isLockValid, waitForAuthentication } from './coordination'

function startCoordinationServer(): Promise<{ server: Server; port: number }> {
  const app = express()
  app.get('/wait-for-auth', (_req, res) => {
    res.status(200).send('ok')
  })
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port
      resolve({ server, port })
    })
  })
}

function setBrokenGlobalDispatcher(): Agent {
  const brokenAgent = new Agent({
    connect: (_opts: buildConnector.Options, callback: buildConnector.Callback) => {
      callback(new Error('global dispatcher should not be used for coordination'), null)
    },
  })
  setGlobalDispatcher(brokenAgent)
  return brokenAgent
}

describe('coordination fetches bypass global dispatcher', () => {
  let server: Server | undefined
  let brokenAgent: Agent | undefined
  const originalDispatcher = getGlobalDispatcher()

  afterEach(async () => {
    setGlobalDispatcher(originalDispatcher)
    await brokenAgent?.close()
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()))
  })

  it('isLockValid succeeds even when global dispatcher rejects connections', async () => {
    const started = await startCoordinationServer()
    server = started.server
    brokenAgent = setBrokenGlobalDispatcher()

    const result = await isLockValid({
      pid: process.pid,
      port: started.port,
      timestamp: Date.now(),
    })

    expect(result).toBe(true)
  })

  it('waitForAuthentication succeeds even when global dispatcher rejects connections', async () => {
    const started = await startCoordinationServer()
    server = started.server
    brokenAgent = setBrokenGlobalDispatcher()

    const result = await waitForAuthentication(started.port)

    expect(result).toBe(true)
  })
})
