import { describe, expect, it } from 'vitest'
import { EventEmitter } from 'events'
import type { Server } from 'http'
import type { AddressInfo } from 'net'
import { waitForListeningAddress } from './coordination'

describe('waitForListeningAddress', () => {
  it('waits for a server that has not reported its address yet', async () => {
    const events = new EventEmitter()
    let address: AddressInfo | null = null
    const server = {
      address: () => address,
      once: (event: string, listener: () => void) => {
        events.once(event, listener)
        return server
      },
    } as unknown as Server

    const addressPromise = waitForListeningAddress(server)
    address = { address: '127.0.0.1', family: 'IPv4', port: 4242 }
    events.emit('listening')

    await expect(addressPromise).resolves.toMatchObject({ port: 4242 })
  })
})
