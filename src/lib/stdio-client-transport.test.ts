import { describe, it, expect } from 'vitest'
import { createParamsNormalizingStream } from './stdio-client-transport'
import { Readable } from 'stream'

/**
 * Tests for the params normalizing stream, which fixes JSON-RPC messages with
 * `"params": null` before they reach the SDK's schema validation.
 *
 * We test the Transform stream directly since it encapsulates the normalization logic
 * and is simpler to test in isolation than the full transport with process.stdin.
 */
describe('createParamsNormalizingStream', () => {
  async function collectStreamOutput(input: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const normalizingStream = createParamsNormalizingStream()
      const chunks: Buffer[] = []

      normalizingStream.on('data', (chunk: Buffer) => chunks.push(chunk))
      normalizingStream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      normalizingStream.on('error', reject)

      const readable = Readable.from([input])
      readable.pipe(normalizingStream)
    })
  }

  it('should delete params key when params is null', async () => {
    const input = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: null }) + '\n'
    const output = await collectStreamOutput(input)
    const parsed = JSON.parse(output.trim())

    expect(parsed).not.toHaveProperty('params')
    expect(parsed).toMatchObject({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  })

  it('should preserve params when it is a valid object', async () => {
    const input = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'foo', params: { bar: 'baz' } }) + '\n'
    const output = await collectStreamOutput(input)
    const parsed = JSON.parse(output.trim())

    expect(parsed).toHaveProperty('params', { bar: 'baz' })
  })

  it('should pass through messages with no params key', async () => {
    const input = JSON.stringify({ jsonrpc: '2.0', id: 3, result: { ok: true } }) + '\n'
    const output = await collectStreamOutput(input)
    const parsed = JSON.parse(output.trim())

    expect(parsed).not.toHaveProperty('params')
    expect(parsed).toMatchObject({ result: { ok: true } })
  })

  it('should handle multiple messages in a single chunk', async () => {
    const msg1 = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: null })
    const msg2 = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'pong', params: { data: 'x' } })
    const input = msg1 + '\n' + msg2 + '\n'
    const output = await collectStreamOutput(input)
    const lines = output.trim().split('\n').filter(Boolean)

    expect(lines.length).toBe(2)
    const parsed1 = JSON.parse(lines[0])
    const parsed2 = JSON.parse(lines[1])

    expect(parsed1).not.toHaveProperty('params')
    expect(parsed2).toHaveProperty('params', { data: 'x' })
  })

  it('should pass through non-JSON lines unchanged', async () => {
    const input = 'not valid json\n'
    const output = await collectStreamOutput(input)
    expect(output.trim()).toBe('not valid json')
  })
})
