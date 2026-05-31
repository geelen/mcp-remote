import { Transform } from 'stream'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'

/**
 * Creates a Transform stream that normalizes `params: null` to `params` absent
 * in JSON-RPC messages before they are parsed by the SDK.
 *
 * This addresses a compatibility issue where some MCP servers (like Datadog) send
 * `"params": null` in JSON-RPC messages, which violates the JSONRPCMessage schema
 * but should be treated as "no params provided".
 *
 * The SDK's StdioServerTransport reads from stdin line-by-line and parses each line
 * through JSONRPCMessageSchema.parse(). By normalizing the input stream before it
 * reaches the transport, we can fix the schema violation transparently.
 */
export function createParamsNormalizingStream(): Transform {
  let lineBuffer = ''

  return new Transform({
    transform(chunk: Buffer, _encoding: string, callback: Function) {
      // Accumulate chunks into lines (JSON-RPC messages are newline-delimited)
      lineBuffer += chunk.toString('utf8')
      const lines = lineBuffer.split('\n')

      // Keep the last incomplete line in the buffer
      lineBuffer = lines.pop() || ''

      // Process complete lines
      for (const line of lines) {
        if (line.trim()) {
          try {
            // Parse the JSON-RPC message
            const message = JSON.parse(line)

            // Normalize params: null -> delete params key
            if (message && typeof message === 'object' && message.params === null) {
              delete message.params
            }

            // Re-serialize and forward with newline
            this.push(JSON.stringify(message) + '\n')
          } catch (e) {
            // If parsing fails (not valid JSON), pass through as-is
            // The SDK will handle the error appropriately
            this.push(line + '\n')
          }
        } else if (line === '') {
          // Preserve empty lines
          this.push('\n')
        }
      }

      callback()
    },

    flush(callback: Function) {
      // Process any remaining data in the buffer when the stream ends
      if (lineBuffer.trim()) {
        try {
          const message = JSON.parse(lineBuffer)
          if (message && typeof message === 'object' && message.params === null) {
            delete message.params
          }
          this.push(JSON.stringify(message) + '\n')
        } catch (e) {
          // Pass through as-is if not valid JSON
          this.push(lineBuffer)
        }
      }
      callback()
    },
  })
}

/**
 * Custom StdioServerTransport that normalizes `params: null` before schema validation.
 *
 * The SDK's StdioServerTransport constructor accepts custom stdin/stdout streams.
 * We exploit this to pipe process.stdin through a normalizing Transform stream
 * before the SDK reads and parses JSON-RPC messages.
 */
export class NormalizingStdioServerTransport extends StdioServerTransport {
  constructor() {
    // Create the normalizing stream and pipe process.stdin through it
    const normalizingStream = createParamsNormalizingStream()
    process.stdin.pipe(normalizingStream)

    // Pass the normalizing stream as stdin so the SDK reads normalized messages
    super(normalizingStream, process.stdout)
  }
}
