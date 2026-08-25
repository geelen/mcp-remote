import { spawn, type ChildProcess } from 'child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import { fileURLToPath } from 'url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../..')

export type InstanceRun = {
  /** Authorization URLs opened across all instances, i.e. the tabs a user would have seen. */
  tabs: Array<{ atMs: number; url: string }>
  /** Per-instance stderr, for asserting on what an instance decided. */
  logs: string[]
  /** Instances that reported reaching the remote server. */
  connected: number
  configDir: string
}

export type RunOptions = {
  /** How many instances the host starts at once. */
  count: number
  serverUrl: string
  /** Extra CLI args, e.g. `['--port', '9999']`. */
  args?: string[]
  /** How long to let the flow run before tearing down. */
  settleMs?: number
  /** Kills the instance that opened the first tab, this long after it opens. */
  killTabOwnerAfterMs?: number
}

/**
 * Starts `count` real mcp-remote processes against one server, as an MCP host does.
 *
 * They are run from source under `tsx` rather than from `dist` so that the `open` package can be
 * aliased away by a module hook; the bundler inlines it, which would put a real browser launch
 * inside a test run.
 */
export async function runInstances(options: RunOptions): Promise<InstanceRun> {
  const { count, serverUrl, args = [], settleMs = 8000 } = options
  const configDir = mkdtempSync(path.join(tmpdir(), 'mcp-remote-e2e-'))
  const tabLog = path.join(configDir, 'tabs.log')
  writeFileSync(tabLog, '')

  const startedAt = Date.now()
  const children: ChildProcess[] = []
  const logs: string[] = Array.from({ length: count }, () => '')

  for (let i = 0; i < count; i++) {
    const child = spawn(path.join(repoRoot, 'node_modules/.bin/tsx'), [path.join(repoRoot, 'src/proxy.ts'), serverUrl, ...args], {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        MCP_REMOTE_CONFIG_DIR: configDir,
        MCP_TEST_TAB_LOG: tabLog,
        NODE_OPTIONS: `--import ${pathToImport(path.join(here, 'browser-hook.mjs'))}`,
      },
    })
    child.stderr?.on('data', (chunk) => {
      logs[i] += String(chunk)
    })
    children.push(child)
  }

  await new Promise((resolve) => setTimeout(resolve, settleMs))
  for (const child of children) child.kill('SIGKILL')

  const tabs = existsSync(tabLog)
    ? readFileSync(tabLog, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const [at, ...rest] = line.split(' ')
          return { atMs: Number(at) - startedAt, url: rest.join(' ') }
        })
    : []

  return {
    tabs,
    logs,
    connected: logs.filter((l) => /Connected to remote server|Proxy established successfully/.test(l)).length,
    configDir,
  }
}

export function cleanupRun(run: InstanceRun): void {
  rmSync(run.configDir, { recursive: true, force: true })
}

function pathToImport(p: string): string {
  return new URL(`file://${p}`).href
}
