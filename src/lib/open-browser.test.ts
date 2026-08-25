import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { EventEmitter } from 'events'
import { spawn } from 'child_process'
import open from 'open'
import { openBrowser } from './open-browser'

vi.mock('child_process', () => ({ spawn: vi.fn() }))
vi.mock('open', () => ({ default: vi.fn() }))
vi.mock('./utils', () => ({ log: vi.fn(), debugLog: vi.fn() }))

/** A helper process that never exits on its own, like a browser in the foreground. */
const runningHelper = () => new EventEmitter()

/** A helper that exits with the given code, once the caller is listening for it. */
const exitingHelper = (code: number) => emitsWhenWatched('exit', code)

/** A helper that cannot be started at all. */
const missingHelper = () => emitsWhenWatched('error', new Error('spawn ENOENT'))

function emitsWhenWatched(event: 'exit' | 'error', payload: unknown) {
  const child = new EventEmitter()
  child.on('newListener', (added) => {
    if (added === event) queueMicrotask(() => child.emit(event, payload))
  })
  return child
}

describe('Feature: Opening the authorization URL', () => {
  const url = 'https://auth.example.com/authorize'

  beforeEach(() => {
    vi.mocked(spawn).mockReset()
    vi.mocked(open).mockReset()
    Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('Scenario: The bundled opener works', async () => {
    vi.mocked(open).mockResolvedValue(exitingHelper(0) as any)

    await expect(openBrowser(url)).resolves.toBe(true)
    expect(spawn).not.toHaveBeenCalled()
  })

  it('Scenario: A helper that keeps running is the browser itself', async () => {
    // x-www-browser is the browser, and a generic xdg-open runs it in the foreground: waiting for
    // either to exit would block until the user closes their browser.
    vi.useFakeTimers()
    vi.mocked(open).mockResolvedValue(runningHelper() as any)

    const opening = openBrowser(url)
    await vi.advanceTimersByTimeAsync(600)

    await expect(opening).resolves.toBe(true)
    expect(spawn).not.toHaveBeenCalled()
  })

  it('Scenario: Falling through to a helper that works', async () => {
    // What a host that runs the proxy without the graphical session variables does
    vi.mocked(open).mockResolvedValue(exitingHelper(3) as any)
    vi.mocked(spawn)
      .mockReturnValueOnce(exitingHelper(3) as any)
      .mockReturnValueOnce(exitingHelper(0) as any)

    await expect(openBrowser(url)).resolves.toBe(true)
    expect(vi.mocked(spawn).mock.calls.map(([command]) => command)).toEqual(['/usr/bin/xdg-open', 'gio'])
  })

  it('Scenario: Nothing can open a browser', async () => {
    vi.mocked(open).mockResolvedValue(exitingHelper(3) as any)
    vi.mocked(spawn).mockReturnValue(exitingHelper(3) as any)

    await expect(openBrowser(url)).resolves.toBe(false)
    expect(spawn).toHaveBeenCalledTimes(4)
  })

  it('Scenario: A helper that is not installed', async () => {
    vi.mocked(open).mockRejectedValue(new Error('spawn ENOENT'))
    vi.mocked(spawn).mockImplementation(() => missingHelper() as any)

    await expect(openBrowser(url)).resolves.toBe(false)
  })
})
