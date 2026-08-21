import { spawn } from 'child_process'
import open from 'open'
import { log, debugLog } from './utils'

/**
 * Waits for a spawned helper and reports whether it actually succeeded, since helpers such as
 * xdg-open exit well after the spawn resolves
 */
function waitForHelper(child: ReturnType<typeof spawn>, name: string): Promise<boolean> {
  return new Promise((resolve) => {
    let stderr = ''
    child.stderr?.on('data', (chunk) => {
      stderr += String(chunk)
    })
    child.once('error', (error) => {
      debugLog(`Browser helper ${name} failed to start`, error)
      resolve(false)
    })
    child.once('exit', (code) => {
      if (code === 0) {
        debugLog(`Browser helper ${name} exited cleanly`)
        resolve(true)
        return
      }
      debugLog(`Browser helper ${name} exited with a failure`, { code, stderr: stderr.slice(0, 500) })
      resolve(false)
    })
  })
}

/** Helpers to try on Linux, in order, when the bundled opener does not work. */
const LINUX_FALLBACKS: Array<{ command: string; args: (url: string) => string[] }> = [
  { command: '/usr/bin/xdg-open', args: (url) => [url] },
  { command: 'gio', args: (url) => ['open', url] },
  { command: 'x-www-browser', args: (url) => [url] },
  { command: 'sensible-browser', args: (url) => [url] },
]

/**
 * Opens a URL in the user's browser, falling back through the platform's other openers.
 *
 * @returns True if one of the helpers reported success
 */
export async function openBrowser(url: string): Promise<boolean> {
  debugLog('Browser launch environment', {
    DISPLAY: process.env.DISPLAY,
    WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY,
    DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS ? 'set' : undefined,
    BROWSER: process.env.BROWSER,
    PATH: process.env.PATH,
  })

  try {
    if (await waitForHelper(await open(url), 'open')) {
      return true
    }
  } catch (error) {
    debugLog('Failed to spawn the bundled opener', error)
  }

  if (process.platform !== 'linux') {
    return false
  }

  for (const fallback of LINUX_FALLBACKS) {
    try {
      log(`Trying ${fallback.command} to open the browser...`)
      if (await waitForHelper(spawn(fallback.command, fallback.args(url), { stdio: 'ignore' }), fallback.command)) {
        return true
      }
    } catch (error) {
      debugLog(`Failed to spawn ${fallback.command}`, error)
    }
  }

  return false
}
