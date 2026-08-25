import { spawn, type ChildProcess } from 'child_process'
import open from 'open'
import { log, debugLog } from './utils'

/** How long a helper is given to fail before we accept that it launched something. */
const HELPER_SETTLE_MS = 500

/** Helpers to try on Linux, in order, when the bundled opener does not work. */
const LINUX_FALLBACKS: Array<{ command: string; args: (url: string) => string[] }> = [
  { command: '/usr/bin/xdg-open', args: (url) => [url] },
  { command: 'gio', args: (url) => ['open', url] },
  { command: 'x-www-browser', args: (url) => [url] },
  { command: 'sensible-browser', args: (url) => [url] },
]

/**
 * Reports whether a spawned helper launched anything
 *
 * A helper still running once it has had a chance to fail counts as a success: `x-www-browser` is
 * the browser itself, and a generic `xdg-open` runs it in the foreground, so waiting for either to
 * exit would block until the user closes their browser.
 * @param child The spawned helper
 * @param name The helper's name, for logging
 * @returns True unless the helper failed to start or exited with a failure
 */
function launched(child: ChildProcess, name: string): Promise<boolean> {
  return new Promise((resolve) => {
    const settle = setTimeout(() => {
      debugLog(`Browser helper ${name} is still running, treating it as the browser`)
      resolve(true)
    }, HELPER_SETTLE_MS)
    settle.unref?.()

    const settled = (result: boolean) => {
      clearTimeout(settle)
      resolve(result)
    }

    child.once('error', (error) => {
      debugLog(`Browser helper ${name} failed to start`, error)
      settled(false)
    })
    child.once('exit', (code) => {
      debugLog(`Browser helper ${name} exited`, { code })
      settled(code === 0)
    })
  })
}

/**
 * Opens a URL in the user's browser, falling back through the platform's other openers
 *
 * The bundled opener resolves as soon as its helper is spawned, which on a host that runs the
 * proxy without the graphical session variables reports success while nothing opens.
 * @param url The URL to open
 * @returns True if one of the helpers launched something
 */
export async function openBrowser(url: string): Promise<boolean> {
  debugLog('Browser launch environment', {
    DISPLAY: process.env.DISPLAY,
    WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY,
    DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS ? 'set' : undefined,
    BROWSER: process.env.BROWSER,
  })

  try {
    if (await launched(await open(url), 'open')) {
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
      if (await launched(spawn(fallback.command, fallback.args(url), { stdio: 'ignore' }), fallback.command)) {
        return true
      }
    } catch (error) {
      debugLog(`Failed to spawn ${fallback.command}`, error)
    }
  }

  return false
}
