// Redirects the instance's `open` import to our stub, so a test never launches a real browser.
// Done as a module alias rather than a PATH shim because the `open` package resolves its helper
// by absolute path on macOS and prefers its own bundled xdg-open on Linux, so a shim is not
// reliably reached on either.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'open') {
    return { url: new URL('./browser-stub.mjs', import.meta.url).href, shortCircuit: true }
  }
  return nextResolve(specifier, context)
}
