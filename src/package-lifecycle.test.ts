import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import packageJson from '../package.json'

describe('git dependency package lifecycle', () => {
  it('ships the built proxy files without requiring a Git install build hook', () => {
    expect((packageJson.scripts as Record<string, string>).prepare).toBeUndefined()
    expect(existsSync(fileURLToPath(new URL('../dist/proxy.js', import.meta.url)))).toBe(true)
    expect(execFileSync('git', ['ls-files', 'dist/proxy.js'], { encoding: 'utf8' })).toBe('dist/proxy.js\n')
  })
})
