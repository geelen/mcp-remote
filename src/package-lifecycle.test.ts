import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import packageJson from '../package.json'

describe('git dependency package lifecycle', () => {
  it('ships the built proxy files without requiring a Git install build hook', () => {
    expect((packageJson.scripts as Record<string, string>).prepare).toBeUndefined()
    expect(existsSync(fileURLToPath(new URL('../dist/proxy.js', import.meta.url)))).toBe(true)
    expect(execFileSync('git', ['ls-files', 'dist/proxy.js'], { encoding: 'utf8' })).toBe('dist/proxy.js\n')
  })

  it('tracks every generated chunk imported by a distributable entrypoint', () => {
    for (const entrypoint of ['client.js', 'proxy.js']) {
      const entrypointPath = fileURLToPath(new URL(`../dist/${entrypoint}`, import.meta.url))
      const importedChunks = [...readFileSync(entrypointPath, 'utf8').matchAll(/from "\.\/(chunk-[A-Z0-9]+\.js)"/g)].map(
        ([, chunk]) => chunk,
      )

      expect(importedChunks.length).toBeGreaterThan(0)
      for (const chunk of importedChunks) {
        const chunkPath = `dist/${chunk}`
        expect(existsSync(fileURLToPath(new URL(`../${chunkPath}`, import.meta.url)))).toBe(true)
        expect(execFileSync('git', ['ls-files', chunkPath], { encoding: 'utf8' })).toBe(`${chunkPath}\n`)
      }
    }
  })
})
