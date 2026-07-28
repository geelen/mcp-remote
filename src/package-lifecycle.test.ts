import { describe, expect, it } from 'vitest'
import packageJson from '../package.json'

describe('git dependency package lifecycle', () => {
  it('builds the distributable files before npm packages a Git dependency', () => {
    expect(packageJson.scripts.prepare).toBe('npm run build')
  })
})
