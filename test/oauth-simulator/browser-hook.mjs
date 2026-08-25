// Registers the module alias below into the running instance. Passed via --import.
import { register } from 'node:module'
register('./browser-resolver.mjs', import.meta.url)
