// Simulated second DSH instance (e.g. "Gaming-PC") for live testing.
// Usage: node sim-instance.mjs <statePath> <instanceName>
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const statePath = process.argv[2] || path.join(os.tmpdir(), 'sim-instance.json')
const name = process.argv[3] || 'Gaming-PC'

const inst = createDiscovery({ statePath, log: (m) => console.log('[sim]', m) })
inst.setName(name)
inst.start()
console.log('[sim] started as', name, 'port', inst.status().port)

const shutdown = () => {
  inst.stop()
  console.log('[sim] stopped')
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

// keep alive until killed
setInterval(() => {}, 1000)
