// Quick smoke test for the Phase 4 ticket + claim_hash refactor.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-smoke-'))
const d = createDiscovery({ statePath: path.join(tmp, 's.json'), securityPath: path.join(tmp, 'sec.json'), facts: {} })
d.setName('Smoke-PC')
d.start()
await new Promise((r) => setTimeout(r, 600))
const base = 'http://127.0.0.1:' + d.status().port
const post = async (u, b) => (await fetch(base + u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })).json()

const ticket = d.createPairingTicket()
console.log('ticket len', ticket.length, '~bits', ticket.length * 6)

const page = await fetch(base + '/pair?ticket=' + encodeURIComponent(ticket))
console.log('page status', page.status, 'has title', (await page.text()).includes('DSH Remote'))

const r1 = await post('/api/dsh-remote/pair', { device_id: 'qr-phone-0001', device_name: "Evan's Phone", level: 1, code: ticket })
console.log('pair with ticket:', JSON.stringify(r1))

d.acceptPair('qr-phone-0001')
const pick = await post('/api/dsh-remote/pair/status', { device_id: 'qr-phone-0001', code: ticket })
console.log('pickup:', pick.status, 'credLen', pick.credential ? pick.credential.length : 0)

const r2 = await post('/api/dsh-remote/pair', { device_id: 'qr-phone-0002', device_name: 'x', level: 1, code: ticket })
console.log('second scan of same ticket:', JSON.stringify(r2))

const legacy = 'legacy-code-0001-000001'
await post('/api/dsh-remote/pair', { device_id: 'leg-0001', device_name: 'L', level: 1, code: legacy })
d.acceptPair('leg-0001')
const pick2 = await post('/api/dsh-remote/pair/status', { device_id: 'leg-0001', code: legacy })
console.log('legacy pickup:', pick2.status, 'credLen', pick2.credential ? pick2.credential.length : 0)

d.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log('SMOKE OK')
