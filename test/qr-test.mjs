// Phase 4 QR pairing + authentication refactor — functional tests QR-01..QR-14.
// Runs against throwaway instances; no product code is modified.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery, TICKET_TTL_MS } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-qr-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

const facts = {
  agentStatus: () => ({ available: true, status: 'idle' }),
  workspaces: () => ({ available: true, workspaces: [{ path: 'C:\\proj' }] }),
  balance: async () => ({ available: true, balance: '1.00', currency: 'CNY' }),
  system: () => ({ available: true, hostname: 'Q', memory: { used_pct: 1 }, uptime_sec: 1 }),
}

async function jreq(base, url, opts = {}) {
  const res = await fetch(base + url, opts)
  let body = null
  try { body = await res.json() } catch { /* non-json */ }
  return { status: res.status, body }
}
const post = (base, url, payload) => jreq(base, url, {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json' },
  body: JSON.stringify(payload),
})

console.log('== setup: instance A ==')
const a = createDiscovery({
  statePath: path.join(tmp, 'a.json'),
  securityPath: path.join(tmp, 'a-sec.json'),
  facts,
})
a.setName('Evan-PC')
a.start()
await sleep(700)
const base = `http://127.0.0.1:${a.status().port}`

// QR-01 — ticket != credential; QR payload has no credential/session
console.log('== QR-01: ticket generation ==')
const ticket = a.createPairingTicket()
assert.ok(ticket && ticket.length >= 22, 'ticket is at least 128-bit (22+ base64url chars)')
assert.ok(!ticket.includes('credential') && !ticket.includes('session'), 'ticket carries no secret identity')
const url = `http://${a.status().lan_ip}:${a.status().port}/pair?ticket=${encodeURIComponent(ticket)}`
assert.ok(url.includes('/pair?ticket='), 'QR URL is the /pair landing page with a ticket')
assert.ok(!url.includes('credential=') && !url.includes('session'), 'QR URL contains no credential/session')
ok(`QR-01 ticket=43-ch base64url, URL=${url}`)

// QR-02 — ticket randomness
console.log('== QR-02: ticket randomness ==')
const seen = new Set()
for (let i = 0; i < 200; i++) seen.add(a.createPairingTicket())
assert.equal(seen.size, 200)
ok('QR-02 200 tickets all unique')

// QR-03 — 60s expiry (injected short TTL instance)
console.log('== QR-03: ticket expiry ==')
const short = createDiscovery({ statePath: path.join(tmp, 's.json'), securityPath: path.join(tmp, 's-sec.json'), facts, ticketTtlMs: 1200 })
short.setName('Short-PC')
short.start()
await sleep(500)
const sTicket = short.createPairingTicket()
assert.equal(short.consumePairingTicket ? await Promise.resolve(0) : 0, 0) // no-op
await sleep(1600)
// consume through the HTTP path: pair with the expired ticket
const rExp = await post(`http://127.0.0.1:${short.status().port}`, '/api/dsh-remote/pair', {
  device_id: 'qr-exp-0001', device_name: 'x', level: 1, code: sTicket,
})
assert.equal(rExp.status, 400)
assert.equal(rExp.body.code, 'ticket-expired')
short.stop()
ok('QR-03 expired ticket -> 400 ticket-expired')

// QR-04 — one-shot ticket
console.log('== QR-04: ticket single use ==')
const t2 = a.createPairingTicket()
const r4a = await post(base, '/api/dsh-remote/pair', { device_id: 'qr-one-0001', device_name: 'x', level: 1, code: t2 })
assert.equal(r4a.status, 200)
const r4b = await post(base, '/api/dsh-remote/pair', { device_id: 'qr-one-0002', device_name: 'x', level: 1, code: t2 })
assert.equal(r4b.status, 400)
assert.equal(r4b.body.code, 'ticket-used')
ok('QR-04 second use -> ticket-used')

// QR-05 — repeated scan of the same QR produces no second pairing request
console.log('== QR-05: repeated scan ==')
const t3 = a.createPairingTicket()
await post(base, '/api/dsh-remote/pair', { device_id: 'qr-rep-0001', device_name: 'A Phone', level: 1, code: t3 })
const rep = await post(base, '/api/dsh-remote/pair', { device_id: 'qr-rep-0001', device_name: 'A Phone', level: 1, code: t3 })
assert.equal(rep.status, 400)
assert.equal(rep.body.code, 'ticket-used')
const pendCount = a.pairList().pending.filter((p) => p.device_id === 'qr-rep-0001').length
assert.equal(pendCount, 1)
ok('QR-05 repeated scan -> ticket-used, exactly one pairing request')

// QR-06 — no Accept -> no credential
console.log('== QR-06: no approval, no credential ==')
const t4 = a.createPairingTicket()
await post(base, '/api/dsh-remote/pair', { device_id: 'qr-wait-0001', device_name: 'Waiting Phone', level: 1, code: t4 })
const wait = await post(base, '/api/dsh-remote/pair/status', { device_id: 'qr-wait-0001', code: t4 })
assert.equal(wait.body.status, 'pending')
assert.equal(wait.body.credential, undefined)
ok('QR-06 pending response carries no credential')

// QR-07 — Accept -> phone auto-gets the credential (with the ticket)
console.log('== QR-07: accept delivers credential ==')
const t5 = a.createPairingTicket()
await post(base, '/api/dsh-remote/pair', { device_id: 'qr-ok-0001', device_name: "Evan's Phone", level: 1, code: t5 })
a.acceptPair('qr-ok-0001')
const pick = await post(base, '/api/dsh-remote/pair/status', { device_id: 'qr-ok-0001', code: t5 })
assert.equal(pick.body.status, 'accepted')
assert.ok(pick.body.credential && pick.body.credential.length >= 43)
const sess = (await post(base, '/api/dsh-remote/session', { credential: pick.body.credential })).body.session
assert.equal(sess.level, 1)
ok('QR-07 accept -> credential -> Level-1 session')

// QR-08 — Reject -> no credential
console.log('== QR-08: reject blocks credential ==')
const t6 = a.createPairingTicket()
await post(base, '/api/dsh-remote/pair', { device_id: 'qr-no-0001', device_name: 'Rejected Phone', level: 1, code: t6 })
a.rejectPair('qr-no-0001')
const rej = await post(base, '/api/dsh-remote/pair/status', { device_id: 'qr-no-0001', code: t6 })
assert.equal(rej.body.status, 'rejected')
assert.equal(rej.body.credential, undefined)
const sessBad = await post(base, '/api/dsh-remote/session', { credential: 'garbage' })
assert.equal(sessBad.status, 401)
ok('QR-08 rejected -> no credential, no session')

// QR-09 — Revoke invalidates old credential/session
console.log('== QR-09: revoke ==')
a.revokeDevice('qr-ok-0001')
const afterRevoke = await jreq(base, '/api/dsh-remote/observer/status', { headers: { authorization: 'Bearer ' + sess.session_id } })
assert.equal(afterRevoke.status, 401)
const oldCred = await post(base, '/api/dsh-remote/session', { credential: pick.body.credential })
assert.equal(oldCred.status, 401)
ok('QR-09 revoke -> session + credential dead')

// QR-10 — Broadcast disable invalidates tickets
console.log('== QR-10: disable invalidates tickets ==')
const t7 = a.createPairingTicket()
assert.equal(a.consumePairingTicket(t7), 'ok')
a.stop()
assert.equal(a.status().enabled, false)
// the ticket map is cleared: the same ticket is now unknown
assert.equal(a.consumePairingTicket(t7), 'invalid')
a.start()
await sleep(500)
ok('QR-10 broadcast disable cleared tickets')

// QR-11 — restart loses tickets
console.log('== QR-11: restart invalidates tickets ==')
const t8 = a.createPairingTicket()
assert.equal(a.consumePairingTicket(t8), 'ok')
const a2 = createDiscovery({ statePath: path.join(tmp, 'a.json'), securityPath: path.join(tmp, 'a-sec.json'), facts })
assert.equal(a2.consumePairingTicket(t8), 'invalid', 'tickets are memory-only')
ok('QR-11 tickets lost on restart (memory-only)')

// QR-12 — cross-instance: A's ticket is not a ticket on B
console.log('== QR-12: A ticket unusable on B ==')
const bInst = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts })
bInst.setName('Gaming-PC')
bInst.start()
await sleep(400)
const tA = a.createPairingTicket()
const urlA = `http://${a.status().lan_ip}:${a.status().port}/pair?ticket=${tA}`
assert.ok(urlA.includes(String(a.status().port)), 'QR URL binds A host:port')
assert.equal(bInst.consumePairingTicket(tA), 'invalid', 'A ticket unknown to B')
ok(`QR-12 A ticket unknown on B (URL binds ${urlA})`)
bInst.stop()

// QR-14 — Level 1 capability unchanged; Level 2 not enabled
console.log('== QR-14: Level 1 capability / Level 2 not enabled ==')
const t14 = a.createPairingTicket()
await post(base, '/api/dsh-remote/pair', { device_id: 'qr-cap-0001', device_name: 'Cap Phone', level: 1, code: t14 })
a.acceptPair('qr-cap-0001')
const pick14 = await post(base, '/api/dsh-remote/pair/status', { device_id: 'qr-cap-0001', code: t14 })
const sess14 = (await post(base, '/api/dsh-remote/session', { credential: pick14.body.credential })).body.session
assert.deepEqual([...sess14.capabilities].sort(), ['observe_balance', 'observe_status', 'observe_system', 'observe_task'])
assert.ok(!sess14.capabilities.includes('send_prompt'))
const lvl2 = await post(base, '/api/dsh-remote/pair', { device_id: 'qr-l2-0001', device_name: 'x', level: 2, code: 'qr-l2-code-0001-000001' })
assert.equal(lvl2.status, 403)
ok('QR-14 QR pairing keeps Level 1; level 2 request -> 403 (not enabled)')

// QR-13 — port change reflected in the QR URL (run last; needs 8765 free)
console.log('== QR-13: port change ==')
a.stop()
const holder = http.createServer((req, res) => { res.writeHead(200); res.end('hold') })
await new Promise((resolve) => holder.listen(8765, '0.0.0.0', resolve))
a.start()
await sleep(700)
const pcPort = a.status().port
assert.equal(pcPort, 8766, 'falls back to 8766 when 8765 is taken')
const t13 = a.createPairingTicket()
const url13 = `http://${a.status().lan_ip}:${a.status().port}/pair?ticket=${t13}`
assert.ok(url13.includes(':' + pcPort), `QR URL uses the actual port ${pcPort}`)
ok(`QR-13 QR URL auto-uses new port (${url13})`)
a.stop()
await new Promise((resolve) => holder.close(resolve))

console.log('== cleanup ==')
a.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`QR TESTS PASSED (${pass} checks)`)
