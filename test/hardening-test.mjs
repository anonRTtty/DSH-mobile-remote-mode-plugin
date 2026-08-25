// Phase 3 hardening tests (H1-H10) against throwaway instances.
// Asserts the F-01..F-06 fixes: 409 duplicate pair, immutable pending/TTL,
// pending cap, session cap, SSE cap, balance single-flight, SSE no-overlap,
// session idle expiry with real deletion, CSRF Origin gate, Content-Type 415.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-harden-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

const baseFacts = {
  agentStatus: () => ({ available: true, status: 'idle' }),
  workspaces: () => ({ available: true, workspaces: [{ path: 'C:\\proj' }] }),
  system: () => ({ available: true, hostname: 'H', memory: { used_pct: 1 }, uptime_sec: 1 }),
}

async function jreq(base, url, opts = {}) {
  const res = await fetch(base + url, opts)
  let body = null
  try { body = await res.json() } catch { /* non-json */ }
  return { status: res.status, body }
}
const post = (base, url, payload, extra) => jreq(base, url, {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json', ...(extra || {}) },
  body: JSON.stringify(payload),
})

console.log('== setup ==')
let balanceCalls = 0
const a = createDiscovery({
  statePath: path.join(tmp, 'a.json'),
  securityPath: path.join(tmp, 'a-sec.json'),
  facts: {
    ...baseFacts,
    balance: async () => {
      balanceCalls += 1
      await sleep(60)
      return { available: true, balance: '9.99', currency: 'CNY' }
    },
  },
})
a.setName('H-PC')
a.start()
await sleep(700)
const base = `http://127.0.0.1:${a.status().port}`

// H1 — duplicate pair -> 409 (F-01)
console.log('== H1: duplicate pair -> 409 ==')
let r = await post(base, '/api/dsh-remote/pair', { device_id: 'h1-dev-0001', device_name: 'A', level: 1, code: 'h1-code-0001-000001' })
assert.equal(r.status, 200)
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h1-dev-0001', device_name: 'Evil', level: 1, code: 'h1-code-0002-000002' })
assert.equal(r.status, 409)
assert.equal(r.body.code, 'already-pending')
ok('duplicate pair (different code) -> 409')

// H2 — replay does not refresh TTL (F-06)
console.log('== H2: pair replay leaves TTL untouched ==')
await post(base, '/api/dsh-remote/pair', { device_id: 'h2-dev-0001', device_name: 'B', level: 1, code: 'h2-code-0001-000001' })
const c1 = a.pairList().pending.find((p) => p.device_id === 'h2-dev-0001').created_at_ms
await sleep(1100)
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h2-dev-0001', device_name: 'B', level: 1, code: 'h2-code-0001-000001' })
assert.equal(r.status, 200)
const c2 = a.pairList().pending.find((p) => p.device_id === 'h2-dev-0001').created_at_ms
assert.equal(c2, c1)
ok('same-code replay idempotent; created_at/expires_at unchanged')

// H3 — pending overflow -> 429 (F-02) on a dedicated instance
console.log('== H3: pending cap -> 429 ==')
const capInst = createDiscovery({
  statePath: path.join(tmp, 'cap.json'),
  securityPath: path.join(tmp, 'cap-sec.json'),
  facts: baseFacts,
})
capInst.setName('Cap-PC')
capInst.start()
await sleep(700)
const baseCap = `http://127.0.0.1:${capInst.status().port}`
let capHit = null
let held = 0
for (let i = 0; i < 120; i++) {
  r = await post(baseCap, '/api/dsh-remote/pair', { device_id: `h3-${String(i).padStart(5, '0')}`, device_name: 'f', level: 1, code: `h3-code-${String(i).padStart(8, '0')}` })
  if (r.status === 429) { capHit = r; break }
}
held = capInst.pairList().pending.length
assert.ok(capHit && capHit.body.code === 'too-many-pending', `expected 429 too-many-pending, got ${JSON.stringify(capHit)}`)
assert.ok(held <= 100, `pending held=${held}`)
capInst.stop()
ok(`pending overflow -> 429 (held=${held})`)

// H4 — session overflow -> 429 (F-03)
console.log('== H4: session cap -> 429 ==')
await post(base, '/api/dsh-remote/pair', { device_id: 'h4-dev-0001', device_name: 'S', level: 1, code: 'h4-code-0001-000001' })
a.acceptPair('h4-dev-0001')
const pick = await post(base, '/api/dsh-remote/pair/status', { device_id: 'h4-dev-0001', code: 'h4-code-0001-000001' })
const cred = pick.body.credential
const created = []
for (let i = 0; i < 6; i++) {
  r = await post(base, '/api/dsh-remote/session', { credential: cred })
  if (r.status === 200) created.push(r.body.session.session_id)
  else break
}
assert.equal(created.length, 5)
r = await post(base, '/api/dsh-remote/session', { credential: cred })
assert.equal(r.status, 429)
assert.equal(r.body.code, 'session-limit')
ok('6th session for one device -> 429')

// H5 — SSE overflow -> 429 (F-03)
console.log('== H5: SSE cap -> 429 ==')
const sid = created[0]
const sse1 = await fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sid } })
assert.equal(sse1.status, 200)
const sse2 = await fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sid } })
assert.equal(sse2.status, 200)
const sse3 = await fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sid } })
assert.equal(sse3.status, 429)
const b3 = await sse3.json()
assert.equal(b3.code, 'sse-limit')
sse1.body.getReader().cancel()
sse2.body.getReader().cancel()
ok('3rd SSE connection for one session -> 429')

// H6 — balance single-flight (F-04) on a dedicated instance (clean cache)
console.log('== H6: balance single-flight ==')
let sfCalls = 0
const sf = createDiscovery({
  statePath: path.join(tmp, 'sf.json'),
  securityPath: path.join(tmp, 'sf-sec.json'),
  facts: {
    ...baseFacts,
    balance: async () => {
      sfCalls += 1
      await sleep(80)
      return { available: true, balance: '9.99', currency: 'CNY' }
    },
  },
})
sf.setName('SF-PC')
sf.start()
await sleep(700)
const baseSF = `http://127.0.0.1:${sf.status().port}`
await post(baseSF, '/api/dsh-remote/pair', { device_id: 'h6-dev-0001', device_name: 'F', level: 1, code: 'h6-code-0001-000001' })
sf.acceptPair('h6-dev-0001')
const pick6 = await post(baseSF, '/api/dsh-remote/pair/status', { device_id: 'h6-dev-0001', code: 'h6-code-0001-000001' })
const sess6 = (await post(baseSF, '/api/dsh-remote/session', { credential: pick6.body.credential })).body.session
await Promise.all(
  Array.from({ length: 10 }, () => jreq(baseSF, '/api/dsh-remote/observer/status', { headers: { authorization: 'Bearer ' + sess6.session_id } })),
)
assert.equal(sfCalls, 1, `10 concurrent observers should trigger 1 balance fetch, got ${sfCalls}`)
sf.stop()
ok(`balance single-flight: 10 concurrent observers -> 1 fetch (${sfCalls})`)

// H7 — slow balance + SSE no overlap (F-04)
console.log('== H7: slow balance, SSE pushes never overlap ==')
let slowCalls = 0
const slow = createDiscovery({
  statePath: path.join(tmp, 'slow.json'),
  securityPath: path.join(tmp, 'slow-sec.json'),
  facts: {
    ...baseFacts,
    balance: async () => {
      slowCalls += 1
      await sleep(3000)
      return { available: true, balance: '1.00', currency: 'CNY' }
    },
  },
})
slow.setName('Slow-PC')
slow.start()
await sleep(700)
const baseSlow = `http://127.0.0.1:${slow.status().port}`
await post(baseSlow, '/api/dsh-remote/pair', { device_id: 'h7-dev-0001', device_name: 'S', level: 1, code: 'h7-code-0001-000001' })
slow.acceptPair('h7-dev-0001')
const pick7 = await post(baseSlow, '/api/dsh-remote/pair/status', { device_id: 'h7-dev-0001', code: 'h7-code-0001-000001' })
const sess7 = (await post(baseSlow, '/api/dsh-remote/session', { credential: pick7.body.credential })).body.session
const sse = await fetch(baseSlow + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sess7.session_id } })
const reader = sse.body.getReader()
const frames = []
const readLoop = (async () => {
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += new TextDecoder().decode(value)
    let sep
    while ((sep = buf.indexOf('\n\n')) >= 0) {
      frames.push(buf.slice(0, sep))
      buf = buf.slice(sep + 2)
    }
  }
})()
await sleep(5500) // ~3 SSE ticks at 2 s; the 3 s balance fetch must not overlap
assert.equal(slowCalls, 1, `slow balance should be fetched once, got ${slowCalls}`)
assert.ok(frames.length >= 1, 'at least one status frame delivered')
await reader.cancel()
slow.stop()
ok(`slow balance (3s) with 2s ticks -> ${slowCalls} fetch, ${frames.length} frames (no overlap)`)

// H8 — session idle expiry -> 401 + real deletion (F-03)
console.log('== H8: idle session expiry ==')
const exp = createDiscovery({
  statePath: path.join(tmp, 'exp.json'),
  securityPath: path.join(tmp, 'exp-sec.json'),
  idleTimeoutMs: 1500,
  facts: baseFacts,
})
exp.setName('Exp-PC')
exp.start()
await sleep(700)
const baseExp = `http://127.0.0.1:${exp.status().port}`
await post(baseExp, '/api/dsh-remote/pair', { device_id: 'h8-dev-0001', device_name: 'E', level: 1, code: 'h8-code-0001-000001' })
exp.acceptPair('h8-dev-0001')
const pick8 = await post(baseExp, '/api/dsh-remote/pair/status', { device_id: 'h8-dev-0001', code: 'h8-code-0001-000001' })
const cred8 = pick8.body.credential
// fill to the cap, wait past idle, then refill: expired sessions must be really gone
for (let i = 0; i < 5; i++) await post(baseExp, '/api/dsh-remote/session', { credential: cred8 })
await sleep(2200)
let refilled = 0
let freshSid = null
for (let i = 0; i < 5; i++) {
  const rr = await post(baseExp, '/api/dsh-remote/session', { credential: cred8 })
  if (rr.status === 200) { refilled += 1; freshSid = rr.body.session.session_id }
}
assert.equal(refilled, 5, `expected 5 fresh sessions after expiry, got ${refilled}`)
// and an expired session token is now rejected
await sleep(2200)
r = await jreq(baseExp, '/api/dsh-remote/observer/status', { headers: { authorization: 'Bearer ' + freshSid } })
assert.equal(r.status, 401)
ok('idle-expired sessions deleted (refill works) and old token -> 401')
exp.stop()

// H9 — CSRF Origin gate (F-05)
console.log('== H9: Origin allowlist on /pair ==')
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h9-evil-0001', device_name: 'x', level: 1, code: 'h9-code-0001-000001' }, { origin: 'http://evil.example' })
assert.equal(r.status, 403)
assert.equal(r.body.code, 'origin-forbidden')
ok('malicious Origin -> 403')
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h9-self-0001', device_name: 'x', level: 1, code: 'h9-code-0001-000001' }, { origin: `http://127.0.0.1:${a.status().port}` })
assert.equal(r.status, 200)
ok('own origin allowed')
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h9-null-0001', device_name: 'x', level: 1, code: 'h9-code-0001-000001' }, { origin: 'null' })
assert.equal(r.status, 403)
ok('Origin: null rejected')
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h9-none-0001', device_name: 'x', level: 1, code: 'h9-code-0001-000001' })
assert.equal(r.status, 200)
ok('no Origin (non-browser fallback) allowed')
// cross-instance: phone page served by B may pair with A
const bInst = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts: baseFacts })
bInst.setName('B-PC')
bInst.start()
await sleep(2500) // mutual discovery
const baseB = `http://127.0.0.1:${bInst.status().port}`
r = await post(base, '/api/dsh-remote/pair', { device_id: 'h9-cross-0001', device_name: 'x', level: 1, code: 'h9-code-0001-000001' }, { origin: `http://127.0.0.1:${bInst.status().port}` })
assert.equal(r.status, 200)
ok('discovered-instance origin allowed (cross-instance pairing)')

// H10 — Content-Type 415
console.log('== H10: Content-Type enforcement ==')
r = await jreq(base, '/api/dsh-remote/pair', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify({ device_id: 'h10-0001', device_name: 'x', level: 1, code: 'h10-code-0001-000001' }) })
assert.equal(r.status, 415)
r = await jreq(base, '/api/dsh-remote/session', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify({ credential: 'x' }) })
assert.equal(r.status, 415)
ok('text/plain JSON -> 415 on pair and session')

console.log('== cleanup ==')
a.stop()
bInst.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`HARDENING TESTS PASSED (${pass} checks)`)
