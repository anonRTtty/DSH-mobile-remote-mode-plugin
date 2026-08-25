// Phase 2.5 adversarial security audit — read-only, against throwaway
// instances (temp state/security files). No product code is modified.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import dgram from 'node:dgram'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery, MULTICAST_GROUP, MULTICAST_PORT } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-audit-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0, fail = 0
const ok = (name) => { pass++; console.log('  PASS', name) }
const bad = (name, extra) => { fail++; console.log('  FAIL', name, extra || '') }

const facts = {
  agentStatus: () => ({ available: true, status: 'idle' }),
  workspaces: () => ({ available: true, workspaces: [{ path: 'C:\\proj', title: 'proj' }] }),
  balance: async () => ({ available: true, balance: '1.00', currency: 'CNY' }),
  system: () => ({ available: true, hostname: 'AUDIT-PC', memory: { used_pct: 10 }, uptime_sec: 60 }),
}

async function jreq(base, url, opts = {}) {
  const res = await fetch(base + url, opts)
  let body = null
  try { body = await res.json() } catch { /* non-json */ }
  return { status: res.status, body }
}
const post = (base, url, payload, headers) => jreq(base, url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', ...(headers || {}) }, body: JSON.stringify(payload) })

// ---------------------------------------------------------------- setup
console.log('== setup: throwaway instance A ==')
const a = createDiscovery({
  statePath: path.join(tmp, 'a.json'),
  securityPath: path.join(tmp, 'a-sec.json'),
  facts,
})
a.setName('Audit-PC')
a.start()
await sleep(700)
const base = `http://127.0.0.1:${a.status().port}`
console.log('  port', a.status().port)

// ------------------------------------------------------------------ A. HTTP / allowlist
console.log('== A. allowlist / path normalization ==')
let r
for (const [url, method, expected] of [
  ['/api/dsh-remote/observer/status/../pair', 'GET', 403],
  ['/api%2Fdsh-remote%2Fpair', 'GET', 403],
  ['//api/dsh-remote/pair', 'GET', 403],
  ['/api/dsh-remote/session/', 'GET', 403],
  ['/api/dsh-remote/pair%2Fstatus', 'GET', 403],
  ['/api/dsh-remote/;pair', 'GET', 403],
  ['/api/dsh-remote/observer/status?x=/api/dsh-remote/session', 'GET', 401],
  ['/api/dsh-remote/session', 'GET', 403],
  ['/api/dsh-remote/pair', 'GET', 403],
  ['/api/dsh-remote/observer/status', 'POST', 403],
  ['/api/dsh-remote/instances', 'POST', 403],
  ['/api/dsh-remote/pair', 'DELETE', 403],
]) {
  r = await jreq(base, url, { method })
  r.status === expected ? ok(`path/method gate ${method} ${url} -> ${r.status}`) : bad(`path gate ${method} ${url}`, `got ${r.status}, want ${expected}`)
}
const optRes = await fetch(base + '/api/dsh-remote/pair', { method: 'OPTIONS' })
optRes.status === 204 && optRes.headers.get('access-control-allow-origin') === '*' ? ok('OPTIONS preflight allowed (by design, harmless)') : bad('OPTIONS', String(optRes.status))
// trailing-slash on an allowlisted POST path
r = await jreq(base + '/api/dsh-remote/pair/', { method: 'POST', body: '{}' })
r.status === 403 ? ok('trailing slash on POST pair -> 403') : bad('trailing slash POST pair', String(r.status))

// ------------------------------------------------------------------ B. auth parsing
console.log('== B. Authorization parsing ==')
// pair + accept to obtain a credential
await post(base, '/api/dsh-remote/pair', { device_id: 'audit-0001', device_name: 'A Phone', level: 1, code: 'audit-code-0001-0001' })
a.acceptPair('audit-0001')
const pick = await post(base, '/api/dsh-remote/pair/status', { device_id: 'audit-0001', code: 'audit-code-0001-0001' })
const cred = pick.body.credential
const sess = (await post(base, '/api/dsh-remote/session', { credential: cred })).body.session
const sid = sess.session_id
for (const [hdr, expected] of [
  [undefined, 401],
  ['Bearer ', 401],
  ['bearer ' + sid, 401],
  ['Bearer ' + sid + ' extra', 401],
  ['Basic ' + sid, 401],
  ['Bearer' + sid, 401],
  ['Bearer ' + sid.slice(0, 10), 401],
  ['Bearer ' + sid, 200],
]) {
  const headers = hdr === undefined ? {} : { authorization: hdr }
  const rr = await jreq(base, '/api/dsh-remote/observer/status', { headers })
  rr.status === expected ? ok(`auth header ${JSON.stringify((hdr || '').slice(0, 18))}... -> ${rr.status}`) : bad('auth header', `${hdr} -> ${rr.status}, want ${expected}`)
}

// ------------------------------------------------------------------ C. pairing hijack (F-01 FIXED)
console.log('== C. pairing hijack (F-01: overwrite must fail) ==')
await post(base, '/api/dsh-remote/pair', { device_id: 'victim-0001', device_name: 'Victim Phone', level: 1, code: 'victim-code-0001-0001' })
const before = await post(base, '/api/dsh-remote/pair/status', { device_id: 'victim-0001', code: 'victim-code-0001-0001' })
before.body.status === 'pending' ? ok('victim pending') : bad('victim pending')
// attacker re-posts the SAME device_id with their own code + name
const overwrite = await post(base, '/api/dsh-remote/pair', { device_id: 'victim-0001', device_name: 'Evil Name', level: 1, code: 'evil-code-0001-000001' })
overwrite.status === 409 ? ok('attacker overwrite attempt -> 409 (blocked)') : bad('overwrite attempt', `got ${overwrite.status}`)
const victimNow = await post(base, '/api/dsh-remote/pair/status', { device_id: 'victim-0001', code: 'victim-code-0001-0001' })
const attackerNow = await post(base, '/api/dsh-remote/pair/status', { device_id: 'victim-0001', code: 'evil-code-0001-000001' })
if (victimNow.body.status === 'pending' && attackerNow.body.status === 'not-found') {
  ok('pending entry unchanged; attacker code useless')
} else bad('pending immutability', JSON.stringify({ victimNow: victimNow.body, attackerNow: attackerNow.body }))
// accept -> the ORIGINAL code picks up the credential, not the attacker's
a.acceptPair('victim-0001')
const victimPick = await post(base, '/api/dsh-remote/pair/status', { device_id: 'victim-0001', code: 'victim-code-0001-0001' })
const attackerPick = await post(base, '/api/dsh-remote/pair/status', { device_id: 'victim-0001', code: 'evil-code-0001-000001' })
if (victimPick.body.status === 'accepted' && victimPick.body.credential) {
  ok('victim picks up the credential with the original code')
} else bad('victim pickup', JSON.stringify(victimPick.body))
if (!(attackerPick.body.credential)) ok('attacker code cannot pick up anything')
else bad('attacker pickup leaked a credential', JSON.stringify(attackerPick.body))

// ------------------------------------------------------------------ D. TTL not refreshed (F-06 FIXED)
console.log('== D. pairing replay does not refresh TTL ==')
await post(base, '/api/dsh-remote/pair', { device_id: 'ttl-0001', device_name: 'TTL Phone', level: 1, code: 'ttl-code-0001-000001' })
const created1 = a.pairList().pending.find((p) => p.device_id === 'ttl-0001').created_at_ms
await sleep(1100)
const replay = await post(base, '/api/dsh-remote/pair', { device_id: 'ttl-0001', device_name: 'TTL Phone', level: 1, code: 'ttl-code-0001-000001' })
const created2 = a.pairList().pending.find((p) => p.device_id === 'ttl-0001').created_at_ms
replay.status === 200 && created2 === created1
  ? ok('same-code replay is idempotent and TTL is NOT refreshed')
  : bad('ttl refresh', `status=${replay.status} created1=${created1} created2=${created2}`)

// ------------------------------------------------------------------ E. session cap (F-03 FIXED)
console.log('== E. sessions capped per device (429 after 5) ==')
// note: section B already created 1 session for audit-0001
const sids = []
let sixth = null
for (let i = 0; i < 6; i++) {
  const res = await post(base, '/api/dsh-remote/session', { credential: cred })
  if (res.status === 200 && res.body && res.body.ok) sids.push(res.body.session.session_id)
  else if (res.status === 429) sixth = res
}
sids.length === 4 && sixth && sixth.body.code === 'session-limit'
  ? ok('session cap enforced: 4 new + 1 existing = 5, 6th -> 429 (session-limit)')
  : bad('session cap', `sids=${sids.length} sixth=${sixth && sixth.status}`)

// ------------------------------------------------------------------ F. pending cap (F-02 FIXED) on a dedicated instance
console.log('== F. pending requests capped (429 after 100) ==')
const capInst = createDiscovery({ statePath: path.join(tmp, 'cap.json'), securityPath: path.join(tmp, 'cap-sec.json'), facts })
capInst.setName('Cap-PC')
capInst.start()
await sleep(700)
const baseCap = `http://127.0.0.1:${capInst.status().port}`
let capHit = null
for (let i = 0; i < 110; i++) {
  const res = await post(baseCap, '/api/dsh-remote/pair', { device_id: `flood-${String(i).padStart(5, '0')}`, device_name: 'f', level: 1, code: `flood-code-${String(i).padStart(8, '0')}` })
  if (res.status === 429) { capHit = res; break }
}
const pendCount = capInst.pairList().pending.length
capHit && capHit.body.code === 'too-many-pending'
  ? ok(`pending cap enforced: ${pendCount} held, next -> 429 (too-many-pending)`)
  : bad('pending cap', `held=${pendCount} capHit=${capHit && capHit.status}`)
capInst.stop()

// ------------------------------------------------------------------ G. SSE
console.log('== G. SSE auth + lifecycle ==')
r = await fetch(base + '/api/dsh-remote/observer/events', { headers: {} })
r.status === 401 ? ok('SSE without auth -> 401') : bad('SSE no auth', String(r.status))
// valid session SSE receives a frame; revoke then closes with invalid
const sseRes = await fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sids[0] } })
const rd = sseRes.body.getReader()
let sawStatusFrame = false
let sawInvalid = false
const sseLoop = (async () => {
  let buf = ''
  for (;;) {
    const { value, done } = await rd.read()
    if (done) return
    buf += new TextDecoder().decode(value)
    if (buf.includes('event: status') && buf.includes('"ok":true')) sawStatusFrame = true
    if (buf.includes('event: invalid')) { sawInvalid = true; return }
  }
})()
await sleep(400)
sawStatusFrame ? ok('SSE status frame for valid session') : bad('SSE frame missing')
a.revokeDevice('audit-0001')
await sseLoop
sawInvalid ? ok('revoke pushes SSE invalid frame') : bad('revoke sse: no invalid frame')

// ------------------------------------------------------------------ H. fake discovery
console.log('== H. fake discovery broadcast (spoofing) ==')
const fake = dgram.createSocket({ type: 'udp4' })
fake.bind(0, '0.0.0.0', () => {
  fake.setMulticastTTL(1)
  fake.setMulticastLoopback(true)
  fake.send(Buffer.from(JSON.stringify({ service: 'dsh-remote', version: '1', instance_id: 'fake-1234-5678', instance_name: 'Fake DSH', port: 9999, status: 'online' })), MULTICAST_PORT, MULTICAST_GROUP)
  setTimeout(() => fake.close(), 300)
})
await sleep(2500)
const list = (await jreq(base, '/api/dsh-remote/instances')).body.instances
list.some((i) => i.instance_name === 'Fake DSH' && i.status === 'online')
  ? ok('CONFIRMED: an attacker can broadcast a fake instance that the phone page lists as online (discovery spoofing, by design)')
  : bad('fake broadcast')

// ------------------------------------------------------------------ I. data exposure
console.log('== I. observer payload exposure ==')
// fresh device + session (previous device was revoked in G)
await post(base, '/api/dsh-remote/pair', { device_id: 'audit-0002', device_name: 'Observer Phone', level: 1, code: 'audit-code-0002-0001' })
a.acceptPair('audit-0002')
const pick2 = await post(base, '/api/dsh-remote/pair/status', { device_id: 'audit-0002', code: 'audit-code-0002-0001' })
const sess2 = (await post(base, '/api/dsh-remote/session', { credential: pick2.body.credential })).body.session
const obsResp = await jreq(base, '/api/dsh-remote/observer/status', { headers: { authorization: 'Bearer ' + sess2.session_id } })
obsResp.status === 200 ? ok('observer 200 with valid session') : bad('observer status', String(obsResp.status))
const obs = obsResp.body
const flat = JSON.stringify(obs)
const secretHits = ['api_key', 'apikey', 'DEEPSEEK', 'credential', 'authorization', 'secret', 'process.env', 'DASH_']
const leaks = secretHits.filter((k) => flat.toLowerCase().includes(k.toLowerCase()))
leaks.length === 0 ? ok('observer payload contains no key/credential/env fields') : bad('payload leak', leaks.join(','))
if (obs.balance) {
  const balanceKeys = Object.keys(obs.balance).sort().join(',')
  balanceKeys === 'available,balance,currency' ? ok('balance proxy returns only whitelisted fields: ' + balanceKeys) : bad('balance fields', balanceKeys)
} else bad('balance missing from observer payload')
// error responses leak no internals
r = await post(base, '/api/dsh-remote/pair', { device_id: 'x', level: 1, code: 'short' })
const errFlat = JSON.stringify(r.body)
!/stack|at /i.test(errFlat) && /^\{[^}]*\}$/.test(errFlat) ? ok('error responses are code-only, no stack traces') : bad('error leak', errFlat)

// ------------------------------------------------------------------ J. credential storage
console.log('== J. credential storage ==')
const sec = JSON.parse(fs.readFileSync(path.join(tmp, 'a-sec.json'), 'utf8'))
const devs = Object.values(sec.devices)
const hashOk = devs.every((d) => /^[0-9a-f]{64}$/.test(d.credential_hash || ''))
hashOk ? ok('security file stores only SHA-256 hashes') : bad('hash format')
const rawLeak = devs.some((d) => d.credential !== undefined)
rawLeak ? bad('raw credential persisted!') : ok('no raw credential in security file')

// ------------------------------------------------------------------ K. port stability across disable/enable
console.log('== K. port stability with an open SSE ==')
const portBefore = a.status().port
const sse2 = await fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + sess2.session_id } })
const sse2Reader = sse2.body.getReader()
const sse2Loop = (async () => { for (;;) { const { done } = await sse2Reader.read(); if (done) return } })()
a.stop()
await sleep(400)
a.start()
await sleep(800)
const portAfter = a.status().port
portAfter === portBefore ? ok(`port stable across disable/enable with open SSE (${portBefore})`) : bad('port changed', `${portBefore} -> ${portAfter}`)
await sse2Loop

// ------------------------------------------------------------------ L. oversized body
console.log('== L. oversized JSON body ==')
const big = 'x'.repeat(1024 * 1024)
let bigStatus = 'no-response'
try {
  const res = await fetch(base + '/api/dsh-remote/pair', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ device_id: 'big-0001', code: 'big-code-0001-000001', level: 1, pad: big }) })
  bigStatus = String(res.status)
} catch { bigStatus = 'connection-destroyed' }
bigStatus !== '200' ? ok(`oversized body rejected (${bigStatus})`) : bad('oversized body accepted', bigStatus)

// ------------------------------------------------------------------ M. cross-instance
console.log('== M. cross-instance (A credential -> B) ==')
const bInst = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts })
bInst.setName('B-PC')
bInst.start()
await sleep(700)
const baseB = `http://127.0.0.1:${bInst.status().port}`
const cross = await post(baseB, '/api/dsh-remote/session', { credential: cred })
cross.status === 401 ? ok("A's credential rejected on B") : bad('cross-instance', String(cross.status))

console.log('== cleanup ==')
a.stop()
bInst.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`AUDIT TEST SUMMARY: ${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
