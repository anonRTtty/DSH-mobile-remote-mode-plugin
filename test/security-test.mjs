// Phase 2 security test — pairing, credentials, sessions, Level-1 observer,
// revoke, cross-instance isolation, broadcast lifecycle, restart persistence.
// Two instances (A, B) with stub host facts, simulated phones as HTTP clients.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-remote-sec-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

const stubFacts = {
  agentStatus: () => ({ available: true, status: 'idle', detail: { live_agents: 1 } }),
  workspaces: () => ({ available: true, count: 1, workspaces: [{ path: 'C:\\proj\\demo', title: 'demo' }] }),
  balance: async () => ({ available: true, balance: '12.34', currency: 'CNY' }),
  system: () => ({ available: true, hostname: 'TEST-PC', platform: 'win32', memory: { used_pct: 42 }, uptime_sec: 3600 }),
}

// ------------------------------------------------------------ phone client
function phone(deviceId, code, base) {
  const json = (url, opts) => fetch(base + url, opts).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))
  return {
    pair(name = 'My Phone', level = 1, c = code) {
      return json('/api/dsh-remote/pair', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ device_id: deviceId, device_name: name, level, code: c }) })
    },
    pairStatus(c = code) {
      return json('/api/dsh-remote/pair/status', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ device_id: deviceId, code: c }) })
    },
    session(credential) {
      return json('/api/dsh-remote/session', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential }) })
    },
    observerStatus(token) {
      return json('/api/dsh-remote/observer/status', { headers: { authorization: 'Bearer ' + token } })
    },
    get(p) {
      return fetch(base + p).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))
    },
  }
}

async function readSse(base, token, onFrame, timeoutMs = 6000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { controller.abort(); reject(new Error('sse timeout')) }, timeoutMs)
    const controller = new AbortController()
    fetch(base + '/api/dsh-remote/observer/events', { headers: { authorization: 'Bearer ' + token }, signal: controller.signal })
      .then(async (res) => {
        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          let sep
          while ((sep = buf.indexOf('\n\n')) >= 0) {
            const frame = buf.slice(0, sep); buf = buf.slice(sep + 2)
            let event = 'message', dataLine = ''
            for (const line of frame.split('\n')) {
              if (line.startsWith('event: ')) event = line.slice(7)
              else if (line.startsWith('data: ')) dataLine += line.slice(6)
            }
            const done2 = onFrame(event, dataLine)
            if (done2) { clearTimeout(timer); controller.abort(); resolve(); return }
          }
        }
        clearTimeout(timer)
        resolve()
      })
      .catch((e) => { clearTimeout(timer); reject(e) })
  })
}

console.log('== setup: instances A and B ==')
const a = createDiscovery({ statePath: path.join(tmp, 'a.json'), securityPath: path.join(tmp, 'a-sec.json'), facts: stubFacts })
const b = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts: stubFacts })
a.setName('Evan-PC')
b.setName('Gaming-PC')
a.start()
await sleep(600)
b.start()
await sleep(600)
const aPort = a.status().port
const bPort = b.status().port
assert.ok(aPort > 0 && bPort > 0 && aPort !== bPort, 'A and B bind different ports')
const baseA = `http://127.0.0.1:${aPort}`
const baseB = `http://127.0.0.1:${bPort}`
const p1 = phone('phone-0001', 'code-0001-0001-0001', baseA)
const p2 = phone('phone-0002', 'code-0002-0002-0002', baseA)
const p3 = phone('phone-0003', 'code-0003-0003-0003', baseA)
const p4 = phone('phone-0004', 'code-0004-0004-0004', baseB)

console.log('== allowlist / permission boundary (Test 6 + §十三) ==')
let r = await p1.get('/api/plugin.remote/status')
assert.equal(r.status, 403, 'main-server route must be 403 on the mobile server'); ok('main-server route 403 on mobile server')
r = await p1.get('/api/dsh-remote/observer/status')
assert.equal(r.status, 401, 'observer without auth -> 401'); ok('observer without auth -> 401')
r = await p1.get('/nope')
assert.equal(r.status, 403, 'unknown path -> 403'); ok('unknown path -> 403')
r = await p1.get('/api/dsh-remote/send_prompt')
assert.equal(r.status, 403, 'future L2 endpoint -> 403'); ok('future L2 endpoint -> 403')
r = await fetch(baseA + '/api/dsh-remote/send_prompt', { method: 'POST' })
assert.equal(r.status, 403, 'future L2 POST -> 403'); ok('future L2 POST -> 403')
r = await p1.get('/health')
assert.equal(r.status, 200, 'health stays public'); ok('health public')
const cors = await fetch(baseA + '/api/dsh-remote/pair', { method: 'OPTIONS' })
assert.equal(cors.status, 204)
assert.equal(cors.headers.get('access-control-allow-origin'), '*'); ok('CORS preflight allowed')

console.log('== bad pairing requests (§十六) ==')
r = await phone('xy', 'code-1111-1111-1111', baseA).pair()
assert.equal(r.status, 400, 'short device_id -> 400'); ok('short device_id -> 400')
r = await p1.pair('My Phone', 2)
assert.equal(r.status, 403, 'level 2 request -> 403 (no self-elevation)'); ok('level 2 -> 403')
r = await p1.pair('My Phone', 1, 'short')
assert.equal(r.status, 400, 'short pairing code -> 400'); ok('short code -> 400')
r = await p1.session('garbage-credential')
assert.equal(r.status, 401, 'garbage credential -> 401'); ok('garbage credential -> 401')
r = await p1.session('')
assert.equal(r.status, 401, 'empty credential -> 401'); ok('empty credential -> 401')

console.log('== Test 1: Pair ==')
r = await p1.pair("Evan's Phone")
assert.equal(r.body.status, 'pending'); ok('pair -> pending')
r = await p1.pairStatus()
assert.equal(r.body.status, 'pending'); ok('pending while awaiting PC approval')
let accepted = a.acceptPair('phone-0001')
assert.equal(accepted.ok, true); ok('PC accepts (server mints credential)')
r = await p1.pairStatus()
assert.equal(r.body.status, 'accepted')
assert.ok(r.body.credential && r.body.credential.length >= 43, '256-bit base64url credential delivered once')
const cred1 = r.body.credential
ok('accepted -> credential delivered with the pairing code')
r = await p1.session(cred1)
assert.equal(r.status, 200)
assert.equal(r.body.session.level, 1)
assert.ok(r.body.session.capabilities.includes('observe_status'))
ok('credential -> Level-1 session')

console.log('== Test 5: observer API 200 ==')
const sid1 = r.body.session.session_id
r = await p1.observerStatus(sid1)
assert.equal(r.status, 200)
assert.equal(r.body.session.device_id, 'phone-0001', 'session device_id is server truth')
assert.equal(r.body.session.instance_id, a.status().instance_id, 'session instance_id is server truth')
assert.equal(r.body.connection.instance_name, 'Evan-PC')
assert.equal(r.body.agent.status, 'idle')
assert.equal(r.body.balance.balance, '12.34')
assert.equal(r.body.system.uptime_sec, 3600)
assert.equal(r.body.current_task.available, false)
ok('observer status returns real facts (connection/agent/balance/system)')

console.log('== auth boundary (Test 5 negative + §十六) ==')
r = await p1.observerStatus('wrong-session-id')
assert.equal(r.status, 401, 'wrong token -> 401'); ok('wrong token -> 401')
r = await p1.observerStatus('')
assert.equal(r.status, 401, 'empty token -> 401'); ok('empty token -> 401')
r = await p1.observerStatus(sid1 + 'x')
assert.equal(r.status, 401, 'tampered token -> 401'); ok('tampered token -> 401')

console.log('== Test 2: Reject ==')
r = await p2.pair('Rejected Phone')
assert.equal(r.body.status, 'pending')
a.rejectPair('phone-0002')
r = await p2.pairStatus()
assert.equal(r.body.status, 'rejected'); ok('rejected phone sees Pairing rejected')
r = await p2.session('whatever')
assert.equal(r.status, 401, 'rejected phone cannot open a session'); ok('rejected phone has no session')

console.log('== Test 8: multiple devices ==')
r = await p3.pair('Third Phone')
a.acceptPair('phone-0003')
r = await p3.pairStatus()
const cred3 = r.body.credential
const s3 = (await p3.session(cred3)).body.session
const pairsA = a.status().pairs
assert.equal(pairsA.paired.length, 2, 'two paired devices on A')
assert.notEqual(pairsA.paired[0].device_id, pairsA.paired[1].device_id)
ok('two devices paired with distinct ids, both Level 1')
r = await p3.observerStatus(s3.session_id)
assert.equal(r.status, 200); ok('second device observer works')

console.log('== Test 9: credentials are per-instance ==')
// The credential IS the identity: presenting cred3 opens phone-0003's session
// (there is no client-claimed device_id/instance_id field to tamper with).
r = await p1.session(cred3)
assert.equal(r.status, 200)
assert.equal(r.body.session.device_id, 'phone-0003', 'credential determines the session device')
ok('credential determines identity; device_id cannot be spoofed via the request')
r = await p1.session(cred3 + 'x')
assert.equal(r.status, 401, 'tampered credential rejected'); ok('tampered credential rejected')
r = await phone('phone-0001', 'code-0001-0001-0001', baseB).session(cred3)
assert.equal(r.status, 401, "A's credential must not open a session on B"); ok('A credential rejected on B (cross-instance)')
r = await p4.pair('B Phone')
b.acceptPair('phone-0004')
const r4 = await p4.pairStatus()
const s4 = (await p4.session(r4.body.credential)).body.session
assert.equal(s4.instance_id, b.status().instance_id, 'B session bound to B instance')
ok('B pairs its own device; sessions bound per instance')

console.log('== Test 4: Revoke ==')
a.revokeDevice('phone-0001')
r = await p1.observerStatus(sid1)
assert.equal(r.status, 401, 'revoked session dies immediately'); ok('revoked session -> 401')
r = await p1.session(cred1)
assert.equal(r.status, 401, 'revoked credential rejected'); ok('revoked credential rejected')
// p1 must re-pair (its credential is gone)
r = await p1.pair("Evan's Phone")
assert.equal(r.body.status, 'pending', 'revoked device can re-pair'); ok('revoked device re-pairs')
a.acceptPair('phone-0001')
const re = await p1.pairStatus()
const cred1b = re.body.credential
const s1b = (await p1.session(cred1b)).body.session
assert.equal(s1b.device_id, 'phone-0001')
ok('re-pair after revoke works')

console.log('== Test 7: broadcast disable invalidates sessions ==')
// open an SSE for phone-0003, then stop A -> 'invalid' frame
const ssePromise = readSse(baseA, s3.session_id, (event) => event === 'invalid', 8000)
await sleep(600) // let the SSE connect
a.stop() // must push 'invalid' to the open stream
await ssePromise
ok('SSE receives invalid on broadcast disable')
assert.equal(a.status().enabled, false)
// old session is gone
const a2 = createDiscovery({ statePath: path.join(tmp, 'a.json'), securityPath: path.join(tmp, 'a-sec.json'), facts: stubFacts })
a2.start()
await sleep(400)
const baseA2 = `http://127.0.0.1:${a2.status().port}`
r = await phone('phone-0003', 'code-0003-0003-0003', baseA2).observerStatus(s3.session_id)
assert.equal(r.status, 401, 'pre-disable session invalid after restart of broadcast'); ok('old session invalid after re-enable')
// same credential still works (no re-pair needed)
const s3b = (await phone('phone-0003', 'code-0003-0003-0003', baseA2).session(cred3)).body.session
assert.equal(s3b.level, 1)
ok('re-enable: same credential re-establishes session without re-pair (§十二)')

console.log('== Test 10: restart persistence ==')
const a3 = createDiscovery({ statePath: path.join(tmp, 'a.json'), securityPath: path.join(tmp, 'a-sec.json'), facts: stubFacts })
assert.equal(a3.status().instance_id, a2.status().instance_id, 'instance_id stable across restart')
const devs = a3.pairList().paired
assert.ok(devs.some((d) => d.device_id === 'phone-0003'), 'paired devices survive restart (not revoked)')
const s3c = a3.createSession(cred3)
assert.equal(s3c.ok, true, 'stored credential still valid after restart'); ok('pairing credential survives DSH restart')

console.log('== cleanup ==')
a2.stop()
b.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`ALL PHASE 2 SECURITY TESTS PASSED (${pass} checks)`)
