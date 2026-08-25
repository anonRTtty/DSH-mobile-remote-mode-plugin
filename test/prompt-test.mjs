// Phase 5 — Level 2 Remote Prompt: AUTH-01..12 + lifecycle tests.
// Uses a controllable stub prompt executor; runs against throwaway instances.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-prompt-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

const facts = {
  agentStatus: () => ({ available: true, status: 'idle' }),
  workspaces: () => ({ available: true, workspaces: [{ path: 'C:\\proj' }] }),
  balance: async () => ({ available: true, balance: '1.00', currency: 'CNY' }),
  system: () => ({ available: true, hostname: 'P', memory: { used_pct: 1 }, uptime_sec: 1 }),
}

// controllable stub executor + audit sink
const executorCalls = []
const auditEntries = []
let executorMode = 'ok' // ok | fail | slow
const executor = async (payload, emit) => {
  executorCalls.push({ ...payload })
  if (executorMode === 'fail') {
    emit.status('running')
    emit.fail('agent-error', 'boom')
    return
  }
  if (executorMode === 'slow') {
    emit.status('running')
    await sleep(400)
    emit.output('slow-out')
    emit.status('completed')
    return
  }
  emit.status('running')
  emit.output('Hello ')
  emit.output('world')
  emit.status('completed')
}

async function jreq(base, url, opts = {}) {
  const res = await fetch(base + url, opts)
  let body = null
  try { body = await res.json() } catch { /* non-json */ }
  return { status: res.status, body }
}
const post = (base, url, payload, headers) => jreq(base, url, {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json', ...(headers || {}) },
  body: JSON.stringify(payload),
})
const bearer = (sid) => ({ authorization: 'Bearer ' + sid })

async function pairDevice(d, deviceId, name) {
  const ticket = d.createPairingTicket()
  await post(base, '/api/dsh-remote/pair', { device_id: deviceId, device_name: name, level: 1, code: ticket })
  d.acceptPair(deviceId)
  const pick = await post(base, '/api/dsh-remote/pair/status', { device_id: deviceId, code: ticket })
  const sess = (await post(base, '/api/dsh-remote/session', { credential: pick.body.credential })).body.session
  return { credential: pick.body.credential, session: sess }
}

console.log('== setup ==')
const a = createDiscovery({
  statePath: path.join(tmp, 'a.json'),
  securityPath: path.join(tmp, 'a-sec.json'),
  facts,
  promptExecutor: executor,
  onAudit: (e) => auditEntries.push(e),
})
a.setName('Evan-PC')
a.start()
await sleep(700)
const base = `http://127.0.0.1:${a.status().port}`

const phoneA = await pairDevice(a, 'phone-a-0001', "Evan's Phone")
const phoneB = await pairDevice(a, 'phone-b-0001', 'Evan Tablet')
// default is Level 1; upgrade only phone A via the PC-side control
a.setDeviceLevel('phone-a-0001', 2)
const sessA = { ...phoneA.session, level: 2, capabilities: ['observe_status', 'observe_balance', 'observe_task', 'observe_system', 'send_prompt'] }
const sidA = phoneA.session.session_id
const sidB = phoneB.session.session_id

// AUTH-01 — Level 1 session cannot prompt
console.log('== AUTH-01: Level 1 -> 403 ==')
let r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi' }, bearer(sidB))
assert.equal(r.status, 403)
assert.equal(r.body.code, 'insufficient-capability')
ok('AUTH-01 Level 1 session -> 403 insufficient-capability')

// AUTH-02 — forged level in body
console.log('== AUTH-02: forged level:2 -> 403 ==')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi', level: 2 }, bearer(sidB))
assert.equal(r.status, 403)
ok('AUTH-02 forged level in body ignored -> 403')

// AUTH-03 — forged capabilities
console.log('== AUTH-03: forged capabilities -> 403 ==')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi', capabilities: ['send_prompt'] }, bearer(sidB))
assert.equal(r.status, 403)
ok('AUTH-03 forged capabilities ignored -> 403')

// AUTH-04 — wrong / absent session
console.log('== AUTH-04: bad session -> 401 ==')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi' }, bearer('wrong-session'))
assert.equal(r.status, 401)
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi' })
assert.equal(r.status, 401)
ok('AUTH-04 wrong/absent session -> 401')

// happy path: A sends a prompt, task completes with output
console.log('== Level 2 happy path ==')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'analyze the project' }, bearer(sidA))
assert.equal(r.status, 200)
assert.ok(r.body.ok && r.body.task_id)
const taskId = r.body.task_id
await sleep(120) // let the stub executor finish
let st = await jreq(base, `/api/dsh-remote/prompt/status?task_id=${taskId}`, { headers: bearer(sidA) })
assert.equal(st.status, 200)
assert.equal(st.body.task.status, 'completed')
assert.equal(st.body.task.output, 'Hello world')
assert.equal(st.body.task.instance_id, a.status().instance_id)
assert.equal(st.body.task.device_id, 'phone-a-0001')
ok('L2 prompt -> task -> completed with output (bound to instance+device)')

// AUTH-05 — device B reads device A's task
console.log('== AUTH-05: cross-device task read -> 404 ==')
r = await jreq(base, `/api/dsh-remote/prompt/status?task_id=${taskId}`, { headers: bearer(sidB) })
assert.equal(r.status, 404)
assert.equal(r.body.code, 'task-not-found')
ok('AUTH-05 B reading A task -> 404')

// AUTH-12 — device B opens A's task SSE -> 404
console.log('== AUTH-12: cross-device task SSE -> 404 ==')
r = await fetch(base + `/api/dsh-remote/prompt/events?task_id=${taskId}`, { headers: bearer(sidB) })
assert.equal(r.status, 404)
ok('AUTH-12 B SSE on A task -> 404')

// AUTH-09 — oversized prompt
console.log('== AUTH-09: oversized prompt -> 413 ==')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'x'.repeat(9000) }, bearer(sidA))
assert.equal(r.status, 413)
assert.equal(r.body.code, 'prompt-too-large')
ok('AUTH-09 prompt > 8 KB -> 413')

// AUTH-08 — concurrency cap
console.log('== AUTH-08: active prompt cap -> 429 ==')
executorMode = 'slow'
for (let i = 0; i < 3; i++) {
  r = await post(base, '/api/dsh-remote/prompt', { prompt: `task ${i}` }, bearer(sidA))
  assert.equal(r.status, 200)
}
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'overflow' }, bearer(sidA))
assert.equal(r.status, 429)
assert.equal(r.body.code, 'prompt-limit')
ok('AUTH-08 4th concurrent prompt -> 429 prompt-limit')
await sleep(700) // slow tasks finish
executorMode = 'ok'

// AUTH-07 — per-device rate limit
console.log('== AUTH-07: prompt rate limit -> 429 ==')
// 3 slow + previous happy-path prompts already consumed part of the window
let limited = null
let sent = 0
for (let i = 0; i < 12; i++) {
  r = await post(base, '/api/dsh-remote/prompt', { prompt: `rate ${i}` }, bearer(sidA))
  if (r.status === 429) { limited = r; break }
  sent++
}
assert.ok(limited, 'expected a 429 after the per-device window is exhausted')
assert.equal(limited.body.code, 'prompt-rate-limit')
ok(`AUTH-07 per-device rate limit -> 429 (after ${sent} accepted)`)

// AUTH-10 — cross-instance
console.log('== AUTH-10: A credential -> B prompt -> 401 ==')
const bInst = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts, promptExecutor: executor })
bInst.setName('Gaming-PC')
bInst.start()
await sleep(600)
const baseB = `http://127.0.0.1:${bInst.status().port}`
r = await post(baseB, '/api/dsh-remote/prompt', { prompt: 'hi' }, bearer(sidA))
assert.equal(r.status, 401)
ok('AUTH-10 A session on B -> 401 (cross-instance isolation)')

// AUTH-11 — shell-like prompt is data, never executed by the API
console.log('== AUTH-11: prompt is data, no shell endpoints ==')
// fresh device so the AUTH-07 rate window doesn't interfere
const phoneD = await pairDevice(a, 'phone-d-0001', 'Prompt Phone')
a.setDeviceLevel('phone-d-0001', 2)
const sidD = phoneD.session.session_id
executorCalls.length = 0
const evilPrompt = 'list /etc/passwd; run $(whoami) & calc.exe'
r = await post(base, '/api/dsh-remote/prompt', { prompt: evilPrompt }, bearer(sidD))
assert.equal(r.status, 200)
await sleep(120)
const evilTask = executorCalls[executorCalls.length - 1]
assert.equal(evilTask.prompt, evilPrompt, 'executor received the prompt verbatim as data')
for (const path of ['/api/dsh-remote/exec', '/api/dsh-remote/shell', '/api/dsh-remote/powershell', '/api/dsh-remote/cmd', '/api/dsh-remote/run']) {
  const rr = await jreq(base, path, { method: 'POST', headers: bearer(sidD), body: '{}' })
  assert.equal(rr.status, 403, path + ' must not exist')
}
ok('AUTH-11 prompt treated as data; exec/shell/cmd endpoints do not exist (403)')

// AUTH-06 — revoke kills the session
console.log('== AUTH-06: revoke -> 401 ==')
a.revokeDevice('phone-a-0001')
r = await post(base, '/api/dsh-remote/prompt', { prompt: 'hi' }, bearer(sidA))
assert.equal(r.status, 401)
r = await jreq(base, `/api/dsh-remote/prompt/status?task_id=${taskId}`, { headers: bearer(sidA) })
assert.equal(r.status, 401)
ok('AUTH-06 revoke -> old session 401 on prompt + task status')

// lifecycle + audit
console.log('== lifecycle + audit ==')
assert.ok(auditEntries.length > 0)
const auditOk = auditEntries.every((e) =>
  typeof e.ts === 'number' && typeof e.device_id === 'string' && typeof e.task_id === 'string' &&
  typeof e.prompt_len === 'number' && ['queued', 'running', 'completed', 'failed'].includes(e.status) &&
  e.prompt === undefined && e.credential === undefined
)
assert.ok(auditOk, 'audit entries carry metadata only, never prompt/credential')
ok(`audit trail minimal (${auditEntries.length} entries, no prompt/credential)`)

// default level stays 1 after pairing; setDeviceLevel enforces 1|2 only
console.log('== level controls ==')
const fresh = await pairDevice(a, 'phone-c-0001', 'Fresh Phone')
assert.equal(fresh.session.level, 1, 'new pairings default to Level 1')
const bad = a.setDeviceLevel('phone-c-0001', 3)
assert.equal(bad.ok, false)
const miss = a.setDeviceLevel('no-such-device', 2)
assert.equal(miss.ok, false)
a.setDeviceLevel('phone-c-0001', 2)
assert.equal(a.pairList().paired.find((p) => p.device_id === 'phone-c-0001').level, 2)
ok('new pairings default Level 1; setDeviceLevel only accepts 1/2')

console.log('== cleanup ==')
a.stop()
bInst.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`PROMPT TESTS PASSED (${pass} checks)`)
