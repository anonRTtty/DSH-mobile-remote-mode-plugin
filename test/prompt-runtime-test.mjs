// Phase 5.1 — Bug #2 regression: "The agent task failed" must become a
// structured, diagnosable failure. R1-R10 exercise the discovery core with
// controllable stub executors that emulate every failing stage (create,
// followup, turn error, throw, missing executor) and assert:
//   - the task snapshot / SSE terminal frame carry error_code + error_message
//     (+ partial output) — never prompt text, credentials or stacks;
//   - the final audit entry records error_code (diagnostics only);
//   - session binding holds for failed tasks; retry after failure works;
//   - success keeps error_code null.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery, TASK_OUTPUT_MAX } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-prompt-rt-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

const facts = {
  agentStatus: () => ({ available: true, status: 'idle' }),
  workspaces: () => ({ available: true, workspaces: [{ path: 'C:\\proj' }] }),
  balance: async () => ({ available: true, balance: '1.00', currency: 'CNY' }),
  system: () => ({ available: true, hostname: 'P', memory: { used_pct: 1 }, uptime_sec: 1 }),
}

const auditEntries = []
let executorMode = 'ok' // ok | code | throw | slow-fail | big-fail | cap-msg | fail-once
let failOnceUsed = false
const executor = async (payload, emit) => {
  emit.status('running')
  switch (executorMode) {
    case 'code': // stage A-style explicit failure with partial output
      emit.output('partial-1')
      emit.fail('AGENT_CREATE_FAILED', 'failed to create the agent task')
      return
    case 'throw': // executor blows up mid-turn (stage C/D-style)
      emit.output('partial-2')
      throw new Error('simulated runtime explosion')
    case 'slow-fail': // SSE test: running, then a staged failure
      emit.output('partial-sse')
      await sleep(150)
      emit.fail('AGENT_TURN_ERROR', 'agent turn ended with an error')
      return
    case 'big-fail': // output cap + failure
      emit.output('x'.repeat(TASK_OUTPUT_MAX + 4096))
      emit.fail('AGENT_FOLLOWUP_FAILED', 'failed to start the agent turn')
      return
    case 'cap-msg': // error_message truncation
      emit.fail('AGENT_X', 'err '.repeat(200))
      return
    case 'fail-once': // first call fails, later calls succeed
      if (!failOnceUsed) { failOnceUsed = true; emit.fail('AGENT_TURN_ERROR', 'turn failed'); return }
      emit.output('retry-ok')
      emit.status('completed')
      return
    default:
      emit.output('Hello ')
      emit.output('world')
      emit.status('completed')
  }
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

async function pairDevice(d, deviceId, name, baseUrl) {
  const b = baseUrl || base
  const ticket = d.createPairingTicket()
  await post(b, '/api/dsh-remote/pair', { device_id: deviceId, device_name: name, level: 1, code: ticket })
  d.acceptPair(deviceId)
  const pick = await post(b, '/api/dsh-remote/pair/status', { device_id: deviceId, code: ticket })
  const sess = (await post(b, '/api/dsh-remote/session', { credential: pick.body.credential })).body.session
  return { credential: pick.body.credential, session: sess }
}
async function pairLevel2(d, deviceId, name, baseUrl) {
  const p = await pairDevice(d, deviceId, name, baseUrl)
  d.setDeviceLevel(deviceId, 2)
  return p
}
async function sendPromptOk(sid, prompt) {
  const r = await post(base, '/api/dsh-remote/prompt', { prompt }, bearer(sid))
  assert.equal(r.status, 200, `prompt "${prompt}" must be accepted`)
  assert.ok(r.body.ok && r.body.task_id)
  return r.body.task_id
}
async function taskSnapshot(sid, taskId) {
  const st = await jreq(base, `/api/dsh-remote/prompt/status?task_id=${taskId}`, { headers: bearer(sid) })
  assert.equal(st.status, 200)
  return st.body.task
}
async function readSseFrames(url, headers, timeoutMs = 5000) {
  const res = await fetch(url, { headers })
  assert.equal(res.status, 200)
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  const frames = []
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    let sep
    while ((sep = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, sep); buf = buf.slice(sep + 2)
      const ev = { event: 'message', data: '' }
      frame.split('\n').forEach((line) => {
        if (line.startsWith('event: ')) ev.event = line.slice(7)
        else if (line.startsWith('data: ')) ev.data += line.slice(6)
      })
      frames.push(ev)
    }
  }
  return frames
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

const phoneA = await pairLevel2(a, 'phone-r-a', 'Runtime Phone')
const phoneB = await pairLevel2(a, 'phone-r-b', 'Reader Phone')
const sidA = phoneA.session.session_id
const sidB = phoneB.session.session_id

// R1 — explicit staged failure: code + message + partial output in snapshot
console.log('== R1: emit.fail(code) -> snapshot carries code + message + output ==')
executorMode = 'code'
const t1 = await sendPromptOk(sidA, 'r1')
await sleep(120)
let snap = await taskSnapshot(sidA, t1)
assert.equal(snap.status, 'failed')
assert.equal(snap.error_code, 'AGENT_CREATE_FAILED')
assert.equal(snap.error_message, 'failed to create the agent task')
assert.equal(snap.output, 'partial-1')
assert.ok(!('prompt' in snap), 'snapshot must never contain the prompt text')
ok('R1 explicit fail(code) -> failed snapshot with AGENT_CREATE_FAILED + message + partial output')

// R2 — executor throws -> generic AGENT_EXECUTION_FAILED, output kept
console.log('== R2: executor throw -> AGENT_EXECUTION_FAILED ==')
executorMode = 'throw'
const t2 = await sendPromptOk(sidA, 'r2')
await sleep(120)
snap = await taskSnapshot(sidA, t2)
assert.equal(snap.status, 'failed')
assert.equal(snap.error_code, 'AGENT_EXECUTION_FAILED')
assert.equal(snap.error_message, 'agent error')
assert.equal(snap.output, 'partial-2', 'output emitted before the throw must be retained')
ok('R2 thrown executor -> AGENT_EXECUTION_FAILED with partial output retained')

// R3 — no executor configured -> AGENT_EXECUTION_FAILED (executor unavailable)
console.log('== R3: missing executor -> AGENT_EXECUTION_FAILED ==')
const bInst = createDiscovery({ statePath: path.join(tmp, 'b.json'), securityPath: path.join(tmp, 'b-sec.json'), facts })
bInst.setName('Bare-PC')
bInst.start()
await sleep(600)
const baseB = `http://127.0.0.1:${bInst.status().port}`
const phoneBare = await pairLevel2(bInst, 'phone-r-bare', 'Bare Phone', baseB)
const sidBare = phoneBare.session.session_id
const rB = await post(baseB, '/api/dsh-remote/prompt', { prompt: 'r3' }, bearer(sidBare))
assert.equal(rB.status, 200)
await sleep(120)
const stB = await jreq(baseB, `/api/dsh-remote/prompt/status?task_id=${rB.body.task_id}`, { headers: bearer(sidBare) })
assert.equal(stB.body.task.status, 'failed')
assert.equal(stB.body.task.error_code, 'AGENT_EXECUTION_FAILED')
assert.equal(stB.body.task.error_message, 'agent executor unavailable')
ok('R3 no executor -> AGENT_EXECUTION_FAILED (executor unavailable)')

// R4 — output cap still enforced on the failure path
console.log('== R4: output cap on failure path ==')
executorMode = 'big-fail'
const t4 = await sendPromptOk(sidA, 'r4')
await sleep(120)
snap = await taskSnapshot(sidA, t4)
assert.equal(snap.status, 'failed')
assert.equal(snap.error_code, 'AGENT_FOLLOWUP_FAILED')
assert.equal(snap.output.length, TASK_OUTPUT_MAX, 'output must be capped at TASK_OUTPUT_MAX')
ok('R4 output capped at TASK_OUTPUT_MAX on failure path')

// R5 — failed task SSE: terminal frame carries error_code + partial output and closes
console.log('== R5: failed task SSE -> terminal frame with code + output ==')
executorMode = 'slow-fail'
const t5 = await sendPromptOk(sidA, 'r5')
const frames = await readSseFrames(base + `/api/dsh-remote/prompt/events?task_id=${t5}`, bearer(sidA))
const last = frames[frames.length - 1]
assert.equal(last.event, 'task')
const lastData = JSON.parse(last.data)
assert.equal(lastData.status, 'failed')
assert.equal(lastData.error_code, 'AGENT_TURN_ERROR')
assert.equal(lastData.error_message, 'agent turn ended with an error')
assert.equal(lastData.output, 'partial-sse')
assert.ok(!('prompt' in lastData), 'SSE frame must never contain the prompt')
ok('R5 failed SSE terminal frame carries error_code + message + partial output, then closes')

// R6 — failed-task audit records error_code; never prompt/credential
console.log('== R6: audit records error_code on failure only ==')
const failedAudits = auditEntries.filter((e) => e.status === 'failed')
assert.ok(failedAudits.length >= 4, 'expected failed audits for R1/R2/R4/R5')
assert.ok(failedAudits.every((e) => typeof e.error_code === 'string' && e.error_code.length > 0), 'failed audits must carry error_code')
assert.ok(auditEntries.every((e) => e.prompt === undefined && e.credential === undefined), 'audit must never contain prompt/credential')
assert.ok(auditEntries.every((e) => typeof e.ts === 'number' && typeof e.task_id === 'string' && typeof e.prompt_len === 'number'), 'audit fields are metadata only')
ok(`R6 ${failedAudits.length} failed audits carry error_code; no prompt/credential/stack anywhere`)

// R7 — completed task: error_code null in snapshot AND audit
console.log('== R7: completed task keeps error_code null ==')
executorMode = 'ok'
const t7 = await sendPromptOk(sidA, 'r7')
await sleep(120)
snap = await taskSnapshot(sidA, t7)
assert.equal(snap.status, 'completed')
assert.equal(snap.error_code, null)
assert.equal(snap.output, 'Hello world')
const completedAudit = auditEntries.find((e) => e.task_id === t7 && e.status === 'completed')
assert.ok(completedAudit, 'completed audit entry must exist')
assert.equal(completedAudit.error_code, null)
ok('R7 completed snapshot + audit keep error_code null')

// R8 — session binding holds for FAILED tasks (cross-device read/SSE -> 404)
console.log('== R8: failed task is still device-private ==')
const r8 = await jreq(base, `/api/dsh-remote/prompt/status?task_id=${t5}`, { headers: bearer(sidB) })
assert.equal(r8.status, 404)
assert.equal(r8.body.code, 'task-not-found')
const r8s = await fetch(base + `/api/dsh-remote/prompt/events?task_id=${t5}`, { headers: bearer(sidB) })
assert.equal(r8s.status, 404)
ok('R8 other device reading/streaming a FAILED task -> 404')

// R9 — retry after failure is accepted and completes (no poisoned state)
console.log('== R9: retry after failure works ==')
executorMode = 'fail-once'
const t9a = await sendPromptOk(sidA, 'retry me')
await sleep(120)
snap = await taskSnapshot(sidA, t9a)
assert.equal(snap.status, 'failed')
const t9b = await sendPromptOk(sidA, 'retry me')
await sleep(120)
snap = await taskSnapshot(sidA, t9b)
assert.equal(snap.status, 'completed')
assert.equal(snap.error_code, null)
assert.equal(snap.output, 'retry-ok')
ok('R9 failed task followed by a retry completes with fresh output')

// R10 — error_message capped at 500 chars; snapshot has no prompt/stack
console.log('== R10: error_message cap + no prompt/stack leakage ==')
executorMode = 'cap-msg'
const t10 = await sendPromptOk(sidA, 'r10 secret-prompt-token-xyz')
await sleep(120)
snap = await taskSnapshot(sidA, t10)
assert.equal(snap.status, 'failed')
assert.ok(snap.error_message.length <= 500, 'error_message must be truncated to 500 chars')
assert.equal(snap.error_message.length, 500)
assert.ok(!snap.error_message.includes('secret-prompt-token-xyz'), 'error_message must never echo the prompt')
assert.ok(!snap.error_message.includes('at '), 'error_message must never leak stack frames')
assert.ok(!('prompt' in snap) && !('credential' in snap), 'snapshot must never contain prompt or credential')
ok('R10 error_message capped at 500 chars; no prompt/credential/stack leakage')

console.log('== cleanup ==')
a.stop()
bInst.stop()
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`PROMPT RUNTIME TESTS PASSED (${pass} checks)`)
