// Phase 5.1 — Bug #1 regression: the phone prompt textarea must never be
// rebuilt by background observer/prompt frames (that stole focus and retracted
// the keyboard). U1-U5 are structural checks on the mobile page source; U6-U7
// execute the real page script in a VM with a minimal DOM shim and verify the
// live invariants: the textarea node is created once, cached, and survives
// observer + task frames; failures render "Code: <code>" + Retry + partial
// output without touching the input.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

const htmlPath = new URL('../src/mobile.html', import.meta.url)
const html = fs.readFileSync(htmlPath, 'utf8')
const m = /<script>([\s\S]*?)<\/script>/.exec(html)
assert.ok(m, 'mobile.html must contain an inline <script>')
const js = m[1]

let pass = 0
const ok = (name) => { pass++; console.log('  PASS', name) }

// ------------------------------------------------------- source extraction
function extractFunction(src, name) {
  const re = new RegExp('function\\s+' + name + '\\s*\\([^)]*\\)\\s*\\{')
  const start = re.exec(src)
  assert.ok(start, `function ${name} must exist`)
  let i = start.index + start[0].length - 1 // index of '{'
  let depth = 0
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++
    else if (src[i] === '}') {
      depth--
      if (depth === 0) return src.slice(start.index, i + 1)
    }
  }
  assert.fail(`function ${name} has unbalanced braces`)
}

// U1 — no focus/blur hacks, no innerHTML anywhere (output is textContent only)
console.log('== U1: no focus-stealing hacks / no innerHTML ==')
assert.ok(!/\.focus\(/.test(js), 'script must not call .focus()')
assert.ok(!/\.blur\(/.test(js), 'script must not call .blur()')
assert.ok(!/innerHTML/.test(js), 'script must never use innerHTML')
ok('U1 no .focus()/.blur() hacks and no innerHTML in mobile page')

// U2 — observer refresh paths update in place; they never full-render
console.log('== U2: observer SSE/poll never full-render ==')
const fallback = extractFunction(js, 'startFallbackPoll')
assert.ok(fallback.includes('updateObserverLive()'), 'fallback poll must update in place')
assert.ok(!fallback.includes('render()'), 'fallback poll must never call render()')
const startLive = extractFunction(js, 'startLive')
assert.ok(startLive.includes('updateObserverLive()'), 'observer SSE must update in place')
assert.ok(!startLive.includes('render()'), 'observer SSE must never call render()')
const pollDiscovery = extractFunction(js, 'pollDiscovery')
assert.ok(pollDiscovery.includes('state.view === "discovery"'), 'discovery poll must guard the view')
ok('U2 observer SSE + fallback poll use updateObserverLive() and never render()')

// U3 — the textarea is created once and cached; updaters never rebuild it
console.log('== U3: textarea created once, cached, never rebuilt ==')
const composer = extractFunction(js, 'renderPromptComposer')
assert.ok(composer.includes('p.taEl = ta'), 'composer must cache the textarea in state.prompt.taEl')
assert.ok(composer.includes('p.wrapEl = wrap') && composer.includes('p.dynamicEl = dyn'), 'composer must cache wrap + dynamic region')
const updater = extractFunction(js, 'updatePromptComposer')
assert.ok(!updater.includes('el("textarea"'), 'updatePromptComposer must never create a textarea')
assert.ok(!updater.includes('render('), 'updatePromptComposer must never full-render')
const obsUpdater = extractFunction(js, 'updateObserverLive')
assert.ok(!obsUpdater.includes('el("textarea"'), 'updateObserverLive must never create a textarea')
assert.ok(!obsUpdater.includes('render('), 'updateObserverLive must never full-render')
ok('U3 textarea cached (state.prompt.taEl); updaters never rebuild it')

// U4 — structured failure UI: Code + Retry + partial response, safe text
console.log('== U4: structured error UI (Code + Retry + partial) ==')
assert.ok(updater.includes('"Code: " + p.errorCode'), 'failure UI must show "Code: <code>"')
assert.ok(updater.includes('"Retry"'), 'failure UI must offer a Retry button')
assert.ok(updater.includes('sendPrompt()'), 'Retry must re-send via sendPrompt()')
assert.ok(updater.includes('el("pre", "prompt-output")') && updater.includes('out.textContent = p.output'), 'partial response rendered as textContent pre')
assert.ok(updater.includes('document.createTextNode(label)'), 'error text must be a plain text node (XSS-safe)')
ok('U4 failure card shows Code + Retry + partial response, rendered as text')

// U5 — failed SSE frame maps error_code; recovery poll exists; success clears ta
console.log('== U5: error-code plumbing + drop recovery ==')
const sse = extractFunction(js, 'startPromptSse')
assert.ok(sse.includes('payload.error_code || "AGENT_EXECUTION_FAILED"'), 'SSE failed frame must surface error_code with fallback')
assert.ok(sse.includes('payload.error_message'), 'SSE failed frame must surface error_message')
assert.ok(js.includes('function refreshPromptStatus'), 'SSE-drop recovery poll must exist')
const send = extractFunction(js, 'sendPrompt')
assert.ok(send.includes('cur.trim() === text'), 'success path clears the textarea only when it still holds the submitted text')
assert.ok(send.includes('updatePromptComposer()'), 'sendPrompt must refresh the composer in place, never render()')
ok('U5 failed frames carry error_code; recovery poll + safe clear-on-success wired')

// ------------------------------------------------ VM + minimal DOM shim
const viewRoot = makeRootNode()
const win = { __DSH_REMOTE__: undefined }

function textNode(text) {
  return { _isText: true, textContent: text, parentNode: null, children: null }
}
function makeNode(tag) {
  const node = {
    tagName: String(tag || 'div'),
    className: '',
    value: '',
    rows: 0,
    placeholder: '',
    disabled: false,
    type: '',
    children: [],
    parentNode: null,
    dataset: {},
    listeners: {},
    appendChild(child) {
      child.parentNode = this
      this.children.push(child)
      return child
    },
    removeChild(child) {
      const i = this.children.indexOf(child)
      if (i >= 0) this.children.splice(i, 1)
      child.parentNode = null
      return child
    },
    insertBefore(child, ref) {
      child.parentNode = this
      const i = ref ? this.children.indexOf(ref) : -1
      if (i >= 0) this.children.splice(i, 0, child)
      else this.children.push(child)
      return child
    },
    addEventListener(type, fn) {
      ;(this.listeners[type] = this.listeners[type] || []).push(fn)
    },
    querySelector(sel) {
      const m = /^\[([a-z-]+)(?:="([^"]*)")?\]$/.exec(sel)
      assert.ok(m, `unsupported selector ${sel}`)
      const attr = m[1].startsWith('data-') ? m[1].slice(5) : m[1] // data-okey -> dataset.okey
      const walk = (node) => {
        for (const c of node.children || []) {
          if (c._isText) continue
          if (m[2] === undefined ? c.dataset[attr] !== undefined : c.dataset[attr] === m[2]) return c
          const hit = walk(c)
          if (hit) return hit
        }
        return null
      }
      return walk(this)
    },
  }
  Object.defineProperty(node, 'firstChild', {
    get() { return this.children[0] || null },
  })
  Object.defineProperty(node, 'textContent', {
    get() {
      return this.children.map((c) => (c._isText ? c.textContent : c.textContent)).join('')
    },
    set(v) {
      this.children = []
      this.appendChild(textNode(String(v)))
    },
  })
  return node
}
function makeRootNode() {
  const root = makeNode('div')
  return root
}

// localStorage + fetch + timer shims
const storage = new Map()
const intervals = new Map()
let timerSeq = 1
let fetchRoutes = []
const fetchCalls = []

const documentShim = {
  getElementById(id) {
    if (id === 'view') return viewRoot
    return null
  },
  createElement: (tag) => makeNode(tag),
  createTextNode: (t) => textNode(t),
}

const fetchStub = async (url, opts) => {
  const u = String(url)
  fetchCalls.push({ url: u, opts })
  for (const [sub, make, exact] of fetchRoutes) {
    if (exact ? u === sub : u.includes(sub)) return make(u, opts)
  }
  return { ok: false, status: 404, json: async () => ({}) }
}

const context = vm.createContext({
  console,
  window: win,
  document: documentShim,
  location: { search: '', hostname: '127.0.0.1', port: '3080' },
  localStorage: {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => storage.set(k, String(v)),
  },
  crypto: globalThis.crypto,
  URLSearchParams: globalThis.URLSearchParams,
  fetch: fetchStub,
  setInterval: (fn, ms) => { const id = timerSeq++; intervals.set(id, fn); return id },
  clearInterval: (id) => { intervals.delete(id) },
  setTimeout: (fn, ms) => { const id = timerSeq++; intervals.set(id, fn); return id },
  clearTimeout: (id) => { intervals.delete(id) },
  TextDecoder: globalThis.TextDecoder,
  TextEncoder: globalThis.TextEncoder,
  Response: globalThis.Response,
  ReadableStream: globalThis.ReadableStream,
})

vm.runInContext(js, context, { filename: 'mobile.html' })
const app = win.__DSH_REMOTE__
assert.ok(app, 'test hook window.__DSH_REMOTE__ must be exposed')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const obsData = {
  session: { session_id: 'session-ui-1', capabilities: ['observe_status', 'observe_balance', 'observe_task', 'observe_system', 'send_prompt'] },
  connection: { instance_name: 'Evan-PC', status: 'online' },
  agent: { available: true, status: 'idle' },
  project: { available: true, workspaces: [{ path: 'C:\\proj' }] },
  balance: { available: true, balance: '1.00', currency: 'CNY' },
  system: { available: true, memory: { used_pct: 12 }, uptime_sec: 3600 },
}

// U6 — observer frames (SSE/poll path) must keep the SAME textarea node,
// value, and attachment while the user is typing.
console.log('== U6: textarea survives observer refresh frames ==')
app.state.view = 'observer'
app.state.target = { instance_id: 'i1', instance_name: 'Evan-PC', ip: '127.0.0.1', port: '3080', status: 'online' }
app.state.obs.session = { session_id: 'session-ui-1' }
app.state.obs.data = obsData
app.render()
const box1 = app.state.obs.rootEl
const wrap1 = app.state.prompt.wrapEl
const ta1 = app.state.prompt.taEl
assert.ok(box1 && wrap1 && ta1, 'observer view must build + cache root, wrap and textarea')
const typed = 'This is a 100+ character prompt being typed on the phone keyboard without losing focus mid-typing. '.repeat(2)
ta1.value = typed
app.state.prompt.text = typed
// 10 simulated observer status frames + a prompt task frame, as background work
for (let i = 0; i < 10; i++) app.updateObserverLive()
app.updatePromptComposer()
assert.equal(app.state.obs.rootEl, box1, 'observer container must not be rebuilt')
assert.equal(app.state.prompt.wrapEl, wrap1, 'prompt card must not be rebuilt')
assert.equal(app.state.prompt.taEl, ta1, 'textarea node must be the same object')
assert.equal(ta1.parentNode, wrap1, 'textarea must still be attached to the card')
assert.equal(ta1.value, typed, 'typed content must be preserved')
// an online status frame also updates the row values in place
assert.ok(viewRoot.querySelector('[data-okey="instance"]').textContent.includes('Evan-PC'))
ok('U6 10 observer frames + task frame: same textarea node, still attached, content preserved')

// U7 — failed task frame: Code + Retry + partial response, input untouched;
// then Retry re-sends and completes. Exercises the REAL SSE frame parser.
console.log('== U7: failed task frame -> Code + Retry + partial; Retry completes ==')
let sseController1
const stream1 = new ReadableStream({ start(c) { sseController1 = c } })
fetchRoutes.unshift(['/prompt/events', () => new Response(stream1, { status: 200, headers: { 'content-type': 'text/event-stream' } })])
fetchRoutes.unshift(['http://127.0.0.1:3080/api/dsh-remote/prompt', () => ({ ok: true, status: 200, json: async () => ({ ok: true, task_id: 'task-2' }) }), true])
const enc = new TextEncoder()
const frame = (status, extra) =>
  enc.encode('event: task\ndata: ' + JSON.stringify(Object.assign({ task_id: 'task-1', status, output: '' }, extra)) + '\n\n')

app.state.prompt.text = 'hello agent'
app.state.prompt.taEl.value = 'hello agent'
app.startPromptSse('task-1')
sseController1.enqueue(frame('running', { output: 'partial…' }))
sseController1.enqueue(frame('failed', { output: 'partial…', error_code: 'AGENT_CREATE_FAILED', error_message: 'failed to create the agent task' }))
await sleep(120)
assert.equal(app.state.prompt.errorCode, 'AGENT_CREATE_FAILED', 'error_code must surface from the frame')
const dynText = app.state.prompt.dynamicEl.textContent
assert.ok(dynText.includes('Code: AGENT_CREATE_FAILED'), 'UI must show Code: AGENT_CREATE_FAILED')
assert.ok(dynText.includes('Retry'), 'UI must offer Retry')
assert.ok(dynText.includes('partial…'), 'partial response must be shown')
assert.equal(app.state.prompt.taEl, ta1, 'textarea node must survive the failed frame')
assert.equal(app.state.prompt.taEl.value, 'hello agent', 'typed text must survive the failed frame')

// click Retry (bound to sendPrompt) -> new task -> completed
function findNode(node, pred) {
  for (const c of node.children || []) {
    if (c._isText) continue
    if (pred(c)) return c
    const hit = findNode(c, pred)
    if (hit) return hit
  }
  return null
}
const retryBtn = findNode(app.state.prompt.dynamicEl, (c) => c.tagName === 'button' && c.textContent === 'Retry')
assert.ok(retryBtn, 'Retry button must be present in the dynamic region')
let sseController2
const stream2 = new ReadableStream({ start(c) { sseController2 = c } })
fetchRoutes.unshift(['/prompt/events', () => new Response(stream2, { status: 200, headers: { 'content-type': 'text/event-stream' } })])
retryBtn.listeners.click[0]()
await sleep(60)
assert.equal(app.state.prompt.status, 'queued', 'Retry must re-submit and queue a new task')
assert.ok(fetchCalls.some((c) => c.url.includes('/api/dsh-remote/prompt') && c.opts && c.opts.method === 'POST'), 'Retry must POST a new prompt')
sseController2.enqueue(enc.encode('event: task\ndata: ' + JSON.stringify({ task_id: 'task-2', status: 'completed', output: 'retry-ok' }) + '\n\n'))
await sleep(120)
assert.equal(app.state.prompt.status, 'completed', 'retried task must complete')
assert.equal(app.state.prompt.errorCode, null, 'error state must clear after retry success')
assert.ok(app.state.prompt.dynamicEl.textContent.includes('retry-ok'), 'retry output must render')
assert.ok(app.state.prompt.dynamicEl.textContent.includes('🟢 Completed'), 'completed banner must render')
assert.equal(app.state.prompt.taEl, ta1, 'textarea node must still be the same after retry')
ok('U7 failed frame -> Code + Retry + partial; Retry re-sends and completes, textarea preserved')

for (const id of intervals.keys()) { /* stub timers hold no event-loop refs */ }
console.log(`PROMPT UI TESTS PASSED (${pass} checks)`)
