// Standalone end-to-end test of dsh-plugin-remote's discovery core.
// Runs two instances (A, B) in ONE process on the same machine and verifies:
//  1. mutual multicast discovery (Test 5 analog)
//  2. HTTP port fallback (A takes 8765, B falls back to 8766)
//  3. mobile page + instances API are served
//  4. TTL: after B stops, A reports B offline (Test 2/3 analog)
//  5. re-enable -> B is discovered again (Test 6 analog)
//  6. instance rename + state persistence (instance_id stable)
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const core = new URL('../src/discovery.mjs', import.meta.url)
const { createDiscovery } = await import(core.href)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-remote-test-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const log = (msg) => console.log(msg)

log('== starting instance A and B ==')
const a = createDiscovery({ statePath: path.join(tmp, 'a.json'), log })
const b = createDiscovery({ statePath: path.join(tmp, 'b.json'), log })
a.setName('Evan-PC')
b.setName('Gaming-PC')
assert.equal(a.status().enabled, false, 'A must start disabled (broadcast OFF by default)')

a.start()
await sleep(600)
assert.equal(a.status().enabled, true)
assert.equal(a.status().port, 8765, 'A should bind the preferred port 8765')

b.start()
await sleep(600)
assert.equal(b.status().port, 8766, 'B should fall back to 8766 when 8765 is taken')

// give heartbeats time to flow both ways (2s interval)
await sleep(3000)

const aView = a.instancesPayload()
const bView = b.instancesPayload()
console.log('A sees:', JSON.stringify(aView.instances.map((i) => i.instance_name + ':' + i.status)))
console.log('B sees:', JSON.stringify(bView.instances.map((i) => i.instance_name + ':' + i.status)))

assert.ok(aView.instances.some((i) => i.self && i.instance_name === 'Evan-PC'), 'A lists itself')
assert.ok(aView.instances.some((i) => !i.self && i.instance_name === 'Gaming-PC' && i.status === 'online'), 'A sees B online (Test 5)')
assert.ok(bView.instances.some((i) => !i.self && i.instance_name === 'Evan-PC' && i.status === 'online'), 'B sees A online')

log('== phone page + API served ==')
const page = await fetch('http://127.0.0.1:8765/')
assert.equal(page.status, 200)
const html = await page.text()
assert.ok(html.includes('DSH Remote'), 'mobile page served with title')
assert.ok(html.includes('Nearby DSH'), 'mobile page has Nearby DSH section')

const api = await fetch('http://127.0.0.1:8766/api/dsh-remote/instances')
const data = await api.json()
assert.equal(data.service, 'dsh-remote')
assert.ok(data.instances.length >= 2, 'instances API lists at least 2 instances')

log('== TTL: stop B, A should mark it offline (Tests 2/3) ==')
b.stop()
await sleep(7500) // > ONLINE_TTL_MS (6s)
const afterStop = a.instancesPayload()
const bEntry = afterStop.instances.find((i) => i.instance_name === 'Gaming-PC')
assert.ok(bEntry, 'B still listed briefly (forget window 30s)')
assert.equal(bEntry.status, 'offline', 'A marks B offline after TTL')

log('== re-enable B -> rediscovered (Test 6) ==')
b.start()
await sleep(3000)
const afterRestart = a.instancesPayload()
assert.ok(
  afterRestart.instances.some((i) => i.instance_name === 'Gaming-PC' && i.status === 'online'),
  'A rediscovers B after re-enable',
)

log('== rename + persistence ==')
a.setName('Renamed-PC')
assert.equal(a.status().instance_name, 'Renamed-PC')
const c = createDiscovery({ statePath: path.join(tmp, 'a.json'), log })
assert.equal(c.status().instance_name, 'Renamed-PC', 'name persisted')
assert.equal(c.status().instance_id, a.status().instance_id, 'instance_id stable across restart')

log('== disable stops everything ==')
const portBefore = a.status().port
a.stop()
assert.equal(a.status().enabled, false)
assert.equal(a.status().port, 0, 'port released after disable')
assert.ok(portBefore > 0)

log('== cleanup ==')
b.stop()
fs.rmSync(tmp, { recursive: true, force: true })
log('ALL TESTS PASSED')
