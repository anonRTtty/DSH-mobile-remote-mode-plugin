// dsh-plugin-remote — discovery protocol core (no Cordis dependencies).
//
// Phase 1 — LAN discovery:
//   UDP multicast heartbeat on 239.255.76.65:48765 every 2 s; neighbor table
//   with ONLINE (6 s TTL) / forgotten (30 s); a mobile HTTP server on 0.0.0.0
//   (8765 + fallbacks) serving the phone page and the instances JSON.
//
// Phase 2 — secure pairing + Level 1 Observer:
//   pairing (PC approval, 256-bit credential picked once with the pairing
//   code), credential-hash sessions, capability table, SSE, explicit
//   allowlist.
//
// Phase 3 — security hardening (Phase 2.5 audit blockers):
//   F-01  duplicate pair -> 409; pending entries immutable; one-shot code;
//         pickup deadline after accept; accept/reject delete pending.
//   F-02  per-IP rate limit on POST /pair; pending Map hard cap (429);
//         64 KB body cap on every JSON POST; Content-Type 415.
//   F-03  max 5 sessions per device (429); max 2 SSE per session (429);
//         24 h idle session expiry with real deletion + SSE close.
//   F-04  shared balance cache (15 s) + single-flight; SSE pushes skip when
//         the previous payload is still in flight; failures -> Unavailable.
//   F-05  Origin allowlist on POST /pair (own origins + discovered instances);
//         non-browser (no Origin) falls back to allow.
//   F-06  re-pair never refreshes created_at/expires_at (TTL from first).
//   F-08  TLS is deliberately NOT implemented here — see README (BLOCKED).
//
// Phase 4 — QR pairing + authentication refactor:
//   - one-time pairing tickets (256-bit, 60 s TTL, single use, hashed at
//     rest, cleared on stop/restart); the phone scans a QR containing only
//     the ticket + host/port and pairing still requires PC-side Accept;
//   - the pairing claim value (legacy phone code OR QR ticket) is stored only
//     as SHA-256 (`claim_hash`) — no plaintext claim is ever persisted;
//   - capability model moved to a LEVELS table with Level 2/3 DEFINED but
//     NOT enabled; device records carry server-derived `capabilities`.
//
// Discovery remains UNTRUSTED INPUT: it is never used for authentication.

import dgram from 'node:dgram'
import http from 'node:http'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'

export const MULTICAST_GROUP = '239.255.76.65'
export const MULTICAST_PORT = 48765
export const HEARTBEAT_MS = 2000
export const ONLINE_TTL_MS = 6000 // 3 missed heartbeats -> offline
export const FORGET_MS = 30000 // drop unseen instances after 30s
export const HTTP_BASE_PORT = 8765
export const HTTP_MAX_TRIES = 10
export const PAIR_TTL_MS = 300000 // pending pairing request lifetime (from first request)
export const REJECT_TTL_MS = 300000 // how long "rejected" is reported
export const PICKUP_TTL_MS = 300000 // credential pickup deadline after accept
export const SSE_PUSH_MS = 2000
export const PAIR_RATE_WINDOW_MS = 60000 // per-IP window for /pair
export const PAIR_RATE_MAX = 120 // max /pair requests per IP per window
export const MAX_PENDING = 100 // pending pairing request hard cap
export const MAX_SESSIONS_PER_DEVICE = 5
export const MAX_SSE_PER_SESSION = 2
export const SESSION_IDLE_MS = 24 * 60 * 60 * 1000
export const SESSION_PRUNE_MS = 5 * 60 * 1000
export const BALANCE_CACHE_MS = 15000
export const TICKET_TTL_MS = 60000 // QR pairing ticket lifetime (60 s)
export const PROMPT_MAX_LENGTH = 8192 // max prompt chars
export const PROMPT_RATE_WINDOW_MS = 60000 // per-device prompt window
export const PROMPT_RATE_MAX = 10 // max prompts per device per window
export const MAX_ACTIVE_PROMPTS = 3 // concurrent queued/running remote prompts
export const TASK_RETENTION_MS = 10 * 60 * 1000 // terminal task retention
export const TASK_OUTPUT_MAX = 512 * 1024 // per-task output cap (chars)

export const DEFAULT_STATE_PATH = path.join(
  process.env.DSH_HOME || path.join(os.homedir(), '.dsh'),
  'plugin-remote.json',
)
export const DEFAULT_SECURITY_PATH = path.join(
  process.env.DSH_HOME || path.join(os.homedir(), '.dsh'),
  'plugin-remote-security.json',
)

/**
 * Capability model. Level 2 and Level 3 are DEFINED for future phases but are
 * NOT enabled in Phase 4: no pairing request may ask for them (level must be
 * 1) and no session is ever issued above level 1.
 */
const LEVELS = Object.freeze({
  1: Object.freeze([
    'observe_status',
    'observe_balance',
    'observe_task',
    'observe_system',
  ]),
  // Phase 5+: remote prompt. Defined, not enabled.
  2: Object.freeze([
    'observe_status',
    'observe_balance',
    'observe_task',
    'observe_system',
    'send_prompt',
  ]),
  // Future control plane. Defined, not enabled.
  3: Object.freeze(['control']),
})

function capsOf(level) {
  return LEVELS[level] || []
}

function can(level, cap) {
  return capsOf(level).includes(cap)
}

/** All non-internal IPv4 addresses of this host. */
export function lanAddresses() {
  const out = []
  const nets = os.networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) out.push(net.address)
    }
  }
  return out
}

/** Subnet broadcast address of one interface, or null for IPv6. */
export function broadcastOf(net) {
  if (!net || net.family !== 'IPv4' || !net.netmask) return null
  const ip = net.address.split('.').map(Number)
  const mask = net.netmask.split('.').map(Number)
  return ip.map((b, i) => b | (~mask[i] & 255)).join('.')
}

function sha256hex(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex')
}

function generateCredential() {
  return randomBytes(32).toString('base64url') // 256-bit random token
}

const DEVICE_ID_RE = /^[A-Za-z0-9._:-]{4,128}$/

function normDeviceId(value) {
  if (typeof value !== 'string') return ''
  const v = value.trim()
  return DEVICE_ID_RE.test(v) ? v : ''
}

function normDeviceName(value) {
  const v = String(value ?? '').trim().slice(0, 64)
  return v || 'My Phone'
}

function readMobileHtml() {
  try {
    return fs.readFileSync(
      fileURLToPath(new URL('./mobile.html', import.meta.url)),
      'utf8',
    )
  } catch (error) {
    return '<!doctype html><meta charset="utf-8"><title>DSH Remote</title><body>missing mobile.html</body>'
  }
}

function writeJson(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
  })
  res.end(body)
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
      if (data.length > 64 * 1024) req.destroy()
    })
    req.on('end', () => resolve(data))
    req.on('error', () => resolve(''))
  })
}

function readBodyJson(raw) {
  try {
    return JSON.parse(raw || '{}')
  } catch {
    return {}
  }
}

function isJsonContentType(req) {
  const header = req.headers['content-type'] || ''
  return header.split(';', 1)[0].trim().toLowerCase() === 'application/json'
}

function clientIp(req) {
  const addr = req.socket && req.socket.remoteAddress
  if (!addr) return 'unknown'
  return addr.startsWith('::ffff:') ? addr.slice(7) : addr
}

/** Extract the Bearer session id, or null. */
function bearerSessionId(req) {
  const header = req.headers['authorization'] || ''
  const match = /^Bearer\s+(\S+)$/.exec(header)
  return match ? match[1] : null
}

/**
 * Create one discovery engine.
 * @param {object} options
 * @param {string} [options.statePath] persisted instance identity file.
 * @param {string} [options.securityPath] persisted paired-devices file.
 * @param {number} [options.idleTimeoutMs] session idle expiry (default 24 h).
 * @param {number} [options.balanceCacheMs] balance cache TTL (default 15 s).
 * @param {number} [options.ticketTtlMs] QR pairing ticket TTL (default 60 s).
 * @param {{ agentStatus?: () => object, workspaces?: () => object,
 *           balance?: () => Promise<object>, system?: () => object }} [options.facts]
 * @param {(payload: object, emit: object) => Promise<void>} [options.promptExecutor]
 *        Phase 5: drives one remote prompt against the real DSH agent. Receives
 *        { task_id, device_id, device_name, prompt } and an emit handle with
 *        status('running'|'completed'|'failed'), output(text) and
 *        fail(code, message). Absent -> tasks fail with 'agent-error'.
 * @param {(entry: object) => void} [options.onAudit] minimal audit sink.
 * @param {(msg: string) => void} [options.log] log sink.
 */
export function createDiscovery(options = {}) {
  const statePath = options.statePath || DEFAULT_STATE_PATH
  const securityPath = options.securityPath || DEFAULT_SECURITY_PATH
  const facts = options.facts || {}
  const promptExecutor = options.promptExecutor
  const onAudit = options.onAudit
  const idleTimeoutMs = Number.isFinite(options.idleTimeoutMs) ? options.idleTimeoutMs : SESSION_IDLE_MS
  const balanceCacheMs = Number.isFinite(options.balanceCacheMs) ? options.balanceCacheMs : BALANCE_CACHE_MS
  const ticketTtlMs = Number.isFinite(options.ticketTtlMs) ? options.ticketTtlMs : TICKET_TTL_MS
  const log = options.log || ((msg) => console.error('[dsh-plugin-remote]', msg))

  let enabled = false
  let udp = null
  let server = null
  let heartbeatTimer = null
  let sessionPruneTimer = null
  let port = 0
  let lanIp = '127.0.0.1'
  let instanceId = ''
  let instanceName = ''
  const neighbors = new Map() // instance_id -> { info, lastSeen, ip }

  // ---------------------------------------------------- security runtime
  const devices = new Map() // device_id -> record
  const hashIndex = new Map() // credential_hash -> device_id
  const pending = new Map() // device_id -> pairing request
  const rejected = new Map() // device_id -> { claim_hash, expires_at }
  const tickets = new Map() // ticket_hash -> { created_at, expires_at, used }
  const sessions = new Map() // session_id -> session
  const sseClients = new Set() // { res, timer, sessionId, inFlight }
  const pairRate = new Map() // ip -> { count, windowStart }
  let securitySaveTimer = null

  // Phase 5: remote prompt task registry + per-device prompt rate limit.
  const promptTasks = new Map() // task_id -> task record
  const promptRate = new Map() // device_id -> { count, windowStart }

  // F-04: shared balance cache + single-flight
  let balanceCacheValue = null
  let balanceCacheAt = 0
  let balanceFlight = null

  function loadSecurity() {
    let data = {}
    try {
      data = JSON.parse(fs.readFileSync(securityPath, 'utf8'))
    } catch {
      /* first run */
    }
    const stored = (data && data.devices) || {}
    for (const id of Object.keys(stored)) {
      const record = stored[id]
      if (!record || !record.device_id) continue
      devices.set(record.device_id, {
        device_id: record.device_id,
        device_name: record.device_name || 'My Phone',
        level: 1,
        capabilities: capsOf(1),
        credential_hash: typeof record.credential_hash === 'string' ? record.credential_hash : '',
        paired_at_ms: typeof record.paired_at_ms === 'number' ? record.paired_at_ms : Date.now(),
        last_seen_ms: typeof record.last_seen_ms === 'number' ? record.last_seen_ms : 0,
        credential_picked: true, // a reloaded device never holds the raw credential
      })
      if (record.credential_hash) hashIndex.set(record.credential_hash, record.device_id)
    }
  }

  function saveSecurityNow() {
    try {
      fs.mkdirSync(path.dirname(securityPath), { recursive: true })
      const persisted = {}
      for (const record of devices.values()) {
        persisted[record.device_id] = {
          device_id: record.device_id,
          device_name: record.device_name,
          level: record.level,
          capabilities: capsOf(record.level),
          credential_hash: record.credential_hash,
          paired_at_ms: record.paired_at_ms,
          last_seen_ms: record.last_seen_ms,
        }
      }
      const tmp = securityPath + '.tmp'
      fs.writeFileSync(tmp, JSON.stringify({ devices: persisted }, null, 2))
      try {
        fs.chmodSync(tmp, 0o600)
      } catch {
        /* best effort */
      }
      fs.renameSync(tmp, securityPath)
    } catch (error) {
      log(`failed to persist security state: ${String(error)}`)
    }
  }

  function scheduleSecuritySave() {
    if (securitySaveTimer) return
    securitySaveTimer = setTimeout(() => {
      securitySaveTimer = null
      saveSecurityNow()
    }, 1500)
  }

  // ------------------------------------------------------------ state file
  function loadState() {
    let state = {}
    try {
      state = JSON.parse(fs.readFileSync(statePath, 'utf8'))
    } catch {
      /* first run */
    }
    instanceId =
      typeof state.instance_id === 'string' && state.instance_id
        ? state.instance_id
        : randomUUID()
    instanceName =
      typeof state.instance_name === 'string' && state.instance_name.trim()
        ? state.instance_name.trim()
        : os.hostname()
  }

  function saveState() {
    try {
      fs.mkdirSync(path.dirname(statePath), { recursive: true })
      const tmp = statePath + '.tmp'
      fs.writeFileSync(
        tmp,
        JSON.stringify(
          { instance_id: instanceId, instance_name: instanceName },
          null,
          2,
        ),
      )
      fs.renameSync(tmp, statePath)
    } catch (error) {
      log(`failed to persist state: ${String(error)}`)
    }
  }

  // -------------------------------------------------------------- payload
  function heartbeatPayload() {
    return Buffer.from(
      JSON.stringify({
        service: 'dsh-remote',
        version: '1',
        instance_id: instanceId,
        instance_name: instanceName,
        port,
        status: 'online',
        fingerprint: sha256hex(instanceId).slice(0, 8),
      }),
    )
  }

  function sendHeartbeat() {
    if (!enabled || !udp) return
    const payload = heartbeatPayload()
    const targets = new Set([MULTICAST_GROUP, '127.0.0.1', ...lanAddresses()])
    for (const addr of targets) {
      try {
        udp.send(payload, MULTICAST_PORT, addr)
      } catch {
        /* ignore per-target failures */
      }
    }
    const nets = os.networkInterfaces()
    for (const name of Object.keys(nets)) {
      for (const net of nets[name] || []) {
        const bcast = broadcastOf(net)
        if (!bcast) continue
        try {
          udp.send(payload, MULTICAST_PORT, bcast)
        } catch {
          /* ignore */
        }
      }
    }
    pruneNeighbors()
  }

  function pruneNeighbors() {
    const now = Date.now()
    for (const [id, entry] of neighbors) {
      if (now - entry.lastSeen > FORGET_MS) neighbors.delete(id)
    }
  }

  // ------------------------------------------------------------------ udp
  function onMessage(msg, rinfo) {
    let info
    try {
      info = JSON.parse(msg.toString('utf8'))
    } catch {
      return
    }
    if (!info || info.service !== 'dsh-remote' || !info.instance_id) return
    if (info.instance_id === instanceId) return // our own echo
    neighbors.set(info.instance_id, {
      info,
      lastSeen: Date.now(),
      ip: rinfo.address,
    })
  }

  function startUdp() {
    try {
      udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      udp.on('error', (error) => log(`udp error: ${String(error)}`))
      udp.on('message', onMessage)
      udp.bind(MULTICAST_PORT, '0.0.0.0', () => {
        try {
          udp.setMulticastTTL(1)
          udp.setMulticastLoopback(true)
          udp.addMembership(MULTICAST_GROUP)
          for (const addr of [...lanAddresses(), '127.0.0.1']) {
            try {
              udp.addMembership(MULTICAST_GROUP, addr)
            } catch {
              /* interface may not support membership */
            }
          }
        } catch (error) {
          log(`udp membership failed: ${String(error)}`)
        }
      })
    } catch (error) {
      log(`failed to create udp socket: ${String(error)}`)
    }
  }

  // ----------------------------------------------------------- F-02 rate
  function pairRateLimited(ip) {
    const now = Date.now()
    if (pairRate.size > 5000) {
      for (const [key, bucket] of pairRate) {
        if (now - bucket.windowStart >= PAIR_RATE_WINDOW_MS) pairRate.delete(key)
      }
      if (pairRate.size > 5000) pairRate.clear()
    }
    const bucket = pairRate.get(ip)
    if (!bucket || now - bucket.windowStart >= PAIR_RATE_WINDOW_MS) {
      pairRate.set(ip, { count: 1, windowStart: now })
      return false
    }
    bucket.count += 1
    return bucket.count > PAIR_RATE_MAX
  }

  // ------------------------------------------------------------ QR tickets
  // Phase 4: one-time pairing tickets. Only SHA-256 hashes are stored; the
  // plaintext ticket exists only in the QR the user scans. Tickets die after
  // TICKET_TTL_MS, on single use, on broadcast disable, and on DSH restart
  // (this Map is memory-only).
  function pruneTickets() {
    const now = Date.now()
    for (const [hash, record] of tickets) {
      if (record.expires_at <= now) tickets.delete(hash)
    }
  }

  function createPairingTicket() {
    pruneTickets()
    const ticket = generateCredential() // 256-bit random
    tickets.set(sha256hex(ticket), {
      created_at: Date.now(),
      expires_at: Date.now() + ticketTtlMs,
      used: false,
    })
    return ticket
  }

  /** @returns 'ok' | 'used' | 'expired' | 'invalid'; consumes on 'ok'. */
  function consumePairingTicket(ticket) {
    if (typeof ticket !== 'string' || !ticket) return 'invalid'
    const hash = sha256hex(ticket)
    const record = tickets.get(hash)
    if (!record) {
      pruneTickets() // housekeeping only; unknown ticket is 'invalid'
      return 'invalid'
    }
    if (record.used) return 'used'
    if (Date.now() > record.expires_at) {
      tickets.delete(hash)
      return 'expired'
    }
    record.used = true // one-shot: a ticket may start at most one pairing
    return 'ok'
  }

  // ------------------------------------------------------------- pairing
  function prunePairing() {
    const now = Date.now()
    for (const [id, req] of pending) {
      if (req.expires_at <= now) pending.delete(id)
    }
    for (const [id, entry] of rejected) {
      if (entry.expires_at <= now) rejected.delete(id)
    }
    // F-01: credentials not picked up within the pickup deadline die too.
    for (const [id, dev] of [...devices]) {
      if (dev.credential_picked) continue
      if (dev.pickup_deadline && now > dev.pickup_deadline) {
        devices.delete(id)
        if (dev.credential_hash) hashIndex.delete(dev.credential_hash)
      }
    }
  }

  // F-05: Origin allowlist for the state-changing pairing endpoint.
  function originAllowedForPair(req) {
    const origin = req.headers.origin
    if (origin === undefined) return true // non-browser fallback (CSRF requires a browser)
    if (origin === 'null') return false
    let url
    try {
      url = new URL(origin)
    } catch {
      return false
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    const host = url.hostname
    const originPort = url.port || (url.protocol === 'https:' ? '443' : '80')
    // The instance's own origins (however the phone opened the page).
    if (
      (host === '127.0.0.1' || host === 'localhost' || host === lanIp) &&
      String(originPort) === String(port)
    ) {
      return true
    }
    // Origins of discovered instances (a phone page served by DSH B may pair
    // with DSH A; A knows B because both broadcast on the multicast group).
    for (const entry of neighbors.values()) {
      if (entry.ip === host && String(entry.info.port) === String(originPort)) {
        return true
      }
    }
    return false
  }

  async function handlePair(req, res) {
    if (!originAllowedForPair(req)) {
      writeJson(res, 403, { ok: false, code: 'origin-forbidden' })
      return
    }
    if (pairRateLimited(clientIp(req))) {
      writeJson(res, 429, { ok: false, code: 'rate-limited' })
      return
    }
    const body = readBodyJson(await readBody(req))
    const deviceId = normDeviceId(body.device_id)
    const deviceName = normDeviceName(body.device_name)
    const level = Number(body.level)
    // `code` carries either a legacy phone-generated pairing code OR a QR
    // pairing ticket. Either way only its SHA-256 is kept (claim_hash).
    const code = typeof body.code === 'string' ? body.code : ''
    if (!deviceId || code.length < 16 || code.length > 256) {
      writeJson(res, 400, { ok: false, code: 'bad-request' })
      return
    }
    // No self-elevation: only Level 1 can ever be requested. Level 2/3 exist
    // in the capability model but are not enabled (Phase 4).
    if (level !== 1) {
      writeJson(res, 403, { ok: false, code: 'level-not-allowed' })
      return
    }
    // Phase 4: if the submitted value is a QR ticket, consume it (one-shot).
    // A used/expired ticket is rejected outright (QR-03/QR-05); an unknown
    // value is treated as a legacy phone code.
    const ticketStatus = consumePairingTicket(code)
    if (ticketStatus === 'used') {
      writeJson(res, 400, { ok: false, code: 'ticket-used' })
      return
    }
    if (ticketStatus === 'expired') {
      writeJson(res, 400, { ok: false, code: 'ticket-expired' })
      return
    }
    const claimHash = sha256hex(code)
    prunePairing()
    if (devices.has(deviceId)) {
      writeJson(res, 200, { ok: true, status: 'paired' })
      return
    }
    const existing = pending.get(deviceId)
    if (existing) {
      // F-01/F-06: a pending entry is immutable. Same claim = idempotent retry
      // (200, no TTL refresh); different claim = conflict (no overwrite).
      if (claimHash === existing.claim_hash) {
        writeJson(res, 200, { ok: true, status: 'pending' })
      } else {
        writeJson(res, 409, { ok: false, code: 'already-pending' })
      }
      return
    }
    if (pending.size >= MAX_PENDING) {
      writeJson(res, 429, { ok: false, code: 'too-many-pending' })
      return
    }
    pending.set(deviceId, {
      device_id: deviceId,
      device_name: deviceName,
      level: 1,
      claim_hash: claimHash,
      created_at: Date.now(),
      expires_at: Date.now() + PAIR_TTL_MS,
    })
    writeJson(res, 200, { ok: true, status: 'pending' })
  }

  async function handlePairStatus(req, res) {
    const body = readBodyJson(await readBody(req))
    const deviceId = normDeviceId(body.device_id)
    const code = typeof body.code === 'string' ? body.code : ''
    prunePairing()
    if (!deviceId || !code) {
      writeJson(res, 200, { ok: true, status: 'not-found' })
      return
    }
    const claimHash = sha256hex(code)
    const dev = devices.get(deviceId)
    if (dev) {
      // Credential pickup: with the matching claim (code or ticket), only
      // once, only within the pickup deadline (F-01: expired requests can
      // never claim a credential).
      if (
        !dev.credential_picked &&
        dev.pickup_deadline &&
        Date.now() <= dev.pickup_deadline &&
        claimHash === dev.claim_hash &&
        dev.credential
      ) {
        const raw = dev.credential
        dev.credential_picked = true
        dev.claim_hash = undefined
        dev.credential = undefined
        dev.pickup_deadline = undefined
        scheduleSecuritySave()
        writeJson(res, 200, {
          ok: true,
          status: 'accepted',
          credential: raw,
          level: dev.level,
          instance_id: instanceId,
        })
        return
      }
      writeJson(res, 200, { ok: true, status: 'paired' })
      return
    }
    const pend = pending.get(deviceId)
    if (pend && claimHash === pend.claim_hash) {
      writeJson(res, 200, { ok: true, status: 'pending' })
      return
    }
    const rej = rejected.get(deviceId)
    if (rej && claimHash === rej.claim_hash) {
      writeJson(res, 200, { ok: true, status: 'rejected' })
      return
    }
    writeJson(res, 200, { ok: true, status: 'not-found' })
  }

  /** PC-side: accept a pending pairing request, minting the credential. */
  function acceptPair(deviceId) {
    prunePairing()
    const req = pending.get(deviceId)
    if (!req) return { ok: false, code: 'not-pending' }
    const raw = generateCredential()
    devices.set(deviceId, {
      device_id: deviceId,
      device_name: req.device_name,
      level: 1,
      capabilities: capsOf(1), // server-derived; never taken from the client
      credential_hash: sha256hex(raw),
      credential: raw, // transient; handed to the phone once, never persisted
      claim_hash: req.claim_hash,
      credential_picked: false,
      pickup_deadline: Date.now() + PICKUP_TTL_MS,
      paired_at_ms: Date.now(),
      last_seen_ms: Date.now(),
    })
    hashIndex.set(sha256hex(raw), deviceId)
    pending.delete(deviceId) // F-01: accept removes the pending request
    saveSecurityNow()
    return { ok: true }
  }

  /** PC-side: reject a pending pairing request. */
  function rejectPair(deviceId) {
    const req = pending.get(deviceId)
    if (!req) return { ok: false, code: 'not-pending' }
    pending.delete(deviceId) // F-01: reject removes the pending request
    rejected.set(deviceId, {
      claim_hash: req.claim_hash,
      expires_at: Date.now() + REJECT_TTL_MS,
    })
    return { ok: true }
  }

  /** PC-side: revoke a paired device (credential dies immediately). */
  function revokeDevice(deviceId) {
    const dev = devices.get(deviceId)
    if (!dev) return { ok: false, code: 'not-paired' }
    devices.delete(deviceId)
    if (dev.credential_hash) hashIndex.delete(dev.credential_hash)
    pending.delete(deviceId)
    invalidateSessionsFor(deviceId)
    saveSecurityNow()
    return { ok: true }
  }

  /** Safe (leak-free) pairing views for the PC UI. */
  function pairList() {
    prunePairing()
    return {
      pending: [...pending.values()].map((req) => ({
        device_id: req.device_id,
        device_name: req.device_name,
        level: req.level,
        created_at_ms: req.created_at,
      })),
      paired: [...devices.values()].map((dev) => ({
        device_id: dev.device_id,
        device_name: dev.device_name,
        level: dev.level,
        paired_at_ms: dev.paired_at_ms,
        last_seen_ms: dev.last_seen_ms,
      })),
    }
  }

  // ------------------------------------------------------------- sessions
  function safeSession(session) {
    return {
      session_id: session.session_id,
      device_id: session.device_id,
      instance_id: session.instance_id,
      level: session.level,
      capabilities: capsOf(session.level),
      created_at_ms: session.created_at,
    }
  }

  function sessionExpired(session, now) {
    return now - session.last_seen_at > idleTimeoutMs
  }

  /** F-03: real cleanup — delete expired sessions and close their SSE. */
  function pruneSessions() {
    const now = Date.now()
    for (const [sid, session] of [...sessions]) {
      if (sessionExpired(session, now)) {
        sessions.delete(sid)
        closeSse(sid, 'expired')
      }
    }
  }

  function createSession(credential) {
    if (typeof credential !== 'string' || !credential) {
      return { ok: false, code: 'invalid-credential', status: 401 }
    }
    const deviceId = hashIndex.get(sha256hex(credential))
    const dev = deviceId ? devices.get(deviceId) : undefined
    if (!dev) return { ok: false, code: 'invalid-credential', status: 401 }
    // F-03: purge this device's expired sessions, then enforce the cap.
    const now = Date.now()
    for (const [sid, session] of [...sessions]) {
      if (session.device_id === deviceId && sessionExpired(session, now)) {
        sessions.delete(sid)
        closeSse(sid, 'expired')
      }
    }
    let active = 0
    for (const session of sessions.values()) {
      if (session.device_id === deviceId) active += 1
    }
    if (active >= MAX_SESSIONS_PER_DEVICE) {
      return { ok: false, code: 'session-limit', status: 429 }
    }
    const session = {
      session_id: randomUUID(),
      device_id: deviceId,
      instance_id: instanceId,
      level: dev.level,
      created_at: now,
      last_seen_at: now,
    }
    sessions.set(session.session_id, session)
    dev.last_seen_ms = now
    scheduleSecuritySave()
    return { ok: true, session: safeSession(session) }
  }

  function getSession(sessionId) {
    if (!sessionId) return undefined
    const session = sessions.get(sessionId)
    if (!session) return undefined
    if (sessionExpired(session, Date.now())) {
      sessions.delete(sessionId)
      closeSse(sessionId, 'expired')
      return undefined
    }
    return session
  }

  function invalidateSessionsFor(deviceId) {
    for (const [sid, session] of [...sessions]) {
      if (session.device_id === deviceId) {
        sessions.delete(sid)
        closeSse(sid, 'revoked')
      }
    }
  }

  function invalidateAllSessions(reason) {
    for (const sid of [...sessions.keys()]) {
      sessions.delete(sid)
      closeSse(sid, reason)
    }
  }

  // -------------------------------------------------- Phase 5 remote prompt
  /**
   * PC-side only: change a paired device's access level (1 or 2). The phone
   * can never request this — the client-declared level/capabilities are never
   * trusted. Active sessions of the device adopt the new level immediately.
   */
  function setDeviceLevel(deviceId, level) {
    const dev = devices.get(deviceId)
    if (!dev) return { ok: false, code: 'not-paired' }
    if (level !== 1 && level !== 2) return { ok: false, code: 'bad-level' }
    dev.level = level
    dev.capabilities = capsOf(level)
    saveSecurityNow()
    for (const session of sessions.values()) {
      if (session.device_id === deviceId) session.level = level
    }
    return { ok: true }
  }

  function audit(entry) {
    try {
      onAudit && onAudit(entry)
    } catch {
      /* audit must never break the flow */
    }
  }

  function taskSnapshot(task) {
    return {
      task_id: task.task_id,
      instance_id: task.instance_id,
      device_id: task.device_id,
      device_name: task.device_name,
      status: task.status,
      output: task.output,
      error_code: task.error_code,
      error_message: task.error_message,
      created_at_ms: task.created_at,
      started_at_ms: task.started_at,
      completed_at_ms: task.completed_at,
    }
  }

  function pruneTasks() {
    const now = Date.now()
    for (const [id, task] of promptTasks) {
      if (
        (task.status === 'completed' || task.status === 'failed') &&
        now - (task.completed_at || now) > TASK_RETENTION_MS
      ) {
        promptTasks.delete(id)
      }
    }
  }

  function promptTaskById(taskId) {
    return taskId ? promptTasks.get(taskId) : undefined
  }

  /**
   * Authenticated prompt intake. The session was already validated by the
   * caller; here we enforce capability, prompt shape, per-device rate limit
   * and the concurrency cap, then hand the task to the host executor.
   * @returns {{ok:true, task_id:string} | {ok:false, code:string, status:number}}
   */
  function createPromptTask(session, prompt) {
    const dev = devices.get(session.device_id)
    if (!dev) return { ok: false, code: 'unauthorized', status: 401 }
    if (!can(session.level, 'send_prompt')) {
      return { ok: false, code: 'insufficient-capability', status: 403 }
    }
    if (typeof prompt !== 'string' || !prompt.trim()) {
      return { ok: false, code: 'invalid-prompt', status: 400 }
    }
    if (prompt.length > PROMPT_MAX_LENGTH) {
      return { ok: false, code: 'prompt-too-large', status: 413 }
    }
    const now = Date.now()
    const bucket = promptRate.get(session.device_id)
    if (!bucket || now - bucket.windowStart >= PROMPT_RATE_WINDOW_MS) {
      promptRate.set(session.device_id, { count: 1, windowStart: now })
    } else {
      bucket.count += 1
      if (bucket.count > PROMPT_RATE_MAX) {
        return { ok: false, code: 'prompt-rate-limit', status: 429 }
      }
    }
    let active = 0
    for (const task of promptTasks.values()) {
      if (task.status === 'queued' || task.status === 'running') active += 1
    }
    if (active >= MAX_ACTIVE_PROMPTS) {
      return { ok: false, code: 'prompt-limit', status: 429 }
    }
    const task = {
      task_id: randomUUID(),
      instance_id: instanceId,
      device_id: session.device_id,
      device_name: dev.device_name,
      status: 'queued',
      created_at: now,
      started_at: null,
      completed_at: null,
      output: '',
      error_code: null,
      error_message: null,
    }
    promptTasks.set(task.task_id, task)
    audit({
      ts: now,
      device_id: task.device_id,
      device_name: task.device_name,
      task_id: task.task_id,
      prompt_len: prompt.length,
      status: 'queued',
    })
    queueMicrotask(() => runTask(task, prompt))
    return { ok: true, task_id: task.task_id }
  }

  async function runTask(task, prompt) {
    task.status = 'running'
    task.started_at = Date.now()
    audit({
      ts: Date.now(),
      device_id: task.device_id,
      device_name: task.device_name,
      task_id: task.task_id,
      prompt_len: prompt.length,
      status: 'running',
    })
    const emit = {
      status(next) {
        if (next === 'completed' || next === 'failed') {
          task.status = next
          task.completed_at = Date.now()
        } else if (task.status === 'running') {
          task.status = next
        }
      },
      output(text) {
        if (typeof text !== 'string') return
        if (task.output.length >= TASK_OUTPUT_MAX) return
        task.output += text.slice(0, TASK_OUTPUT_MAX - task.output.length)
      },
      fail(code, message) {
        task.status = 'failed'
        task.error_code = code || 'agent-error'
        task.error_message = String(message || '').slice(0, 500)
        task.completed_at = Date.now()
      },
    }
    try {
      if (typeof promptExecutor !== 'function') {
        emit.fail('AGENT_EXECUTION_FAILED', 'agent executor unavailable')
      } else {
        await promptExecutor(
          {
            task_id: task.task_id,
            device_id: task.device_id,
            device_name: task.device_name,
            prompt,
          },
          emit,
        )
        if (task.status === 'running') {
          task.status = 'completed'
          task.completed_at = Date.now()
        }
      }
    } catch (error) {
      log(`prompt task failed: ${String(error)}`)
      emit.fail('AGENT_EXECUTION_FAILED', 'agent error')
    }
    audit({
      ts: Date.now(),
      device_id: task.device_id,
      device_name: task.device_name,
      task_id: task.task_id,
      prompt_len: prompt.length,
      status: task.status,
      error_code: task.error_code, // diagnostics only; never prompt content
    })
    pruneTasks()
  }

  /** Task SSE: pushes task snapshots until the task is terminal, then closes. */
  function startTaskSse(req, res, session, task) {
    let open = 0
    for (const client of sseClients) {
      if (client.sessionId === session.session_id) open += 1
    }
    if (open >= MAX_SSE_PER_SESSION) {
      writeJson(res, 429, { ok: false, code: 'sse-limit' })
      return
    }
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'access-control-allow-origin': '*',
    })
    res.write('retry: 3000\n\n')
    const client = { res, timer: null, sessionId: session.session_id, inFlight: false }
    const push = () => {
      if (client.inFlight) return
      client.inFlight = true
      try {
        const current = promptTasks.get(task.task_id)
        if (!current || current.status === 'completed' || current.status === 'failed') {
          // terminal: final snapshot + close
          res.write(`event: task\ndata: ${JSON.stringify(taskSnapshot(current || task))}\n\n`)
          res.end()
          clearInterval(client.timer)
          sseClients.delete(client)
          return
        }
        res.write(`event: task\ndata: ${JSON.stringify(taskSnapshot(current))}\n\n`)
      } catch {
        /* closed */
      } finally {
        client.inFlight = false
      }
    }
    push()
    client.timer = setInterval(push, 1000)
    sseClients.add(client)
    req.on('close', () => {
      clearInterval(client.timer)
      sseClients.delete(client)
    })
  }

  // ------------------------------------------------------------------ sse
  function startSse(req, res, session) {
    let open = 0
    for (const client of sseClients) {
      if (client.sessionId === session.session_id) open += 1
    }
    if (open >= MAX_SSE_PER_SESSION) {
      writeJson(res, 429, { ok: false, code: 'sse-limit' })
      return
    }
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'access-control-allow-origin': '*',
    })
    res.write('retry: 3000\n\n')
    const client = { res, timer: null, sessionId: session.session_id, inFlight: false }
    const push = async () => {
      if (client.inFlight) return // F-04: never overlap payload builds
      client.inFlight = true
      try {
        const payload = await buildObserverPayload(session)
        if (!res.destroyed) {
          res.write(`event: status\ndata: ${JSON.stringify(payload)}\n\n`)
        }
      } catch {
        /* stream closed */
      } finally {
        client.inFlight = false
      }
    }
    push()
    client.timer = setInterval(push, SSE_PUSH_MS)
    sseClients.add(client)
    req.on('close', () => {
      clearInterval(client.timer)
      sseClients.delete(client)
    })
  }

  function closeSse(sessionId, reason) {
    for (const client of [...sseClients]) {
      if (client.sessionId !== sessionId) continue
      try {
        client.res.write(
          `event: invalid\ndata: ${JSON.stringify({ reason })}\n\n`,
        )
      } catch {
        /* ignore */
      }
      try {
        client.res.end()
      } catch {
        /* ignore */
      }
      clearInterval(client.timer)
      sseClients.delete(client)
    }
  }

  // ------------------------------------------------------------ observer
  async function safeFact(fn) {
    try {
      const value = await fn()
      return value || { available: false }
    } catch {
      return { available: false }
    }
  }

  /** F-04: shared cache + single-flight balance lookup. */
  async function getBalance() {
    const now = Date.now()
    if (balanceCacheValue !== null && now - balanceCacheAt < balanceCacheMs) {
      return balanceCacheValue
    }
    if (balanceFlight) return balanceFlight
    balanceFlight = (async () => {
      const value = await safeFact(() => facts.balance && facts.balance())
      balanceCacheValue = value
      balanceCacheAt = Date.now()
      balanceFlight = null
      return value
    })()
    return balanceFlight
  }

  async function buildObserverPayload(session) {
    session.last_seen_at = Date.now() // any payload build is activity
    const level = session.level
    const payload = {
      ok: true,
      generated_ms: Date.now(),
      session: safeSession(session),
      connection: null,
      agent: null,
      project: null,
      current_task: null,
      balance: null,
      system: null,
    }
    if (can(level, 'observe_status')) {
      payload.connection = {
        instance_id: instanceId,
        instance_name: instanceName,
        status: enabled ? 'online' : 'offline',
        connection: 'local-network',
        lan_ip: lanIp,
        port,
      }
    }
    if (can(level, 'observe_task')) {
      payload.agent = await safeFact(() => facts.agentStatus && facts.agentStatus())
      payload.project = await safeFact(() => facts.workspaces && facts.workspaces())
      payload.current_task = { available: false } // no global task source
    }
    if (can(level, 'observe_balance')) {
      payload.balance = await getBalance()
    }
    if (can(level, 'observe_system')) {
      payload.system = await safeFact(() => facts.system && facts.system())
    }
    return payload
  }

  async function observerStatus(session) {
    const dev = devices.get(session.device_id)
    if (dev) {
      dev.last_seen_ms = Date.now()
      scheduleSecuritySave()
    }
    return buildObserverPayload(session)
  }

  // ----------------------------------------------------------------- http
  function handleCors(req, res) {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'authorization, content-type',
      'access-control-max-age': '600',
    })
    res.end()
  }

  async function handleHttp(req, res, mobileHtml) {
    if (req.method === 'OPTIONS') {
      handleCors(req, res)
      return
    }
    const url = (req.url || '/').split('?')[0]
    const method = req.method || 'GET'

    // Public allowlist
    if (method === 'GET' && (url === '/' || url === '/pair')) {
      // `/pair?ticket=...` is the QR landing page (Phase 4): it serves the
      // same mobile page, which reads the ticket from the query string.
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
      })
      res.end(mobileHtml)
      return
    }
    if (method === 'GET' && (url === '/health' || url === '/api/health')) {
      writeJson(res, 200, { ok: true, service: 'dsh-remote' })
      return
    }
    if (method === 'GET' && url === '/api/dsh-remote/instances') {
      writeJson(res, 200, instancesPayload())
      return
    }
    if (method === 'POST' && url === '/api/dsh-remote/pair') {
      if (!isJsonContentType(req)) {
        writeJson(res, 415, { ok: false, code: 'unsupported-media-type' })
        return
      }
      await handlePair(req, res)
      return
    }
    if (method === 'POST' && url === '/api/dsh-remote/pair/status') {
      if (!isJsonContentType(req)) {
        writeJson(res, 415, { ok: false, code: 'unsupported-media-type' })
        return
      }
      await handlePairStatus(req, res)
      return
    }

    // Authenticated endpoints (explicit allowlist; anything else -> 403)
    if (method === 'POST' && url === '/api/dsh-remote/session') {
      if (!isJsonContentType(req)) {
        writeJson(res, 415, { ok: false, code: 'unsupported-media-type' })
        return
      }
      const body = readBodyJson(await readBody(req))
      const result = createSession(body && body.credential)
      if (!result.ok) {
        writeJson(res, result.status || 401, { ok: false, code: result.code })
        return
      }
      writeJson(res, 200, { ok: true, session: result.session })
      return
    }
    if (method === 'GET' && url === '/api/dsh-remote/observer/status') {
      const session = getSession(bearerSessionId(req))
      if (!session) {
        writeJson(res, 401, { ok: false, code: 'unauthorized' })
        return
      }
      if (!can(session.level, 'observe_status')) {
        writeJson(res, 403, { ok: false, code: 'forbidden' })
        return
      }
      writeJson(res, 200, await observerStatus(session))
      return
    }
    if (method === 'GET' && url === '/api/dsh-remote/observer/events') {
      const session = getSession(bearerSessionId(req))
      if (!session) {
        writeJson(res, 401, { ok: false, code: 'unauthorized' })
        return
      }
      if (!can(session.level, 'observe_status')) {
        writeJson(res, 403, { ok: false, code: 'forbidden' })
        return
      }
      startSse(req, res, session)
      return
    }

    // ---- Phase 5: Level 2 remote prompt (server-enforced capability)
    if (method === 'POST' && url === '/api/dsh-remote/prompt') {
      if (!isJsonContentType(req)) {
        writeJson(res, 415, { ok: false, code: 'unsupported-media-type' })
        return
      }
      const session = getSession(bearerSessionId(req))
      if (!session) {
        writeJson(res, 401, { ok: false, code: 'unauthorized' })
        return
      }
      if (!can(session.level, 'send_prompt')) {
        writeJson(res, 403, { ok: false, code: 'insufficient-capability' })
        return
      }
      const body = readBodyJson(await readBody(req))
      const result = createPromptTask(session, body && body.prompt)
      writeJson(res, result.status || 200, result.ok ? { ok: true, task_id: result.task_id } : result)
      return
    }
    if (method === 'GET' && url === '/api/dsh-remote/prompt/status') {
      const session = getSession(bearerSessionId(req))
      if (!session) {
        writeJson(res, 401, { ok: false, code: 'unauthorized' })
        return
      }
      const taskId = new URL(req.url || '/', 'http://x').searchParams.get('task_id') || ''
      const task = promptTaskById(taskId)
      if (!task || task.instance_id !== session.instance_id || task.device_id !== session.device_id) {
        // unify unknown and foreign tasks to reduce info leakage
        writeJson(res, 404, { ok: false, code: 'task-not-found' })
        return
      }
      writeJson(res, 200, { ok: true, task: taskSnapshot(task) })
      return
    }
    if (method === 'GET' && url === '/api/dsh-remote/prompt/events') {
      const session = getSession(bearerSessionId(req))
      if (!session) {
        writeJson(res, 401, { ok: false, code: 'unauthorized' })
        return
      }
      const taskId = new URL(req.url || '/', 'http://x').searchParams.get('task_id') || ''
      const task = promptTaskById(taskId)
      if (!task || task.instance_id !== session.instance_id || task.device_id !== session.device_id) {
        writeJson(res, 404, { ok: false, code: 'task-not-found' })
        return
      }
      startTaskSse(req, res, session, task)
      return
    }

    // Everything else is outside the allowlist.
    writeJson(res, 403, { ok: false, code: 'forbidden' })
  }

  function instancesPayload() {
    const now = Date.now()
    const list = []
    list.push({
      instance_id: instanceId,
      instance_name: instanceName,
      port,
      ip: lanIp,
      self: true,
      status: 'online',
      fingerprint: sha256hex(instanceId).slice(0, 8),
      last_seen_ms: now,
    })
    for (const entry of neighbors.values()) {
      list.push({
        instance_id: entry.info.instance_id,
        instance_name:
          typeof entry.info.instance_name === 'string'
            ? entry.info.instance_name
            : '(unknown)',
        port: Number(entry.info.port) || 0,
        ip: entry.ip,
        self: false,
        status: now - entry.lastSeen <= ONLINE_TTL_MS ? 'online' : 'offline',
        fingerprint:
          typeof entry.info.fingerprint === 'string'
            ? entry.info.fingerprint
            : '',
        last_seen_ms: entry.lastSeen,
      })
    }
    return {
      service: 'dsh-remote',
      version: '1',
      generated_ms: now,
      instances: list,
    }
  }

  function startHttpServer() {
    const mobileHtml = readMobileHtml()
    let attemptIndex = 0
    const attempt = () => {
      if (attemptIndex >= HTTP_MAX_TRIES) {
        log(`could not bind an http port (tried ${HTTP_MAX_TRIES})`)
        return
      }
      const candidate = HTTP_BASE_PORT + attemptIndex++
      const srv = http.createServer((req, res) =>
        handleHttp(req, res, mobileHtml),
      )
      srv.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          srv.close()
          attempt()
        } else {
          log(`http server error: ${String(error)}`)
          try {
            srv.close()
          } catch {
            /* already closed */
          }
        }
      })
      srv.listen(candidate, '0.0.0.0', () => {
        server = srv
        port = candidate
        log(`listening on 0.0.0.0:${port} (multicast ${MULTICAST_GROUP}:${MULTICAST_PORT})`)
      })
    }
    attempt()
  }

  // -------------------------------------------------------------- public
  function start() {
    if (enabled) return
    enabled = true
    const addresses = lanAddresses()
    lanIp = addresses[0] || '127.0.0.1'
    startUdp()
    startHttpServer()
    heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_MS)
    sessionPruneTimer = setInterval(pruneSessions, SESSION_PRUNE_MS)
    sendHeartbeat()
  }

  function stop() {
    enabled = false
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
    if (sessionPruneTimer) {
      clearInterval(sessionPruneTimer)
      sessionPruneTimer = null
    }
    if (udp) {
      try {
        udp.close()
      } catch {
        /* ignore */
      }
      udp = null
    }
    // Phase 2: every active session dies with the broadcast (§十二).
    invalidateAllSessions('broadcast-disabled')
    pending.clear()
    rejected.clear()
    tickets.clear() // Phase 4: QR tickets die with the broadcast (QR-10)
    if (server) {
      try {
        server.close()
      } catch {
        /* ignore */
      }
      server = null
    }
    port = 0
    neighbors.clear()
  }

  function setName(name) {
    const trimmed = String(name || '').trim().slice(0, 64)
    if (!trimmed) return false
    instanceName = trimmed
    saveState()
    return true
  }

  function status() {
    return {
      ok: true,
      enabled,
      instance_id: instanceId,
      instance_name: instanceName,
      hostname: os.hostname(),
      lan_ip: lanIp,
      port,
      multicast_group: MULTICAST_GROUP,
      multicast_port: MULTICAST_PORT,
      heartbeat_ms: HEARTBEAT_MS,
      online_ttl_ms: ONLINE_TTL_MS,
      neighbors: [...neighbors.values()].map((entry) => ({
        instance_id: entry.info.instance_id,
        instance_name: entry.info.instance_name,
        ip: entry.ip,
        last_seen_ms: entry.lastSeen,
      })),
      pairs: pairList(),
    }
  }

  loadState()
  saveState() // persist the identity immediately so restarts keep instance_id
  loadSecurity()
  return {
    start,
    stop,
    setName,
    status,
    instancesPayload,
    pairList,
    acceptPair,
    rejectPair,
    revokeDevice,
    createSession,
    createPairingTicket,
    consumePairingTicket,
    setDeviceLevel,
    promptTaskById,
    get instanceName() {
      return instanceName
    },
  }
}
