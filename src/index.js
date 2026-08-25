// dsh-plugin-remote — host half.
//
// Wires the discovery engine (src/discovery.mjs) into the DSH host:
//  - registers the PC-side API routes on the main webServer
//    (/api/plugin.remote/*), which the browser capsule calls;
//  - supplies real DSH facts (agent status, workspaces, API balance via the
//    balance plugin's own route, system info) for the Level-1 observer API;
//  - Phase 5: runs remote prompts through the REAL DSH agent system (a fresh
//    session + agent, `agent.followup`, streamed via `session/event`) and
//    writes a minimal audit trail (never the prompt content);
//  - guarantees the broadcast is fully stopped when the plugin unloads or
//    DSH exits (the discovery engine is disposed by the ctx.effect disposer).
//
// The plugin is always OFF at startup: DSH never auto-broadcasts. Only the
// instance identity and the paired-device hashes are persisted; the enabled
// state is deliberately not.

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'

export const name = 'dsh-plugin-remote'

export const inject = ['webServer']

const STATUS_ROUTE = '/api/plugin.remote/status'
const ENABLE_ROUTE = '/api/plugin.remote/enable'
const DISABLE_ROUTE = '/api/plugin.remote/disable'
const NAME_ROUTE = '/api/plugin.remote/name'
const PAIR_ACCEPT_ROUTE = '/api/plugin.remote/pair/accept'
const PAIR_REJECT_ROUTE = '/api/plugin.remote/pair/reject'
const PAIR_REVOKE_ROUTE = '/api/plugin.remote/pair/revoke'
const PAIR_LEVEL_ROUTE = '/api/plugin.remote/pair/level'

function writeJson(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
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

function isJsonContentType(req) {
  const header = req.headers['content-type'] || ''
  return header.split(';', 1)[0].trim().toLowerCase() === 'application/json'
}

export function apply(ctx) {
  const require = createRequire(import.meta.url)
  const { createDiscovery } = require('./discovery.mjs')
  const { textToQrSvg } = require('./qr.mjs')

  const mainPort = ctx.webServer && ctx.webServer.port ? ctx.webServer.port : 3080

  // Real DSH facts for the Level-1 observer payload. Nothing is fabricated:
  // every provider returns { available: false } when the source is missing.
  const facts = {
    agentStatus() {
      const agents = ctx.get('agents')
      if (!agents) return { available: false }
      try {
        const list = agents.list() || []
        const running = list.filter(
          (agent) => agent && agent.status === 'running',
        ).length
        return {
          available: true,
          status: running > 0 ? 'working' : 'idle',
          detail: { live_agents: list.length, running_agents: running },
        }
      } catch {
        return { available: false }
      }
    },
    workspaces() {
      const registry = ctx.get('workspaceRegistry')
      if (!registry) return { available: false }
      try {
        const list = registry.list() || []
        const items = list
          .map((workspace) => ({
            path:
              typeof workspace.path === 'string' ? workspace.path : String(workspace.path || ''),
            title:
              typeof workspace.title === 'string' ? workspace.title : undefined,
          }))
          .filter((item) => item.path)
        return items.length
          ? { available: true, count: items.length, workspaces: items }
          : { available: false }
      } catch {
        return { available: false }
      }
    },
    async balance() {
      // Reuse the balance plugin's own route (never copy its logic).
      try {
        const response = await fetch(
          `http://127.0.0.1:${mainPort}/api/plugin.balance`,
          {
            headers: { accept: 'application/json' },
            signal: AbortSignal.timeout(8000),
          },
        )
        const data = await response.json().catch(() => null)
        if (response.status === 200 && data && data.ok) {
          return {
            available: true,
            balance: String(data.balance),
            currency: typeof data.currency === 'string' ? data.currency : '',
          }
        }
        return { available: false }
      } catch {
        return { available: false }
      }
    },
    system() {
      const total = os.totalmem()
      const free = os.freemem()
      return {
        available: true,
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        memory: {
          total_bytes: total,
          free_bytes: free,
          used_pct: total ? Math.round(((total - free) / total) * 1000) / 10 : null,
        },
        uptime_sec: Math.round(os.uptime()),
      }
    },
  }

  // ---- Phase 5: minimal audit trail (never the prompt content) ----------
  const auditFile = path.join(
    process.env.DSH_HOME || path.join(os.homedir(), '.dsh'),
    'plugin-remote-audit.jsonl',
  )
  const onAudit = (entry) => {
    try {
      fs.mkdirSync(path.dirname(auditFile), { recursive: true })
      fs.appendFileSync(auditFile, JSON.stringify(entry) + '\n')
      if (fs.statSync(auditFile).size > 1024 * 1024) {
        const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n')
        fs.writeFileSync(auditFile, lines.slice(-1000).join('\n') + '\n')
      }
    } catch {
      /* best effort */
    }
  }

  // ---- Phase 5: run a remote prompt through the REAL DSH agent ----------
  // The remote API is only a new entry point into DSH's own agent pipeline.
  // An agent is created through the canonical factory path (ctx.agents.create)
  // with the deployment's default preset + default model — NOT the raw
  // agentLoop.create() path, which skips preset composition and the default
  // model and makes the first model request throw ("no provider/model").
  // Output streams back through the session event log. Staged diagnostics
  // (code + stage) are logged locally; the phone only ever sees a friendly
  // message plus the stable error code — never stacks, keys, or paths.
  const promptExecutor = async (payload, emit) => {
    const agents = ctx.get('agents')
    const sessions = ctx.get('sessions')
    if (!agents || !sessions) {
      ctx.logger?.warn?.('dsh-plugin-remote prompt: agents/sessions unavailable')
      emit.fail('AGENT_UNAVAILABLE', 'agent system unavailable')
      return
    }
    let cwd
    let presetId
    let provider
    let model
    try {
      const registry = ctx.get('workspaceRegistry')
      const list = registry ? registry.list() : []
      if (list[0] && typeof list[0].path === 'string') cwd = list[0].path
      const agentPresets = ctx.get('agentPresets')
      if (agentPresets) {
        const resolved = await agentPresets.resolve()
        if (resolved && resolved.id) presetId = resolved.id
      }
      const defaultModel = ctx.get('agentDefaultModel')
      if (defaultModel) {
        const selection = defaultModel.currentSelection()
        if (selection) {
          provider = selection.provider
          model = selection.model
        }
      }
    } catch (error) {
      ctx.logger?.warn?.(`dsh-plugin-remote prompt: resolve defaults ${String(error)}`)
    }
    ctx.logger?.warn?.(`dsh-plugin-remote prompt: stage=resolve cwd=${cwd ? 'yes' : 'no'} preset=${presetId ? 'yes' : 'no'} model=${model ? 'yes' : 'no'}`)

    // Stage A: create + publish the agent (session + agent + preset + model).
    let handle
    try {
      handle = await agents.create({
        sessionId: 'session-' + randomUUID(),
        meta: {
          ...(cwd ? { cwd } : {}),
          ...(presetId ? { agentPreset: presetId } : {}),
        },
        agentOptions: {
          ...(provider ? { provider } : {}),
          ...(model ? { model } : {}),
        },
        setup: async (agentCtx) => {
          // The factory consumes the setup result as `(await setup(ctx))?.commit()`:
          // it MUST resolve to a commit object, not the mount return value.
          const ap = agentCtx.get('agentPresets')
          if (ap && presetId) await ap.mount(agentCtx, presetId)
          return { commit() {} }
        },
      })
    } catch (error) {
      ctx.logger?.warn?.(`dsh-plugin-remote prompt: stage=agent_create ${String(error)}`)
      emit.fail('AGENT_CREATE_FAILED', 'failed to create the agent task')
      return
    }
    ctx.logger?.warn?.(`dsh-plugin-remote prompt: stage=agent_create ok id=${handle.agent.id}`)

    // Stages B-G: build the user message, drive one turn, stream output.
    let off
    let finished = false
    try {
      const { createUserMessage } = require('@deepseek-ai/dsh-llm')
      const userMessage = createUserMessage({
        content: [{ type: 'text', text: payload.prompt }],
        source: { kind: 'plugin', plugin: 'dsh-plugin-remote' },
      })
      off = ctx.on('session/event', (s, event) => {
        if (!s || s.id !== handle.agent.id || finished) return
        if (event.type === 'assistant/chunk') {
          const chunk = event.data && event.data.chunk
          let text = ''
          if (chunk) {
            if (chunk.type === 'text-delta' || chunk.type === 'reasoning-delta') {
              text = chunk.text || ''
            } else if (typeof chunk.text === 'string') {
              text = chunk.text
            }
          }
          if (text) emit.output(text)
        } else if (event.type === 'assistant/message') {
          const message = event.data && event.data.message
          if (message && Array.isArray(message.content)) {
            const text = message.content
              .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
              .map((b) => b.text)
              .join('')
            if (text) emit.output(text)
          }
        } else if (event.type === 'turn/end') {
          finished = true
          const reason = event.data && event.data.reason
          if (reason && reason.kind === 'error') {
            emit.fail('AGENT_TURN_ERROR', 'agent turn ended with an error')
          } else {
            emit.status('completed')
          }
          off && off()
        }
      })
      handle.agent.followup(userMessage)
      ctx.logger?.warn?.(`dsh-plugin-remote prompt: stage=followup ok status=${handle.agent.status}`)
    } catch (error) {
      ctx.logger?.warn?.(`dsh-plugin-remote prompt: stage=followup ${String(error)}`)
      if (off) {
        try {
          off()
        } catch {
          /* ignore */
        }
      }
      try {
        await handle.dispose()
      } catch {
        /* ignore */
      }
      emit.fail('AGENT_FOLLOWUP_FAILED', 'failed to start the agent turn')
    }
  }

  const discovery = createDiscovery({
    facts,
    promptExecutor,
    onAudit,
    log: (msg) => ctx.logger?.warn?.(`dsh-plugin-remote: ${msg}`),
  })

  const handler = (route, method, run) => async (req, res) => {
    if (req.method !== method) {
      writeJson(res, 405, { ok: false, code: 'method', status: 405 })
      return
    }
    try {
      const result = await run(req)
      // Handlers may return { ok, code, status } for non-2xx outcomes; honor
      // the HTTP status instead of always answering 200.
      const status =
        result && typeof result === 'object' && Number.isInteger(result.status)
          ? result.status
          : 200
      writeJson(res, status, result)
    } catch (error) {
      ctx.logger?.warn?.(`dsh-plugin-remote ${route}: ${String(error)}`)
      writeJson(res, 500, { ok: false, code: 'failed', status: 500 })
    }
  }

  const pairAction = (action) => async (req) => {
    if (!isJsonContentType(req)) {
      return { ok: false, code: 'unsupported-media-type', status: 415 }
    }
    let body = {}
    try {
      body = JSON.parse((await readBody(req)) || '{}')
    } catch {
      return { ok: false, code: 'bad-json', status: 400 }
    }
    const deviceId =
      typeof body.device_id === 'string' ? body.device_id.trim() : ''
    if (!deviceId) return { ok: false, code: 'bad-device-id', status: 400 }
    const result = discovery[action](deviceId)
    if (!result.ok) return { ok: false, code: result.code, status: 400 }
    return { ok: true }
  }

  ctx.effect(
    () => {
      const disposers = [
        ctx.webServer.register({
          kind: 'exact',
          path: STATUS_ROUTE,
          handler: handler(STATUS_ROUTE, 'GET', () => discovery.status()),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: ENABLE_ROUTE,
          handler: handler(ENABLE_ROUTE, 'POST', async () => {
            discovery.start()
            return discovery.status()
          }),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: DISABLE_ROUTE,
          handler: handler(DISABLE_ROUTE, 'POST', async () => {
            discovery.stop()
            return discovery.status()
          }),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: NAME_ROUTE,
          handler: handler(NAME_ROUTE, 'POST', async (req) => {
            if (!isJsonContentType(req)) {
              return { ok: false, code: 'unsupported-media-type', status: 415 }
            }
            let body = {}
            try {
              body = JSON.parse((await readBody(req)) || '{}')
            } catch {
              return { ok: false, code: 'bad-json', status: 400 }
            }
            if (!discovery.setName(body && body.name)) {
              return { ok: false, code: 'bad-name', status: 400 }
            }
            return discovery.status()
          }),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: PAIR_ACCEPT_ROUTE,
          handler: handler(PAIR_ACCEPT_ROUTE, 'POST', pairAction('acceptPair')),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: '/api/plugin.remote/pair/ticket',
          handler: handler('/api/plugin.remote/pair/ticket', 'POST', async () => {
            // Phase 4: mint a one-time QR pairing ticket. Requires broadcast
            // to be on (the phone must reach the mobile server to pair).
            const state = discovery.status()
            if (!state.enabled || !state.port) {
              return { ok: false, code: 'broadcast-off', status: 400 }
            }
            const ticket = discovery.createPairingTicket()
            const url = `http://${state.lan_ip}:${state.port}/pair?ticket=${encodeURIComponent(ticket)}`
            let qrSvg = ''
            try {
              qrSvg = textToQrSvg(url)
            } catch (error) {
              ctx.logger?.warn?.(`dsh-plugin-remote qr: ${String(error)}`)
              return { ok: false, code: 'qr-failed', status: 500 }
            }
            return {
              ok: true,
              ticket,
              url,
              qr_svg: qrSvg,
              instance_name: state.instance_name,
              lan_ip: state.lan_ip,
              port: state.port,
              expires_at_ms: Date.now() + 60000,
              ttl_ms: 60000,
            }
          }),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: PAIR_REJECT_ROUTE,
          handler: handler(PAIR_REJECT_ROUTE, 'POST', pairAction('rejectPair')),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: PAIR_REVOKE_ROUTE,
          handler: handler(PAIR_REVOKE_ROUTE, 'POST', pairAction('revokeDevice')),
        }),
        ctx.webServer.register({
          kind: 'exact',
          path: PAIR_LEVEL_ROUTE,
          handler: handler(PAIR_LEVEL_ROUTE, 'POST', async (req) => {
            // Phase 5: the PC changes a device's access level (1 or 2).
            // The phone can never request this.
            if (!isJsonContentType(req)) {
              return { ok: false, code: 'unsupported-media-type', status: 415 }
            }
            let body = {}
            try {
              body = JSON.parse((await readBody(req)) || '{}')
            } catch {
              return { ok: false, code: 'bad-json', status: 400 }
            }
            const deviceId =
              typeof body.device_id === 'string' ? body.device_id.trim() : ''
            if (!deviceId) return { ok: false, code: 'bad-device-id', status: 400 }
            const result = discovery.setDeviceLevel(deviceId, Number(body.level))
            if (!result.ok) return { ok: false, code: result.code, status: 400 }
            return { ok: true }
          }),
        }),
      ]
      return () => {
        for (const dispose of disposers) {
          try {
            dispose()
          } catch {
            /* ignore */
          }
        }
        discovery.stop() // DSH exit / plugin unload -> stop broadcasting + sessions
      }
    },
    'dsh-plugin-remote: routes + broadcast lifecycle',
  )
}
