# DSH-mobile-remote-mode-plugin — DSH 移动端远程模式插件

> **版本 Version: Dev0.1** · **多端通用 Multi-platform** · **早期开发 Early Development**

**让手机成为 DSH 的遥控器。** 同一局域网内扫码配对，手机实时观察（Level 1）、远程向真实 Agent 发送提示词（Level 2）；后续方向：Level 3 受控操作、原生 App（Android / iOS）。

**Turn your phone into a DSH remote.** QR pairing over LAN, live observation (Level 1), remote prompts to the real Agent (Level 2) — from Android / iOS / any browser. Roadmap: Level 3 supervised control, native apps.

## 一键安装 / One-click install

```bash
git clone https://github.com/anonRTtty/DSH-mobile-remote-mode-plugin.git "$HOME/.dsh/profiles/node_modules/dsh-mobile-remote-mode-plugin"
```

安装后重启 DSH，WebUI → `远程模式 ◯` → 开启 **Remote Broadcast**。
After installing, restart DSH: WebUI → `远程模式 ◯` → enable **Remote Broadcast**.

[English](#english) · [中文](#中文)

---

## 中文

### 简介

`DSH-mobile-remote-mode-plugin` 是运行在 DSH（DeepSeek Harness）上的一个插件，把「远程访问 DSH」的能力带到移动端与多端浏览器。当前处于**早期开发阶段（Dev0.1）**：核心链路已经可用且经过本地回归测试，但请把它当作开发版使用，不要在生产环境/公网环境依赖它。

**多端通用**：手机（Android / iOS）通过浏览器打开网页即可使用，无需安装 App；PC 浏览器同样可用；后续会提供原生 App 封装（见更新计划）。

### 当前版本能做什么（Phase 1 – 5.1）

| 能力 | 说明 |
| --- | --- |
| **局域网发现** | 开启广播后，DSH 每 2s 通过 UDP 组播广播实例信息；手机自动发现附近实例（在线/离线状态） |
| **安全配对** | 手机发起配对 → PC 端「New Device Request」确认 → 一次性凭据下发（仅存 SHA-256 哈希）；支持**二维码配对**（`/pair?ticket=...`，单次 60s 有效），无需手输 IP/端口 |
| **Level 1 · 观察者** | 手机只读查看：实例状态、Agent 状态（Idle/Working）、工作区/项目、API 余额、系统负载；SSE 实时推送 + 2s 轮询兜底 |
| **Level 2 · 远程提示词** | PC 端单独将设备升级为 Level 2 后，手机可向 DSH 的**真实 Agent** 发送提示词：服务端新建会话+Agent（默认 preset + 默认模型）→ `followup` 驱动一轮 → 输出经 SSE 实时流回手机；失败时手机显示 `Code: <错误码>` + [Retry] + 部分输出 |
| **审计** | 本地追加式审计日志（`plugin-remote-audit.jsonl`，1MB 滚动），只记录元数据（设备/任务/状态/错误码/时间），**绝不记录提示词内容与凭据** |

### 架构

```
┌────────────┐   UDP 组播 / HTTP(8765)   ┌──────────────┐
│ 手机浏览器   │ ◄──────────────────────► │   DSH (PC)    │
│ mobile.html │                          │ dsh-plugin-remote │
└────────────┘                          └──────────────┘
```

| 文件 | 职责 |
| --- | --- |
| `src/discovery.mjs` | 协议核心（零 Cordis 依赖）：发现、配对、QR 票据、凭据/会话、等级与能力表、限流、Origin 校验、SSE、提示词任务注册表 |
| `src/index.js` | DSH 主机侧胶水：`/api/plugin.remote/*` 路由、真实 DSH 事实（Agent/工作区/余额/系统）、把远程提示词接进**真实 Agent 管线**（`agents.create` 规范路径 + preset + 默认模型） |
| `src/mobile.html` | 手机页面：发现列表、QR 配对、Level 1 观察者、Level 2 远程提示词（增量渲染，输入框缓存不丢焦点） |
| `src/client.js` | PC 浏览器侧：`远程模式 ◯` 胶囊、广播开关、Pair with Phone 二维码、设备管理与等级切换 |
| `src/qr.mjs` | 零依赖 ISO 18004 二维码编码器（SVG 输出） |

**安全模型（不会随版本弱化）**：凭据是唯一授权依据（绝不信任 IP/设备 ID/客户端声称）；Bearer 会话 → 设备 → 等级 → 能力表逐层校验；单次取凭据、票据 60s 一次性；限流与并发上限；跨实例凭据隔离；吊销即失效；发现 ≠ 认证（组播输入永远不可信）。

### 已知安全隐患（Dev0.1，必须知晓）

> ⚠️ **当前版本**：请把局域网视为不可信网络，并仅在可信的私人网络中使用。

- **无 TLS（明文 HTTP）**：手机页面与 API 全部走 HTTP。DSH 主机 WebServer 暂不支持 HTTPS，公共 CA 无法为局域网 IP 签发证书 —— 已分析并记为阻塞项（F-08），详见 README 原文 TLS 章节。
- **手机页面 CORS 全开**：`Access-Control-Allow-Origin: *`，以便一页配对多个实例；依赖 Origin 白名单 + 限流 + PC 端确认来缓解。
- **凭据存于手机 localStorage**：明文凭据只存在于手机浏览器本地存储，服务端仅存 SHA-256；手机丢失/浏览器被入侵等于泄露访问权。
- **发现报文可伪造**：组播发现输入不可信，仅作展示辅助（页面显示 `ID <fingerprint>` 仅为区分，不是凭据）。
- **审计/日志不落凭据**，但**提示词内容会进入 DSH 的会话记录**（远程提示词本身就是发往 Agent 的输入）——请勿通过远程提示词发送机密内容。
- 早期开发：接口与行为可能变更，尚无公网部署/多租户场景验证。

### 更新计划（Roadmap）

| 阶段 | 内容 |
| --- | --- |
| **Level 3 · 控制（进行中）** | 在 Level 1 观察 + Level 2 提示词之上增加受控操作（如安全确认式命令执行、会话控制），继续沿用「PC 端显式授权 + 最小权限」模型 |
| **原生 App（Android/iOS）** | 用 WebView 封装现有网页能力，实现推送通知、后台常驻、证书固定与更强的本地凭据保护（Keychain/Keystore） |
| **TLS / 安全传输** | 原生 App 内建信任模型（mTLS / Noise），解决明文 HTTP 问题；局域网 IP 证书不可行的结论下转向 App 级传输安全 |
| **更多端** | Windows / macOS 桌面端、平板适配、多实例同时管理 |
| **稳定性** | 更完整的实机测试矩阵、错误码体系完善、配额与速率策略可配置化 |

### 快速开始（本地开发）

1. 把插件目录放进 DSH Web profile 的 `node_modules`（或按 DSH 插件加载方式挂载），重启 DSH。
2. WebUI → `远程模式 ◯` → 开启 **Remote Broadcast**。
3. PC 菜单 → **Pair with Phone** → 手机相机扫码 → 配对确认 → 进入 Level 1 观察者。
4. PC 端 Paired Devices → **Change Level** 升到 Level 2 → 手机即可发送远程提示词。

> ⚠️ 主机侧代码（`discovery.mjs` / `index.js`）在 DSH 启动时加载：修改后需**重启 DSH**；`mobile.html` 从磁盘提供，手机刷新即生效。

### 测试

`test/` 下为无外部依赖的回归套件（Node ≥ 20，直接 `node test/<file>.mjs`）：

- `discovery-test.mjs` — 发现协议回归
- `security-test.mjs` — 配对/凭据/会话安全（37 项）
- `audit-test.mjs` — 对抗性审计（43 项）
- `hardening-test.mjs` — 加固（14 项）
- `qr-test.mjs` — 二维码配对（14 项）
- `prompt-test.mjs` — Level 2 鉴权与生命周期（15 项）
- `prompt-runtime-test.mjs` — 5.1 任务失败诊断（R1–R10，10 项）
- `prompt-ui-test.mjs` — 5.1 输入框焦点/错误 UI（U1–U7，7 项）

### 许可证

MIT。

[English](#english) · [中文](#中文)

---

## English

### Introduction

`DSH-mobile-remote-mode-plugin` is a plugin for DSH (DeepSeek Harness) that brings remote access to DSH to mobile and multi-platform browsers. It is currently in **early development (Dev0.1)**: the core flows work and are covered by local regression tests, but treat it as a development build — do not rely on it in production or on public networks.

**Multi-platform**: phones (Android / iOS) use it straight from the browser — no app installation required; PC browsers work too; native apps are planned (see Roadmap).

### What it can do now (Phase 1 – 5.1)

| Capability | Description |
| --- | --- |
| **LAN discovery** | While broadcast is on, DSH announces itself over UDP multicast every 2 s; the phone auto-discovers nearby instances (online/offline) |
| **Secure pairing** | Phone requests pairing → PC confirms ("New Device Request") → one-time credential issued (only its SHA-256 is stored); **QR pairing** (`/pair?ticket=...`, one-time, 60 s) removes the need to type IP/port |
| **Level 1 · Observer** | Read-only: instance status, Agent status (Idle/Working), workspaces/project, API balance, system load; SSE live updates + 2 s polling fallback |
| **Level 2 · Remote Prompt** | After the PC upgrades the device to Level 2, the phone can send prompts to DSH's **real Agent**: a fresh session + agent (default preset + default model) is created, one turn is driven via `followup`, and output streams back over SSE; on failure the phone shows `Code: <error_code>` + [Retry] + partial output |
| **Audit** | Local append-only audit log (`plugin-remote-audit.jsonl`, 1 MB rotate) with metadata only (device/task/status/error_code/time) — **never prompt content or credentials** |

### Architecture

```
┌────────────┐   UDP multicast / HTTP(8765)   ┌──────────────┐
│ Phone      │ ◄────────────────────────────► │   DSH (PC)   │
│ mobile.html│                               │ dsh-plugin-remote │
└────────────┘                               └──────────────┘
```

| File | Role |
| --- | --- |
| `src/discovery.mjs` | Protocol core (no Cordis deps): discovery, pairing, QR tickets, credentials/sessions, level & capability table, rate limits, Origin gate, SSE, prompt-task registry |
| `src/index.js` | DSH host glue: `/api/plugin.remote/*` routes, real DSH facts (Agent/workspaces/balance/system), and the remote-prompt bridge into the **real Agent pipeline** (`agents.create` canonical path + preset + default model) |
| `src/mobile.html` | Phone page: discovery list, QR pairing, Level-1 observer, Level-2 remote prompt (incremental rendering; cached textarea never loses focus) |
| `src/client.js` | PC browser side: `远程模式 ◯` capsule, broadcast toggle, "Pair with Phone" QR, device management & level switching |
| `src/qr.mjs` | Zero-dependency ISO 18004 QR encoder (SVG output) |

**Security model (not to be weakened by future versions)**: the credential is the only authority (IP / device id / client claims are never trusted); Bearer session → device → level → capability table is enforced server-side; one-shot credential pickup, 60 s one-time tickets; rate & concurrency caps; cross-instance credential isolation; revoke kills sessions; discovery ≠ authentication (multicast input is never trusted).

### Known security risks (Dev0.1 — read this)

> ⚠️ **Current version**: treat your LAN as untrusted and only use this on a trusted private network.

- **No TLS (plaintext HTTP)**: the phone page and API are HTTP. DSH's host webserver cannot serve HTTPS today, and public CAs cannot issue certificates for LAN IPs — analyzed and tracked as a blocker (F-08); see the TLS section in the legacy README for the full decision record.
- **Phone page is CORS-open** (`Access-Control-Allow-Origin: *`) so one page can pair with several instances; mitigated by the Origin allowlist, rate limits and PC-side approval.
- **Credentials live in phone localStorage**: the raw credential exists only in the phone's local storage (server stores only the SHA-256). A stolen phone / compromised browser equals access.
- **Discovery packets can be spoofed**: multicast input is untrusted and display-only (`ID <fingerprint>` tags are a disambiguation aid, not a credential).
- Audit/logs never store credentials, but **prompt content enters DSH's session history** (a remote prompt is literally an input to the Agent) — do not send secrets via remote prompts.
- Early development: APIs and behavior may change; no public-network / multi-tenant validation yet.

### Roadmap

| Stage | Content |
| --- | --- |
| **Level 3 · Control (in progress)** | Add supervised operations on top of Level-1 observe + Level-2 prompt (e.g. confirmed command execution, session control), keeping the "PC-side explicit grant + least privilege" model |
| **Native apps (Android / iOS)** | Wrap the existing web capabilities in WebViews: push notifications, background operation, certificate pinning, stronger local credential protection (Keychain/Keystore) |
| **TLS / secure transport** | Solve plaintext HTTP via an in-app trust model (mTLS / Noise) — the conclusion after LAN-IP certificates proved unviable |
| **More platforms** | Windows / macOS desktop, tablet layout, multi-instance management |
| **Stability** | Bigger real-device test matrix, refined error codes, configurable quotas & rate policies |

### Quick start (local development)

1. Put the plugin directory into the DSH Web profile's `node_modules` (or mount it per the DSH plugin loading mechanism) and restart DSH.
2. WebUI → `远程模式 ◯` → enable **Remote Broadcast**.
3. PC menu → **Pair with Phone** → scan the QR with the phone → approve pairing → Level-1 observer.
4. PC Paired Devices → **Change Level** to Level 2 → the phone can now send remote prompts.

> ⚠️ Host-side code (`discovery.mjs` / `index.js`) loads at DSH startup: after editing, **restart DSH**; `mobile.html` is served from disk, so a phone page refresh is enough.

### Tests

The `test/` directory holds a dependency-free regression suite (Node ≥ 20, run with `node test/<file>.mjs`):

- `discovery-test.mjs` — discovery protocol regression
- `security-test.mjs` — pairing/credential/session security (37 checks)
- `audit-test.mjs` — adversarial audit (43 checks)
- `hardening-test.mjs` — hardening (14 checks)
- `qr-test.mjs` — QR pairing (14 checks)
- `prompt-test.mjs` — Level-2 auth & lifecycle (15 checks)
- `prompt-runtime-test.mjs` — 5.1 task-failure diagnostics (R1–R10, 10 checks)
- `prompt-ui-test.mjs` — 5.1 input-focus / error UI (U1–U7, 7 checks)

### License

MIT.

[中文](#中文) · [English](#english)
