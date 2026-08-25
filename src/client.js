/**
 * dsh-plugin-remote — browser (client) half.
 *
 * Loaded by DSH's client module loader as a `window.__ModuleLoader__.load`
 * bundle. Registers one entry in the right-aligned Session Header utilities
 * list (`conversation.session.header.utilities`) — the same additive slot as
 * dsh-plugin-balance — with order -20 so it renders to the LEFT of the balance
 * capsule:
 *
 *     [远程模式 ◯] [余额：12.34￥ ↻]  [Session log]      (zh UI)
 *     [Remote Mode ◯] [Balance: 12.34￥ ↻]  [Session log] (en UI)
 *
 * The capsule mirrors the balance geometry (32px pill, 13px font, 18px radius)
 * and shows "远程模式" followed by a hollow circle:
 *   - red hollow circle  -> Remote Broadcast OFF (default)
 *   - green hollow circle -> Remote Broadcast ON
 *
 * Clicking the capsule opens the secondary menu, which shows the instance
 * status (name, broadcast port, LAN IP) and the single "Remote Broadcast"
 * toggle button that actually starts/stops the LAN broadcast. The host routes
 * (/api/plugin.remote/*) do the real work; the browser only polls status.
 */

window.__ModuleLoader__.load({
  id: "dsh-plugin-remote",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;

    var react = require("react");

    // ------------------------------------------------------------- styles
    const css =
      ".dsh-remote-wrap{position:relative;display:inline-flex}" +
      ".dsh-remote-header{display:inline-flex;align-items:center;gap:6px;height:32px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));border-radius:18px;padding:6px 12px;font-family:var(--dsw-font-family,inherit);font-size:13px;font-weight:400;line-height:20px;color:var(--dsw-alias-label-primary,inherit);background:transparent;white-space:nowrap;cursor:pointer}" +
      ".dsh-remote-header:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-header:active{background:rgba(128,128,128,.28)}" +
      ".dsh-remote-text{white-space:nowrap}" +
      ".dsh-remote-dot{flex:none;width:9px;height:9px;box-sizing:border-box;border-radius:50%;border:2px solid var(--dsw-alias-state-error-primary,#e5484d);background:transparent}" +
      ".dsh-remote-dot.on{border-color:var(--dsw-alias-state-success-primary,#46a758)}" +
      ".dsh-remote-menu{position:fixed;z-index:1200;min-width:252px;background:var(--dsw-alias-bg-overlay,#fff);border:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.2));border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.22);padding:10px;font-size:13px;color:var(--dsw-alias-label-primary,inherit);font-family:var(--dsw-font-family,inherit)}" +
      ".dsh-remote-menu-title{display:flex;align-items:center;justify-content:space-between;font-weight:600;font-size:13px;margin-bottom:6px}" +
      ".dsh-remote-badge{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:500;color:var(--dsw-alias-label-secondary,inherit)}" +
      ".dsh-remote-badge .dot{width:8px;height:8px;box-sizing:border-box;border-radius:50%;border:2px solid var(--dsw-alias-state-error-primary,#e5484d);background:transparent}" +
      ".dsh-remote-badge.on .dot{border-color:var(--dsw-alias-state-success-primary,#46a758)}" +
      ".dsh-remote-row{display:flex;align-items:center;gap:8px;padding:5px 4px}" +
      ".dsh-remote-row .label{flex:none;width:74px;color:var(--dsw-alias-label-secondary,inherit);font-size:12.5px}" +
      ".dsh-remote-row .value{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums}" +
      ".dsh-remote-input{flex:1;min-width:0;height:26px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));border-radius:7px;background:transparent;color:inherit;font:inherit;font-size:12.5px;padding:0 8px}" +
      ".dsh-remote-input:focus{outline:none;border-color:var(--dsw-alias-brand-primary,#4c6ef5)}" +
      ".dsh-remote-save{flex:none;height:26px;padding:0 10px;border-radius:7px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));background:transparent;color:inherit;font:inherit;font-size:12.5px;cursor:pointer}" +
      ".dsh-remote-save:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-save:disabled{opacity:.5;cursor:default}" +
      ".dsh-remote-saved{color:var(--dsw-alias-state-success-primary,#46a758);font-size:11.5px;padding:0 4px}" +
      ".dsh-remote-toggle{display:flex;align-items:center;justify-content:space-between;width:100%;margin-top:6px;padding:9px 10px;border-radius:9px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));background:transparent;color:inherit;font:inherit;font-size:13px;cursor:pointer}" +
      ".dsh-remote-toggle:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-toggle .t{font-weight:600}" +
      ".dsh-remote-toggle .s{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--dsw-alias-label-secondary,inherit)}" +
      ".dsh-remote-toggle .s .dot{width:8px;height:8px;box-sizing:border-box;border-radius:50%;border:2px solid var(--dsw-alias-state-error-primary,#e5484d);background:transparent}" +
      ".dsh-remote-toggle .s.on .dot{border-color:var(--dsw-alias-state-success-primary,#46a758)}" +
      ".dsh-remote-hint{color:var(--dsw-alias-label-secondary,inherit);font-size:11.5px;padding:6px 4px 2px;line-height:1.5}" +
      ".dsh-remote-count{flex:none;min-width:15px;height:15px;box-sizing:border-box;border-radius:999px;background:var(--dsw-alias-state-error-primary,#e5484d);color:#fff;font-size:10px;line-height:15px;text-align:center;padding:0 4px;font-weight:600}" +
      ".dsh-remote-sec{margin-top:8px;border-top:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.18));padding-top:7px}" +
      ".dsh-remote-sec-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--dsw-alias-label-secondary,inherit);margin:2px 4px 5px}" +
      ".dsh-remote-dev{padding:6px 4px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.12))}" +
      ".dsh-remote-dev:last-child{border-bottom:none}" +
      ".dsh-remote-dev .n{font-weight:600;font-size:12.5px;display:flex;align-items:center;gap:6px}" +
      ".dsh-remote-dev .d{color:var(--dsw-alias-label-secondary,inherit);font-size:11.5px;margin-top:2px}" +
      ".dsh-remote-dev .b{display:flex;gap:6px;margin-top:6px}" +
      ".dsh-remote-dev .b button{flex:1;height:24px;border-radius:7px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));background:transparent;color:inherit;font:inherit;font-size:12px;cursor:pointer}" +
      ".dsh-remote-dev .b button:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-dev .b button.accept{color:var(--dsw-alias-state-success-primary,#46a758)}" +
      ".dsh-remote-dev .b button.reject{color:var(--dsw-alias-state-error-primary,#e5484d)}" +
      ".dsh-remote-dev .b button.revoke{color:var(--dsw-alias-state-error-primary,#e5484d)}" +
      ".dsh-remote-dev .l1{flex:none;font-size:10.5px;color:var(--dsw-alias-state-success-primary,#46a758);border:1px solid color-mix(in srgb,var(--dsw-alias-state-success-primary,#46a758) 50%,transparent);border-radius:999px;padding:0 6px;line-height:14px}" +
      ".dsh-remote-empty{color:var(--dsw-alias-label-secondary,inherit);font-size:12px;padding:4px}" +
      ".dsh-remote-qrbtn{display:flex;align-items:center;justify-content:space-between;width:100%;margin-top:6px;padding:9px 10px;border-radius:9px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));background:transparent;color:inherit;font:inherit;font-size:13px;cursor:pointer}" +
      ".dsh-remote-qrbtn:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-qrbtn .t{font-weight:600}" +
      ".dsh-remote-qrbtn:disabled{opacity:.5;cursor:default}" +
      ".dsh-remote-qrpop{position:fixed;z-index:1400;top:50%;left:50%;transform:translate(-50%,-50%);width:min(320px,86vw);background:var(--dsw-alias-bg-overlay,#fff);border:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.2));border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.3);padding:16px;font-size:13px;color:var(--dsw-alias-label-primary,inherit);font-family:var(--dsw-font-family,inherit);text-align:center}" +
      ".dsh-remote-qrpop .title{font-weight:700;font-size:14px;margin-bottom:10px}" +
      ".dsh-remote-qrpop .qrbox{background:#fff;border-radius:10px;padding:10px;margin:0 auto 10px;width:220px;height:220px;display:flex;align-items:center;justify-content:center}" +
      ".dsh-remote-qrpop .qrbox svg{width:200px;height:200px;display:block}" +
      ".dsh-remote-qrpop .meta{color:var(--dsw-alias-label-secondary,inherit);font-size:12px;line-height:1.6}" +
      ".dsh-remote-qrpop .expire{font-size:12px;margin:8px 0 12px}" +
      ".dsh-remote-qrpop .expire b{font-variant-numeric:tabular-nums}" +
      ".dsh-remote-qrpop .err{color:var(--dsw-alias-state-error-primary,#e5484d);font-size:12.5px;margin:10px 0}" +
      ".dsh-remote-qrpop .act{display:flex;gap:8px}" +
      ".dsh-remote-qrpop .act button{flex:1;height:30px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.25));background:transparent;color:inherit;font:inherit;font-size:12.5px;cursor:pointer}" +
      ".dsh-remote-qrpop .act button:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.15))}" +
      ".dsh-remote-qrpop .act button.primary{background:var(--dsw-alias-brand-primary,#4c6ef5);border-color:var(--dsw-alias-brand-primary,#4c6ef5);color:#fff}" +
      ".dsh-remote-qrshade{position:fixed;inset:0;z-index:1300;background:rgba(0,0,0,.35)}" +
      ".dsh-remote-dev .l2{flex:none;font-size:10.5px;color:var(--dsw-alias-state-warn-primary,#d29922);border:1px solid color-mix(in srgb,var(--dsw-alias-state-warn-primary,#d29922) 50%,transparent);border-radius:999px;padding:0 6px;line-height:14px;font-weight:600}";
    const tagId = "dsh-plugin-remote/remote.css";
    if (
      typeof document !== "undefined" &&
      document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null
    ) {
      const tag = document.createElement("style");
      tag.dataset.plugin = "dsh-plugin-remote";
      tag.dataset.pluginCss = tagId;
      tag.textContent = css;
      document.head.appendChild(tag);
    }

    // ------------------------------------------------------------ locale
    const NS = "remote";

    /** Simplified Chinese dictionary (key-set source of truth). */
    const zh = {
      "label": "远程模式",
      "menuTitle": "DSH Remote",
      "badgeOn": "广播中",
      "badgeOff": "已关闭",
      "nameLabel": "实例名称",
      "save": "保存",
      "saved": "已保存",
      "statusLabel": "状态",
      "statusOn": "开启",
      "statusOff": "关闭",
      "portLabel": "广播端口",
      "ipLabel": "局域网 IP",
      "noPort": "—",
      "toggleName": "Remote Broadcast",
      "toggleOn": "Disable",
      "toggleOff": "Enable",
      "hint": "开启后，同一局域网内的手机浏览器可自动发现本机（http://本机IP:端口）",
      "requests": "配对请求",
      "noRequests": "暂无配对请求",
      "newRequest": "新设备请求",
      "deviceLabel": "设备",
      "requestLevel": "请求权限",
      "accept": "接受",
      "reject": "拒绝",
      "pairedDevices": "已配对设备",
      "noDevices": "暂无已配对设备",
      "revoke": "撤销",
      "level1": "Level 1 — Observer",
      "lastSeen": "最近在线",
      "ago": "前",
      "pairWithPhone": "Pair with Phone",
      "qrTitle": "Pair with Phone",
      "qrHint": "用手机相机扫描，自动打开配对页",
      "qrExpires": "有效时间",
      "qrClose": "关闭",
      "qrExpired": "二维码已过期",
      "qrRegenerate": "重新生成",
      "qrError": "生成失败：请先开启 Remote Broadcast",
      "qrOpen": "扫码配对",
      "level2": "Level 2 — Remote Prompt",
      "changeLevel": "Change Level"
    };

    /** English dictionary, checked complete against the zh key set. */
    const en = {
      "label": "Remote Mode",
      "menuTitle": "DSH Remote",
      "badgeOn": "Broadcasting",
      "badgeOff": "Off",
      "nameLabel": "Instance name",
      "save": "Save",
      "saved": "Saved",
      "statusLabel": "Status",
      "statusOn": "On",
      "statusOff": "Off",
      "portLabel": "Broadcast port",
      "ipLabel": "LAN IP",
      "noPort": "—",
      "toggleName": "Remote Broadcast",
      "toggleOn": "Disable",
      "toggleOff": "Enable",
      "hint": "When enabled, phones on the same LAN can auto-discover this machine (http://this-ip:port)",
      "requests": "Pairing Requests",
      "noRequests": "No pairing requests",
      "newRequest": "New Device Request",
      "deviceLabel": "Device",
      "requestLevel": "Request",
      "accept": "Accept",
      "reject": "Reject",
      "pairedDevices": "Paired Devices",
      "noDevices": "No paired devices",
      "revoke": "Revoke",
      "level1": "Level 1 — Observer",
      "lastSeen": "Last seen",
      "ago": "ago",
      "pairWithPhone": "Pair with Phone",
      "qrTitle": "Pair with Phone",
      "qrHint": "Scan with your phone camera to open the pairing page",
      "qrExpires": "Expires in",
      "qrClose": "Close",
      "qrExpired": "QR code expired",
      "qrRegenerate": "Generate new",
      "qrError": "Failed: enable Remote Broadcast first",
      "qrOpen": "Scan QR to pair",
      "level2": "Level 2 — Remote Prompt",
      "changeLevel": "Change Level"
    };

    // ------------------------------------------------------------- capsule
    const STATUS_ROUTE = "/api/plugin.remote/status";

    /**
     * The header capsule + secondary menu. State is polled from the host so
     * the hollow circle always reflects the real broadcast state.
     */
    function RemoteCapsule(props) {
      const t = props.t;
      const [open, setOpen] = react.useState(false);
      const [status, setStatus] = react.useState(null);
      const [nameDraft, setNameDraft] = react.useState("");
      const [saving, setSaving] = react.useState(false);
      const [savedFlash, setSavedFlash] = react.useState(false);
      const [menuPos, setMenuPos] = react.useState(null);
      const wrapRef = react.useState({ current: null })[0];
      const inputRef = react.useState({ current: null })[0];
      const flashTimer = react.useState({ current: null })[0];

      const refreshStatus = () => {
        fetch(STATUS_ROUTE, {
          method: "GET",
          headers: { accept: "application/json" },
          cache: "no-store",
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            if (res && res.ok) setStatus(res);
          })
          .catch(() => {});
      };

      react.useEffect(() => {
        refreshStatus();
        const id = setInterval(refreshStatus, 3000);
        return () => {
          clearInterval(id);
          if (flashTimer.current) clearTimeout(flashTimer.current);
        };
      }, []);

      // Keep the draft in sync with the server unless the user is typing.
      react.useEffect(() => {
        if (status && document.activeElement !== inputRef.current) {
          setNameDraft(status.instance_name || "");
        }
      }, [status]);

      // Close on outside click while the menu is open.
      react.useEffect(() => {
        if (!open) return;
        const onDown = (e) => {
          if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
        };
        document.addEventListener("mousedown", onDown);
        return () => document.removeEventListener("mousedown", onDown);
      }, [open]);

      const openMenu = (e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        setMenuPos({
          top: rect.bottom + 6,
          right: (window.innerWidth || 0) - rect.right,
        });
        setOpen(!open);
      };

      const toggleBroadcast = () => {
        const action = status && status.enabled ? "disable" : "enable";
        fetch("/api/plugin.remote/" + action, {
          method: "POST",
          headers: { accept: "application/json" },
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            if (res && res.ok) setStatus(res);
          })
          .catch(() => {});
      };

      const saveName = () => {
        const name = (nameDraft || "").trim();
        if (!name || saving) return;
        setSaving(true);
        fetch("/api/plugin.remote/name", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ name }),
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            setSaving(false);
            if (res && res.ok) {
              setStatus(res);
              setNameDraft(res.instance_name || "");
              setSavedFlash(true);
              if (flashTimer.current) clearTimeout(flashTimer.current);
              flashTimer.current = setTimeout(() => setSavedFlash(false), 1600);
            }
          })
          .catch(() => setSaving(false));
      };

      const pairAction = (action, deviceId) => {
        fetch("/api/plugin.remote/pair/" + action, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ device_id: deviceId }),
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            if (res && res.ok) refreshStatus();
          })
          .catch(() => {});
      };
      // Phase 5: PC-side access-level change (Level 1 <-> Level 2).
      const pairLevel = (deviceId, nextLevel) => {
        fetch("/api/plugin.remote/pair/level", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ device_id: deviceId, level: nextLevel }),
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            if (res && res.ok) refreshStatus();
          })
          .catch(() => {});
      };

      // Phase 4: one-time QR pairing ticket + popup.
      const [qr, setQr] = react.useState(null); // { url, qr_svg, instance_name, lan_ip, port, expires_at_ms } | { error: true }
      const [qrLeft, setQrLeft] = react.useState(0);
      const openQr = () => {
        fetch("/api/plugin.remote/pair/ticket", {
          method: "POST",
          headers: { accept: "application/json" },
        })
          .then((res) => res.json().catch(() => null))
          .then((res) => {
            if (res && res.ok) {
              setQr(res);
              setQrLeft(Math.max(0, Math.round((res.expires_at_ms - Date.now()) / 1000)));
            } else {
              setQr({ error: true });
              setQrLeft(0);
            }
          })
          .catch(() => setQr({ error: true }));
      };
      const closeQr = () => {
        setQr(null);
        setQrLeft(0);
      };
      const qrLeftRef = react.useState({ current: 0 })[0];
      react.useEffect(() => {
        if (!qr || qr.error) return;
        qrLeftRef.current = Math.max(0, Math.round((qr.expires_at_ms - Date.now()) / 1000));
        setQrLeft(qrLeftRef.current);
        const id = setInterval(() => {
          const left = qr ? Math.max(0, Math.round((qr.expires_at_ms - Date.now()) / 1000)) : 0;
          qrLeftRef.current = left;
          setQrLeft(left);
        }, 1000);
        return () => clearInterval(id);
      }, [qr]);

      const enabled = Boolean(status && status.enabled);
      const pairs = status && status.pairs ? status.pairs : { pending: [], paired: [] };
      const pendingCount = pairs.pending.length;
      const pairedList = pairs.paired || [];
      const now = Date.now();
      const fmtAgo = (ms) => {
        if (!ms) return t("noPort");
        const sec = Math.max(1, Math.round((now - ms) / 1000));
        if (sec < 60) return sec + "s";
        if (sec < 3600) return Math.round(sec / 60) + "m";
        return Math.round(sec / 3600) + "h";
      };

      return react.createElement(
        "div",
        { className: "dsh-remote-wrap", ref: wrapRef },
        react.createElement(
          "button",
          {
            type: "button",
            className: "dsh-remote-header",
            title: t("menuTitle"),
            onClick: openMenu,
          },
          react.createElement("span", { className: "dsh-remote-text" }, t("label")),
          react.createElement("span", {
            className: "dsh-remote-dot" + (enabled ? " on" : ""),
            "aria-hidden": true,
          }),
          pendingCount > 0
            ? react.createElement(
                "span",
                { className: "dsh-remote-count", title: pendingCount + " " + t("requests") },
                String(pendingCount),
              )
            : null,
        ),
        open &&
          menuPos &&
          react.createElement(
            "div",
            { className: "dsh-remote-menu", style: { top: menuPos.top, right: menuPos.right } },
            react.createElement(
              "div",
              { className: "dsh-remote-menu-title" },
              t("menuTitle"),
              react.createElement(
                "span",
                { className: "dsh-remote-badge" + (enabled ? " on" : "") },
                react.createElement("span", { className: "dot" }),
                enabled ? t("badgeOn") : t("badgeOff"),
              ),
            ),
            react.createElement(
              "div",
              { className: "dsh-remote-row" },
              react.createElement("span", { className: "label" }, t("nameLabel")),
              react.createElement("input", {
                ref: inputRef,
                className: "dsh-remote-input",
                value: nameDraft,
                onChange: (e) => setNameDraft(e.target.value),
                onKeyDown: (e) => {
                  if (e.key === "Enter") saveName();
                },
              }),
              savedFlash
                ? react.createElement("span", { className: "dsh-remote-saved" }, t("saved"))
                : react.createElement(
                    "button",
                    {
                      type: "button",
                      className: "dsh-remote-save",
                      onClick: saveName,
                      disabled: saving,
                    },
                    t("save"),
                  ),
            ),
            react.createElement(
              "div",
              { className: "dsh-remote-row" },
              react.createElement("span", { className: "label" }, t("statusLabel")),
              react.createElement("span", { className: "value" }, enabled ? t("statusOn") : t("statusOff")),
            ),
            react.createElement(
              "div",
              { className: "dsh-remote-row" },
              react.createElement("span", { className: "label" }, t("portLabel")),
              react.createElement(
                "span",
                { className: "value" },
                enabled && status && status.port ? String(status.port) : t("noPort"),
              ),
            ),
            react.createElement(
              "div",
              { className: "dsh-remote-row" },
              react.createElement("span", { className: "label" }, t("ipLabel")),
              react.createElement(
                "span",
                { className: "value" },
                enabled && status && status.lan_ip ? String(status.lan_ip) : t("noPort"),
              ),
            ),
            react.createElement(
              "button",
              { type: "button", className: "dsh-remote-toggle", onClick: toggleBroadcast },
              react.createElement("span", { className: "t" }, t("toggleName")),
              react.createElement(
                "span",
                { className: "s" + (enabled ? " on" : "") },
                react.createElement("span", { className: "dot" }),
                enabled ? t("toggleOn") : t("toggleOff"),
              ),
            ),
            react.createElement(
              "button",
              {
                type: "button",
                className: "dsh-remote-qrbtn",
                onClick: openQr,
                disabled: !enabled,
                title: enabled ? t("qrHint") : t("qrError"),
              },
              react.createElement("span", { className: "t" }, t("pairWithPhone")),
              react.createElement("span", { className: "s" }, t("qrOpen")),
            ),
            react.createElement("div", { className: "dsh-remote-hint" }, t("hint")),
            react.createElement(
              "div",
              { className: "dsh-remote-sec" },
              react.createElement("div", { className: "dsh-remote-sec-title" }, t("requests")),
              pairs.pending.length === 0
                ? react.createElement("div", { className: "dsh-remote-empty" }, t("noRequests"))
                : pairs.pending.map((req) =>
                    react.createElement(
                      "div",
                      { className: "dsh-remote-dev", key: req.device_id },
                      react.createElement(
                        "div",
                        { className: "n" },
                        t("newRequest"),
                        react.createElement("span", { className: "l1" }, t("level1")),
                      ),
                      react.createElement(
                        "div",
                        { className: "d" },
                        t("deviceLabel") + ": " + req.device_name,
                      ),
                      react.createElement(
                        "div",
                        { className: "b" },
                        react.createElement(
                          "button",
                          {
                            type: "button",
                            className: "accept",
                            onClick: () => pairAction("accept", req.device_id),
                          },
                          t("accept"),
                        ),
                        react.createElement(
                          "button",
                          {
                            type: "button",
                            className: "reject",
                            onClick: () => pairAction("reject", req.device_id),
                          },
                          t("reject"),
                        ),
                      ),
                    ),
                  ),
            ),
            react.createElement(
              "div",
              { className: "dsh-remote-sec" },
              react.createElement("div", { className: "dsh-remote-sec-title" }, t("pairedDevices")),
              pairedList.length === 0
                ? react.createElement("div", { className: "dsh-remote-empty" }, t("noDevices"))
                : pairedList.map((dev) =>
                    react.createElement(
                      "div",
                      { className: "dsh-remote-dev", key: dev.device_id },
                      react.createElement(
                        "div",
                        { className: "n" },
                        dev.device_name,
                        react.createElement(
                          "span",
                          { className: dev.level === 2 ? "l2" : "l1" },
                          dev.level === 2 ? t("level2") : t("level1"),
                        ),
                      ),
                      react.createElement(
                        "div",
                        { className: "d" },
                        t("lastSeen") + ": " + fmtAgo(dev.last_seen_ms) + " " + t("ago"),
                      ),
                      react.createElement(
                        "div",
                        { className: "b" },
                        react.createElement(
                          "button",
                          {
                            type: "button",
                            className: "accept",
                            onClick: () => pairLevel(dev.device_id, dev.level === 2 ? 1 : 2),
                          },
                          t("changeLevel"),
                        ),
                        react.createElement(
                          "button",
                          {
                            type: "button",
                            className: "revoke",
                            onClick: () => pairAction("revoke", dev.device_id),
                          },
                          t("revoke"),
                        ),
                      ),
                    ),
                  ),
            ),
          ),
        qr &&
          react.createElement(
            react.Fragment,
            null,
            react.createElement("div", {
              className: "dsh-remote-qrshade",
              onClick: closeQr,
            }),
            react.createElement(
              "div",
              { className: "dsh-remote-qrpop" },
              react.createElement("div", { className: "title" }, t("qrTitle")),
              qr.error
                ? react.createElement("div", { className: "err" }, t("qrError"))
                : react.createElement(
                    react.Fragment,
                    null,
                    react.createElement(
                      "div",
                      { className: "qrbox" },
                      qrLeft > 0
                        ? react.createElement("div", {
                            className: "qrbox",
                            dangerouslySetInnerHTML: { __html: qr.qr_svg },
                          })
                        : react.createElement("div", { className: "err" }, t("qrExpired")),
                    ),
                    react.createElement(
                      "div",
                      { className: "meta" },
                      qr.instance_name + " · " + qr.lan_ip + ":" + qr.port,
                    ),
                    react.createElement(
                      "div",
                      { className: "expire" },
                      qrLeft > 0
                        ? react.createElement(
                            "span",
                            null,
                            t("qrExpires") + ": ",
                            react.createElement("b", null, qrLeft + "s"),
                          )
                        : null,
                    ),
                  ),
              qr.error
                ? react.createElement(
                    "div",
                    { className: "act" },
                    react.createElement(
                      "button",
                      { type: "button", onClick: closeQr },
                      t("qrClose"),
                    ),
                  )
                : react.createElement(
                    "div",
                    { className: "act" },
                    qrLeft > 0
                      ? react.createElement(
                          "button",
                          { type: "button", onClick: closeQr },
                          t("qrClose"),
                        )
                      : react.createElement(
                          react.Fragment,
                          null,
                          react.createElement(
                            "button",
                            { type: "button", className: "primary", onClick: openQr },
                            t("qrRegenerate"),
                          ),
                          react.createElement(
                            "button",
                            { type: "button", onClick: closeQr },
                            t("qrClose"),
                          ),
                        ),
                  ),
            ),
          ),
      );
    }

    // ------------------------------------------------------------ plugin body
    /** Services required by the client plugin. */
    const inject = ["slots", "locale"];

    /**
     * Client plugin body: register the dictionaries and the header capsule.
     */
    function apply(ctx) {
      ctx.effect(
        () => ctx.locale.register(NS, { zh, en }),
        "dsh-plugin-remote: dictionaries",
      );
      ctx.slots.inject("conversation.session.header.utilities", () =>
        ctx.slots.register(
          {
            name: "conversation.session.header.utilities",
            id: "dsh-remote",
            order: -20,
            locale: NS,
          },
          RemoteCapsule,
        ),
      );
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  },
});
