/* Sentinel console. Vanilla JS, no build step, strict CSP (no inline script).
   All server data is inserted with textContent via el(): agent-supplied
   strings are untrusted and must never reach innerHTML. */
"use strict";

const state = { config: null, token: null, user: null };

// ------------------------------------------------------------------ DOM
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
const svgNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs, ...kids) {
  const n = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  for (const c of kids.flat()) if (c) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}
const badge = (v, label) => el("span", { class: `v v-${v}` }, label || title(v));
const title = (s) => (s || "").toString().charAt(0) + (s || "").toString().slice(1).toLowerCase().replaceAll("_", " ");
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
const when = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "—";
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 3500);
}
function view(...kids) {
  const v = document.getElementById("view");
  v.replaceChildren(...kids.flat());
}
const empty = (msg) => el("div", { class: "panel empty" }, msg);

// ------------------------------------------------------------------ auth
async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return btoa(String.fromCharCode(...new Uint8Array(d))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function rand() {
  const a = new Uint8Array(32); crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const redirectUri = () => location.origin + "/";

async function login() {
  const c = state.config, verifier = rand(), st = rand();
  sessionStorage.setItem("pkce", JSON.stringify({ verifier, st, hash: location.hash }));
  const q = new URLSearchParams({
    response_type: "code", client_id: c.clientId, redirect_uri: redirectUri(),
    scope: "openid email profile", state: st,
    code_challenge: await sha256(verifier), code_challenge_method: "S256",
  });
  location.assign(`${c.cognitoDomain}/oauth2/authorize?${q}`);
}
function logout() {
  sessionStorage.removeItem("tok");
  if (state.config.auth !== "cognito") return location.reload();
  const q = new URLSearchParams({ client_id: state.config.clientId, logout_uri: redirectUri() });
  location.assign(`${state.config.cognitoDomain}/logout?${q}`);
}
function decodeJwt(t) {
  try { return JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); } catch { return {}; }
}
async function initAuth() {
  if (state.config.auth !== "cognito") { state.user = { email: "local developer", groups: ["local"] }; return true; }
  const params = new URLSearchParams(location.search);
  if (params.get("code")) {
    const saved = JSON.parse(sessionStorage.getItem("pkce") || "{}");
    if (saved.st !== params.get("state")) throw new Error("Sign-in state mismatch. Sign in again.");
    const r = await fetch(`${state.config.cognitoDomain}/oauth2/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: state.config.clientId,
        code: params.get("code"), redirect_uri: redirectUri(), code_verifier: saved.verifier }),
    });
    if (!r.ok) throw new Error("Sign-in failed. Sign in again.");
    const tok = await r.json();
    sessionStorage.setItem("tok", JSON.stringify({ id: tok.id_token, exp: Date.now() / 1000 + tok.expires_in - 60 }));
    history.replaceState(null, "", "/" + (saved.hash || "#/overview"));
  }
  const tok = JSON.parse(sessionStorage.getItem("tok") || "null");
  if (!tok || tok.exp < Date.now() / 1000) { await login(); return false; }
  state.token = tok.id;
  const claims = decodeJwt(tok.id);
  state.user = { email: claims.email, groups: claims["cognito:groups"] || [] };
  return true;
}
const canApprove = () => state.user.groups.some((g) => ["local", "sentinel-admins", "sentinel-approvers"].includes(g));

// ------------------------------------------------------------------- API
async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = state.token;
  const r = await fetch(state.config.apiUrl + path, {
    method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401) { sessionStorage.removeItem("tok"); await login(); throw new Error("Session expired"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

// ---------------------------------------------------------- shared bits
function promptReason(heading, label, confirmLabel, cls) {
  return new Promise((resolve) => {
    const d = document.getElementById("dialog");
    const ta = el("textarea", { id: "reason", required: true });
    const form = el("form", { method: "dialog" },
      el("h2", {}, heading),
      el("label", { for: "reason", class: "small muted" }, label), ta,
      el("div", { class: "actions" },
        el("button", { type: "button", onclick: () => { d.close(); resolve(null); } }, "Cancel"),
        el("button", { type: "submit", class: cls }, confirmLabel)));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (cls !== "approve" && !ta.value.trim()) { ta.focus(); return; }
      d.close(); resolve(ta.value.trim());
    });
    d.replaceChildren(form); d.showModal(); ta.focus();
  });
}

async function resolveHold(ap, approve) {
  const note = await promptReason(
    approve ? "Approve this held action?" : "Reject this held action?",
    approve ? "Note for the audit trail (optional)" : "Reason (required, recorded in the audit trail)",
    approve ? "Approve action" : "Reject action", approve ? "approve" : "reject");
  if (note === null) return;
  try {
    await api(`/v1/approvals/${encodeURIComponent(ap.approval_id)}/${approve ? "approve" : "reject"}`,
      { method: "POST", body: { comment: note } });
    toast(approve ? "Action approved. The agent will continue." : "Action rejected. The agent was told to stop.");
    route();
  } catch (e) { toast(e.message); }
}

function holdRow(ap) {
  const ev = ap.event || {};
  const left = ap.expires_at - Date.now() / 1000;
  return el("div", { class: "row", dataset: { rail: "PENDING" } },
    el("div", { class: "row-top" },
      el("span", { class: "row-title" }, `${ap.agent_id} wants to ${ev.action || "act"} ${ev.resource ? "" : ev.tool || ""}`),
      badge(ap.severity)),
    ev.resource && el("div", { class: "mono", style: "margin-top:4px" }, ev.resource),
    el("ul", { class: "findings" }, (ap.findings || []).filter((f) => f.severity !== "INFO").slice(0, 4)
      .map((f) => el("li", {}, el("strong", {}, f.title), ` — ${f.detail}`))),
    el("div", { class: "row-meta" },
      ev.task_id && el("span", {}, `Task ${ev.task_id}`),
      el("span", {}, `Held ${ago(ap.created_at)}`),
      el("span", {}, left > 0 ? `Auto-rejects in ${Math.ceil(left / 60)} min` : "Expired")),
    canApprove() && el("div", { class: "actions" },
      el("button", { class: "approve", onclick: () => resolveHold(ap, true) }, "Approve action"),
      el("button", { class: "reject", onclick: () => resolveHold(ap, false) }, "Reject action")));
}

function decisionRow(d) {
  const ev = d.event || {};
  const real = (d.findings || []).filter((f) => f.severity !== "INFO");
  return el("div", { class: "row", dataset: { rail: d.verdict === "ALLOW" && d.mode !== "LOG" ? "FLAG" : d.verdict } },
    el("div", { class: "row-top" },
      el("span", { class: "row-title" }, `${d.agent_id} · ${ev.action || ""}`),
      el("span", {}, badge(d.verdict === "ALLOW" ? (d.mode === "LOG" ? "ALLOW" : "FLAG") : d.verdict,
        d.verdict === "ALLOW" ? (d.mode === "LOG" ? "Allowed" : "Allowed, flagged") :
          d.mode === "QUARANTINE" ? "Blocked, agent quarantined" : d.verdict === "HOLD" ? "Held" : "Blocked"))),
    ev.resource && el("div", { class: "mono", style: "margin-top:4px" }, ev.resource),
    real.length > 0 && el("ul", { class: "findings" }, real.slice(0, 4).map((f) =>
      el("li", {}, el("strong", {}, f.title), ` — ${f.detail}`))),
    el("div", { class: "row-meta" },
      el("span", {}, when(d.timestamp)),
      ev.source && ev.source !== "sdk" && el("span", {}, `via ${ev.source}`),
      ev.task_id && el("span", {}, `Task ${ev.task_id}`),
      el("span", {}, `${d.latency_ms} ms`)));
}

// ---------------------------------------------------------------- views
async function vOverview() {
  const [o, held] = await Promise.all([api("/v1/overview"), api("/v1/approvals?status=PENDING")]);
  const n = held.approvals.length;
  const decide = el("section", { class: "decide" + (n ? "" : " clear") },
    el("div", { class: "decide-head" }, el("strong", {}, String(n)),
      el("span", {}, n === 1 ? "agent action is waiting for your decision" :
        n ? "agent actions are waiting for your decision" : "No agent actions are waiting for a decision")),
    n ? el("div", { class: "rows" }, held.approvals.slice(0, 3).map(holdRow)) :
      el("p", { class: "muted small", style: "margin:0" }, "High-risk actions pause here until someone approves or rejects them."),
    n > 3 && el("p", {}, el("a", { href: "#/approvals" }, `See all ${n} held actions`)));

  const facts = el("div", { class: "facts section" },
    fact(o.agents.total, "agents monitored"),
    fact(o.agents.quarantined, "quarantined", o.agents.quarantined > 0),
    fact(o.decisions_24h.blocked, "blocked today", o.decisions_24h.blocked > 0),
    fact(o.open_alerts.total, "open alerts", (o.open_alerts.by_severity.CRITICAL || 0) > 0),
    fact(o.decisions_24h.total, "actions checked today"),
    fact(`${o.decisions_24h.p95_latency_ms} ms`, "p95 decision time"));

  return [
    el("h1", {}, "Overview"),
    el("p", { class: "lede" }, "What your AI agents did in the last 24 hours, and what needs a human."),
    decide, facts,
    el("div", { class: "grid2 section" },
      el("div", { class: "panel panel-pad" }, el("h2", {}, "Agent actions per hour"), timeline(o.timeline)),
      el("div", { class: "panel panel-pad" }, el("h2", {}, "Compliance readiness"),
        Object.entries(o.compliance).map(([k, v]) => fwRow(FW_SHORT[k] || v.framework, v.score)),
        el("p", { class: "small muted" }, `${o.controls.passing} of ${o.controls.total} controls passing · `,
          el("a", { href: "#/compliance" }, "Open compliance")))),
  ];
}
const FW_SHORT = { SOC2: "SOC 2", ISO27001: "ISO 27001", ISO42001: "ISO 42001 (AI)", PCIDSS: "PCI DSS 4.0", NISTAIRMF: "NIST AI RMF" };
const fact = (v, label, bad) => el("div", { class: "fact" + (bad ? " bad" : "") }, el("b", {}, String(v)), el("span", {}, label));
function fwRow(name, score) {
  return el("div", { class: "fw" }, el("span", { class: "small" }, name),
    el("div", { class: "bar", role: "img", "aria-label": `${score}%` },
      el("span", { style: `width:${score}%;background:var(${score >= 90 ? "--allow" : score >= 70 ? "--flag" : "--block"})` })),
    el("b", {}, `${score}%`));
}
function timeline(raw) {
  if (!raw.length) return el("p", { class: "muted" }, "No agent activity yet. Actions appear here as soon as agents call Sentinel.");
  // 24 hourly slots ending now, so one busy hour reads as one bar, not the whole chart
  const nowH = Math.floor(Date.now() / 3600000) * 3600, byHour = new Map(raw.map((p) => [p.hour, p]));
  const points = Array.from({ length: 24 }, (_, i) => {
    const h = nowH - (23 - i) * 3600;
    return byHour.get(h) || { hour: h, allowed: 0, flagged: 0, held: 0, blocked: 0 };
  });
  const W = 600, H = 170, pad = 26, base = H - 18, keys = ["allowed", "flagged", "held", "blocked"];
  const colors = { allowed: "var(--allow)", flagged: "var(--flag)", held: "var(--hold)", blocked: "var(--block)" };
  const max = Math.max(1, ...points.map((p) => keys.reduce((s, k) => s + p[k], 0)));
  const bw = (W - pad) / points.length;
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Actions per hour by outcome, last 24 hours" });
  g.append(svg("line", { x1: pad, x2: W, y1: base, y2: base, stroke: "var(--rule)" }));
  points.forEach((p, i) => {
    let y = base;
    for (const k of keys) {
      const h = (p[k] / max) * (base - 10);
      if (h > 0) {
        y -= h;
        const r = svg("rect", { x: pad + i * bw + 2, y, width: Math.max(bw - 4, 1), height: h, fill: colors[k] });
        r.append(svg("title", {}, `${new Date(p.hour * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}: ${p[k]} ${k}`));
        g.append(r);
      }
    }
    if (i % 6 === 0 || i === 23) g.append(svg("text", { x: pad + i * bw + bw / 2, y: H - 4, "font-size": 10, "text-anchor": "middle", fill: "var(--ink-3)" },
      i === 23 ? "now" : new Date(p.hour * 1000).toLocaleTimeString([], { hour: "2-digit" })));
  });
  g.append(svg("text", { x: 0, y: 14, "font-size": 10, fill: "var(--ink-3)" }, String(max)));
  return el("div", {}, g, el("div", { class: "legend" },
    keys.map((k) => el("span", {}, el("i", { style: `background:${colors[k]}` }), title(k)))));
}

async function vApprovals() {
  const status = new URLSearchParams(location.hash.split("?")[1] || "").get("status") || "PENDING";
  const data = await api(`/v1/approvals?status=${status}`);
  const sel = el("select", { "aria-label": "Status", onchange: (e) => { location.hash = `#/approvals?status=${e.target.value}`; } },
    ["PENDING", "APPROVED", "REJECTED", "EXPIRED", "ALL"].map((s) => el("option", { value: s, selected: s === status }, title(s))));
  return [
    el("h1", {}, "Held actions"),
    el("p", { class: "lede" }, "Actions an agent tried that policy says a person must approve. The agent waits until you decide; if nobody does before the timeout, the action is rejected."),
    el("div", { class: "filters" }, el("label", { class: "inline" }, "Show", sel)),
    data.approvals.length ? el("div", { class: "rows" }, data.approvals.map((a) =>
      a.status === "PENDING" ? holdRow(a) : el("div", { class: "row", dataset: { rail: a.status === "APPROVED" ? "ALLOW" : "DENY" } },
        el("div", { class: "row-top" }, el("span", { class: "row-title" }, `${a.agent_id} · ${(a.event || {}).action || ""}`), badge(a.status)),
        el("div", { class: "mono" }, (a.event || {}).resource || ""),
        el("div", { class: "row-meta" }, el("span", {}, `By ${a.resolved_by || "—"}`), el("span", {}, when(a.resolved_at)),
          a.comment && el("span", {}, `“${a.comment}”`))))) :
      empty(status === "PENDING" ? "Nothing is waiting for a decision." : "No held actions with this status."),
  ];
}

async function vAlerts() {
  const status = new URLSearchParams(location.hash.split("?")[1] || "").get("status") || "OPEN";
  const data = await api(`/v1/alerts?status=${status}`);
  const sel = el("select", { "aria-label": "Status", onchange: (e) => { location.hash = `#/alerts?status=${e.target.value}`; } },
    ["OPEN", "ACKNOWLEDGED", "RESOLVED", "ALL"].map((s) => el("option", { value: s, selected: s === status }, title(s))));
  const setStatus = async (a, s) => {
    const note = await promptReason(s === "RESOLVED" ? "Resolve this alert?" : "Acknowledge this alert?",
      "Note for the audit trail", s === "RESOLVED" ? "Resolve alert" : "Acknowledge alert", "primary");
    if (note === null) return;
    try { await api(`/v1/alerts/${a.alert_id}`, { method: "POST", body: { status: s, note } }); toast(s === "RESOLVED" ? "Alert resolved." : "Alert acknowledged."); route(); }
    catch (e) { toast(e.message); }
  };
  return [
    el("h1", {}, "Alerts"),
    el("p", { class: "lede" }, "Everything Sentinel flagged, held, blocked or quarantined. The same alerts go to email and Slack."),
    el("div", { class: "filters" }, el("label", { class: "inline" }, "Show", sel)),
    data.alerts.length ? el("div", { class: "rows" }, data.alerts.map((a) =>
      el("div", { class: "row", dataset: { rail: a.severity } },
        el("div", { class: "row-top" }, el("span", { class: "row-title" }, a.title),
          el("span", {}, badge(a.severity), " ", badge(a.mode), " ", badge(a.status))),
        el("div", { class: "row-meta" }, el("span", {}, `Agent ${a.agent_id}`), el("span", {}, ago(a.created_at)),
          el("span", {}, a.rule_id)),
        a.resource && el("div", { class: "mono", style: "margin-top:4px" }, a.resource),
        el("p", { class: "small", style: "margin:6px 0 0" }, a.detail),
        el("div", { class: "actions" },
          a.approval_id && el("a", { href: "#/approvals", class: "btn" }, "Open held action"),
          a.status === "OPEN" && el("button", { onclick: () => setStatus(a, "ACKNOWLEDGED") }, "Acknowledge"),
          a.status !== "RESOLVED" && el("button", { onclick: () => setStatus(a, "RESOLVED") }, "Resolve"))))) :
      empty(status === "OPEN" ? "No open alerts." : "No alerts with this status."),
  ];
}

async function vAgents() {
  const { agents } = await api("/v1/agents");
  const toggle = async (a, q) => {
    const reason = await promptReason(q ? `Quarantine ${a.agent_id}?` : `Release ${a.agent_id}?`,
      q ? "Why? Every action by this agent will be blocked until it is released." : "Why is it safe to release this agent?",
      q ? "Quarantine agent" : "Release agent", q ? "danger" : "approve");
    if (!reason) return;
    try { await api(`/v1/agents/${encodeURIComponent(a.agent_id)}/${q ? "quarantine" : "release"}`, { method: "POST", body: { reason } });
      toast(q ? `${a.agent_id} quarantined.` : `${a.agent_id} released.`); route(); }
    catch (e) { toast(e.message); }
  };
  return [
    el("h1", {}, "Agents"),
    el("p", { class: "lede" }, "Every agent Sentinel knows about: registered agents from the policy, plus any unregistered identity that tried to act."),
    el("div", { class: "panel table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Agent", "Status", "Risk", "Last 24 h", "Heartbeat", ""].map((h) => el("th", {}, h)))),
      el("tbody", {}, agents.map((a) => el("tr", {},
        el("td", {}, el("strong", {}, a.agent_id), el("div", { class: "small muted" }, a.registered ? a.description : "Not in the agent inventory"),
          a.owner && el("div", { class: "small muted" }, a.owner)),
        el("td", {}, badge(a.status), a.status_reason && el("div", { class: "small muted" }, a.status_reason)),
        el("td", {}, title(a.risk_tier)),
        el("td", { class: "small" }, `${a.activity_24h.actions} actions`, el("br"),
          `${a.activity_24h.blocked} blocked · ${a.activity_24h.held} held`),
        el("td", { class: "small" }, a.heartbeat_seconds ? [badge(a.healthy ? "PASS" : "FAIL", a.healthy ? "Reporting" : "Silent"), el("div", { class: "muted" }, ago(a.last_heartbeat))] : el("span", { class: "muted" }, "Not required")),
        el("td", {}, canApprove() && (a.status === "QUARANTINED" ?
          el("button", { class: "approve", onclick: () => toggle(a, false) }, "Release") :
          el("button", { onclick: () => toggle(a, true) }, "Quarantine")))))))),
  ];
}

async function vActivity() {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const minMode = q.get("min_mode") || "FLAG", agent = q.get("agent_id") || "";
  const data = await api(`/v1/decisions?limit=200&min_mode=${minMode}${agent ? `&agent_id=${encodeURIComponent(agent)}` : ""}`);
  const go = (m, a) => { location.hash = `#/activity?min_mode=${m}${a ? `&agent_id=${encodeURIComponent(a)}` : ""}`; };
  const modeSel = el("select", { onchange: (e) => go(e.target.value, agent) },
    [["LOG", "Every action"], ["FLAG", "Flagged and worse"], ["HOLD", "Held and blocked"], ["BLOCK", "Blocked only"]]
      .map(([v, l]) => el("option", { value: v, selected: v === minMode }, l)));
  const agentIn = el("input", { value: agent, placeholder: "Agent id", "aria-label": "Agent id", onchange: (e) => go(minMode, e.target.value.trim()) });
  return [
    el("h1", {}, "Activity log"),
    el("p", { class: "lede" }, "Each decision Sentinel made, newest first, with the reasons."),
    el("div", { class: "filters" }, el("label", { class: "inline" }, "Show", modeSel), agentIn),
    data.decisions.length ? el("div", { class: "rows" }, data.decisions.map(decisionRow)) : empty("No decisions match these filters."),
  ];
}

async function vCompliance() {
  const c = await api("/v1/compliance");
  return [
    el("h1", {}, "Compliance"),
    el("p", { class: "lede" }, "Controls are tested every hour against the live configuration and agent activity. Each result is written to the tamper-proof evidence log."),
    el("div", { class: "panel panel-pad" }, el("h2", {}, "Framework readiness"),
      Object.values(c.frameworks).map((f) => fwRow(f.framework, f.score))),
    el("div", { class: "section rows" }, c.controls.map((ctl) => el("details", { class: "row", dataset: { rail: ctl.status === "PASS" ? "ALLOW" : ctl.status === "WARN" ? "FLAG" : "DENY" } },
      el("summary", {}, el("div", { class: "row-top" },
        el("span", { class: "row-title" }, el("span", { class: "chev" }, "›"), `${ctl.id}  ${ctl.name}`), badge(ctl.status))),
      el("p", { class: "small", style: "margin:8px 0" }, ctl.objective),
      el("div", { class: "small muted" }, `Owner: ${ctl.owner_role} · Last tested ${ago(ctl.tested_at)}`),
      el("div", { class: "small muted", style: "margin:4px 0 8px" },
        Object.entries(ctl.frameworks).map(([fw, reqs]) => `${fw} ${reqs.join(", ")}`).join("  |  ")),
      ctl.checks.map((ch) => el("div", { class: "check" }, badge(ch.status), el("span", {}, ch.check,
        ch.detail && el("span", { class: "muted" }, ` — ${ch.detail}`))))))),
  ];
}

async function vRisks() {
  const { risks } = await api("/v1/risks");
  return [
    el("h1", {}, "Risk register"),
    el("p", { class: "lede" }, "Residual risk is recalculated from the live status of the controls that treat each risk."),
    el("div", { class: "panel table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Risk", "Inherent", "Residual", "Controls", "Owner"].map((h) => el("th", {}, h)))),
      el("tbody", {}, risks.map((r) => el("tr", {},
        el("td", {}, el("strong", {}, `${r.risk_id}  ${r.title}`), el("div", { class: "small muted" }, r.description)),
        el("td", {}, badge(r.inherent_level), el("div", { class: "small muted" }, `${r.likelihood} × ${r.impact} = ${r.inherent_score}`)),
        el("td", {}, badge(r.residual_level), el("div", { class: "small muted" }, `score ${r.residual_score}`)),
        el("td", { class: "small" }, Object.entries(r.control_status).map(([cid, s]) => el("div", {}, badge(s, cid)))),
        el("td", { class: "small" }, r.owner))))))
  ];
}

async function vPolicy() {
  const p = await api("/v1/policy");
  return [
    el("h1", {}, "Policy"),
    el("p", { class: "lede" }, `Active policy ${p.fingerprint} for ${p.organization}. Edit policy.yaml in the policy bucket; Sentinel picks up a valid change within 30 seconds, and keeps the last valid policy if the new one has an error.`),
    el("pre", {}, JSON.stringify(p.document, null, 2)),
  ];
}

// ---------------------------------------------------------------- router
const routes = { overview: vOverview, approvals: vApprovals, alerts: vAlerts, agents: vAgents,
  activity: vActivity, compliance: vCompliance, risks: vRisks, policy: vPolicy };

async function route() {
  const name = (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0]) || "overview";
  const fn = routes[name] || vOverview;
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === name));
  try { view(await fn()); }
  catch (e) { view(el("h1", {}, "Could not load this page"), el("p", { class: "error" }, e.message)); }
  refreshCounts();
}
async function refreshCounts() {
  try {
    const o = await api("/v1/overview");
    const h = document.getElementById("nav-held"), a = document.getElementById("nav-alerts");
    h.textContent = o.pending_approvals; h.hidden = !o.pending_approvals;
    a.textContent = o.open_alerts.total; a.hidden = !o.open_alerts.total;
  } catch { /* counts are best-effort */ }
}

(async function main() {
  try {
    state.config = await (await fetch("config.json", { cache: "no-store" })).json();
    if (!(await initAuth())) return;
    document.getElementById("who").append(el("div", {}, state.user.email),
      el("button", { onclick: logout }, "Sign out"));
    window.addEventListener("hashchange", route);
    await route();
    setInterval(() => { if (!document.querySelector("dialog[open]")) route(); }, 15000);
  } catch (e) {
    view(el("h1", {}, "Sentinel console"), el("p", { class: "error" }, e.message));
  }
})();
