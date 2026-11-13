/* ReD-Pot console — vanilla JS, no build step. */
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const LV = {0: "noise", 1: "touch", 2: "interaction", 3: "intent", 4: "compromise", 5: "honeytoken"};
const LCOL = {0: "#4a4a52", 1: "#6f6f78", 2: "#e3b341", 3: "#ff8a1f", 4: "#f12c35", 5: "#d63bff"};
const ROLE_TITLE = {"windows-file-server": "Windows File Server", "linux-web-hosting": "Linux Web Hosting",
  "ftp-backup-server": "FTP / Backup Server", "windows-domain-controller": "Windows Domain Controller",
  "linux-dns-server": "Linux DNS Server", "canary": "Bait documents"};
const st = {view: "overview", hours: 24, net: null, nodes: null, edges: null, focus: null, failed: 0, skew: 0, errs: {}};
{ const b = document.getElementById("bootfail"); if (b) b.remove(); }   // app.js runs → the static "did not start" banner goes

/* Server clock: every "ago" is computed against the server's time (incident timestamps come from it),
   so a wrong browser OR server clock never shows "1d ago" for a fresh incident. */
const srvNow = () => Date.now() + (st.skew || 0);

/* Errors per part of the page: one failing part (a script that did not load, the map, an API call) never
   blanks the rest; the banner names what is broken. */
function partErr(part, err) {
  if (err) { if (String(err && err.message) === "auth") return; st.errs[part] = String(err && err.message || err).slice(0, 160); console.warn(part, err); }
  else delete st.errs[part];
  const b = $("#jserr"), k = Object.keys(st.errs);
  if (!b) return;
  b.hidden = !k.length;
  b.innerHTML = k.length ? `<b>⚠ Part of the console is not working</b> — ${k.map(x => `${esc(x)}: <span class="mono">${esc(st.errs[x])}</span>`).join(" · ")}
    <span class="dim">· the rest of the page still updates. Reload (Ctrl+F5); if it stays, check the manager log.</span>` : "";
}
async function part(name, fn) {
  try { const r = await fn(); partErr(name, null); return r; } catch (e) { partErr(name, e); if (String(e && e.message) === "auth") throw e; }
}

const lv = l => `<span class="lv l${l}" title="${LV[l]}">L${l} ${LV[l]}</span>`;
const lvs = l => `<span class="lv l${l}" title="${LV[l]}">L${l}</span>`;
function ago(ts) {
  if (!ts) return "—";
  const s = (srvNow() - Date.parse(ts)) / 1000;
  if (s < 60) return Math.max(0, s | 0) + "s ago";
  if (s < 3600) return (s / 60 | 0) + "m ago";
  if (s < 86400) return (s / 3600 | 0) + "h ago";
  return (s / 86400 | 0) + "d ago";
}
const tfmt = ts => ts ? new Date(ts).toLocaleString([], {month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "";

async function api(path, opt) {
  const r = await fetch(path, Object.assign({credentials: "same-origin"}, opt || {}));
  if (r.status === 401) { setTimeout(() => location.reload(), st.wall ? 30000 : 0); throw new Error("auth"); }
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}

/* "community" → "Community Edition"; anything else is shown as plain text (set via textContent / esc()). */
function editionName(e) {
  const v = String(e ?? "").trim().slice(0, 40);
  if (!v) return "";
  return v.charAt(0).toUpperCase() + v.slice(1).toLowerCase() + " Edition";
}

/* ---------------- KPIs ---------------- */
function clockCheck(s, t0, t1) {
  const srv = typeof s.server_time === "number" ? s.server_time * 1000 : Date.parse(s.now);
  if (!isFinite(srv)) return;
  st.skew = srv - (t0 + t1) / 2;                       // server − browser (request midpoint)
  const b = $("#clockwarn"), off = Math.abs(st.skew);
  const fmt = ms => ms >= 86400e3 ? `${(ms / 86400e3).toFixed(1)} days` : ms >= 3600e3 ? `${(ms / 3600e3).toFixed(1)} h` : `${Math.round(ms / 60e3)} min`;
  const bad = off > 120e3, unsync = s.clock_synced === false;
  b.hidden = !(bad || unsync);
  b.innerHTML = bad ? `<b>⚠ Clock mismatch:</b> the manager's clock is <b>${esc(fmt(off))} ${st.skew > 0 ? "ahead of" : "behind"}</b> this browser.
    <span class="dim">Times are shown relative to the manager clock. If the manager is wrong, enable NTP on it (<span class="mono">timedatectl set-ntp true</span>) —
    a clock jump also ends login sessions.</span>` :
    unsync ? `<b>⚠ The manager's clock is not NTP-synchronised.</b> <span class="dim">Incident times may drift — enable NTP (<span class="mono">timedatectl set-ntp true</span>).</span>` : "";
}

async function loadSummary() {
  const t0 = Date.now();
  const s = await api(`/api/summary?hours=${st.hours}`);
  clockCheck(s, t0, Date.now());
  $("#company").textContent = `${s.company} · ${s.domain}`;
  const ed = $("#edition");
  if (ed) { const t = editionName(s.edition); ed.textContent = t; ed.hidden = !t; }
  const k = [
    {t: "Real incidents", n: s.real_incidents, s: "L3+ (intent or worse)", hot: s.real_incidents > 0},
    {t: "Critical", n: s.critical, s: "compromise / honeytoken", hot: s.critical > 0},
    {t: "Honeytokens hit", n: s.honeytokens, s: "different stolen baits used", ht: true, hotv: s.honeytokens > 0},
    {t: "Active attackers", n: s.attackers, s: "sources with L3+"},
    {t: "Touches", n: s.touches, s: "low-level, no alert"},
    {t: "Sensors online", n: `${s.sensors_online}/${s.sensors_total}`, s: `${s.events} events`},
  ];
  const off = Array.isArray(s.sensors_offline) ? s.sensors_offline : [];
  const ban = $("#offline");
  ban.hidden = !off.length;
  ban.innerHTML = off.length ? `<b>⚠ ${off.length === 1 ? "Sensor" : off.length + " sensors"} not reporting</b> — ` +
    off.map(x => `<span class="mono">${esc(x.name)}</span> silent since ${esc(ago(x.last_seen))}`).join(" · ") +
    ` <span class="dim">· someone may have stopped or isolated ${off.length === 1 ? "it" : "them"} (L4 tamper incident opened). Check Deception.</span>` : "";
  $("#kpis").innerHTML = k.map(x => `<div class="kpi ${x.hot ? "hot" : ""} ${x.ht ? "ht" : ""} ${x.hotv ? "hotv" : ""}">
    <div class="t">${esc(x.t)}</div><div class="n">${esc(x.n)}</div><div class="s">${esc(x.s)}</div></div>`).join("");
}

/* ---------------- incidents feed ---------------- */
async function loadFeed() {
  const inc = await api(`/api/incidents?hours=${st.hours}&min_level=2&status=open`);
  $("#inccount").textContent = `${inc.filter(i => i.level >= 3).length} real · ${inc.length} total`;
  $("#feed").innerHTML = inc.length ? inc.slice(0, 60).map(i => `
    <div class="inc" data-inc="${i.id}">
      <div>${lvs(i.level)}</div>
      <div class="who">${esc(i.host)} ${srcTag(i)}</div>
      <div class="what">${esc(i.title)}</div>
      <div class="meta">${esc(i.sensors.join(" → "))} · ${i.count} events · ${ago(i.last_ts)}</div>
    </div>`).join("") : `<div class="empty">No open incidents. Quiet is good.</div>`;
}

const srcTag = i => i.kind === "sensor" ? `<span class="tag ext">tamper</span>` :
  `<span class="tag ${i.internal ? "int" : "ext"}">${i.internal ? "internal" : "external"}</span>`;

/* ---------------- graph ---------------- */
/* internal network map lives in netmap.js (loadGraph, legend, netFocus) */

/* ---------------- drawer: host ---------------- */
function closeDrawer() { $("#drawer").classList.remove("on"); st.focus = null; history.replaceState(null, "", location.pathname); if (typeof netFocus === "function") netFocus(null); }

function timeline(events) {
  return `<div class="tl">${events.map(e => {
    const d = e.data || {};
    const extra = d.cmd ? d.cmd : (d.path && e.type !== "http.request" && e.type !== "http.notfound") ? d.path :
      d.ua && e.level >= 3 ? d.ua : d.urls ? d.urls.join(" ") : d.targets ? d.targets.join(", ") : "";
    return `<div class="it l${e.level}"><div class="when">${tfmt(e.ts)} · ${lvs(e.level)} <span class="mono">${esc(e.type)}</span> · ${esc(e.sensor || "")} ${esc(e.proto || "")}${e.dst_port ? ":" + esc(e.dst_port) : ""}</div>
      <div class="ttl">${esc(e.desc)}</div>${extra ? `<pre>${esc(extra)}</pre>` : ""}</div>`;
  }).join("")}</div>`;
}

function compact(events) {
  // collapse noisy repeats (tcp.connect / notfound) for readability
  const out = [];
  let skipped = 0;
  for (const e of events) {
    if ((e.type === "tcp.connect" || e.type === "http.notfound" || e.type === "ssh.client") && out.length &&
        out[out.length - 1].type === e.type) { skipped++; continue; }
    out.push(e);
  }
  return {list: out, skipped};
}

async function openHost(ip) {
  const h = await api(`/api/host/${encodeURIComponent(ip)}`);
  st.focus = ip;
  history.replaceState(null, "", `#host/${ip}`);
  const n = h.names || {};
  const path = (h.path || []).map((p, i) => `${i ? '<span class="arr">→</span>' : ""}<div class="hop"><b>${esc(p.sensor === "CANARY" ? "Bait doc" : p.sensor)}</b>${lvs(p.lvl)} <span class="muted">${esc(p.protos || "")}</span><div class="muted" style="font-size:11px">${tfmt(p.first)}</div></div>`).join("");
  const c = compact(h.events.filter(e => e.level >= 1));
  $("#dtitle").innerHTML = `<h2>${esc(h.label)}</h2><div style="margin-top:6px">${lv(h.max_level)} <span class="tag ${h.internal ? "int" : "ext"}">${h.internal ? "internal host" : "external"}</span></div>`;
  $("#dbody").innerHTML = `
    <div class="kv">
      <div>IP</div><div class="mono">${esc(h.ip)}</div>
      <div>Workstation</div><div>${esc((n.workstation || []).join(", ") || "—")}</div>
      <div>Logon user</div><div>${esc((n.logon || []).join(", ") || "—")} <span class="muted">(accepted logins only)</span></div>
      <div>Users tried</div><div>${esc((n.tried || []).join(", ") || "—")}</div>
      <div>Reverse DNS</div><div>${esc(h.rdns || "—")}</div>
      <div>Clients</div><div class="mono" style="font-size:12px">${esc((n.client || []).join(" | ") || "—")}</div>
      <div>First / last seen</div><div>${tfmt(h.first_ts)} → ${tfmt(h.last_ts)}</div>
    </div>
    <h3 class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.6px">Attack path</h3>
    <div class="path">${path || '<span class="muted">—</span>'}</div>
    <h3 class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.6px">Timeline <span style="text-transform:none;font-weight:400">(${h.events.length} events${c.skipped ? `, ${c.skipped} repeats folded` : ""})</span></h3>
    ${timeline(c.list)}`;
  $("#drawer").classList.add("on");
  if (typeof netFocus === "function") netFocus(ip, h.path || []);
}

async function openIncident(id) {
  const i = await api(`/api/incident/${id}`);
  history.replaceState(null, "", `#incident/${id}`);
  const c = compact(i.events);
  $("#dtitle").innerHTML = `<h2>Incident #${i.id}</h2><div style="margin-top:6px">${lv(i.level)} <span class="st ${i.status}">${esc(i.status)}</span></div>`;
  $("#dbody").innerHTML = `
    <p style="font-size:15px;margin-top:0"><b>${esc(i.title)}</b></p>
    <div class="kv">
      <div>Source</div><div>${i.src_ip ? `<a href="#" data-host="${esc(i.src_ip)}">${esc(i.host)}</a>` : `${esc(i.host)} ${srcTag(i)}`}</div>
      <div>Sensors</div><div>${esc(i.sensors.join(" → "))}</div>
      <div>Window</div><div>${tfmt(i.first_ts)} → ${tfmt(i.last_ts)}</div>
      <div>Events</div><div>${i.count}</div>
      ${i.note ? `<div>Notes</div><div style="white-space:pre-wrap">${esc(i.note)}</div>` : ""}
    </div>
    <div class="toolbar">
      <button class="btn" data-status="ack">Acknowledge</button>
      <button class="btn" data-status="closed">Close</button>
      <button class="btn" data-status="false_positive">False positive</button>
      <button class="btn" data-status="open">Re-open</button>
    </div>
    ${timeline(c.list)}`;
  $$("#dbody [data-status]").forEach(b => b.onclick = async () => {
    await api(`/api/incident/${id}/status`, {method: "POST", headers: {"Content-Type": "application/json", "X-Requested-With": "rpot"},
      body: JSON.stringify({status: b.dataset.status})});
    openIncident(id); refresh();
  });
  $$("#dbody [data-host]").forEach(a => a.onclick = ev => { ev.preventDefault(); openHost(a.dataset.host); });
  $("#drawer").classList.add("on");
}

/* ---------------- tables ---------------- */
async function loadIncidents() {
  const rows = await api(`/api/incidents?hours=${Math.max(st.hours, 168)}&min_level=${$("#imin").value}&status=${$("#istatus").value}`);
  $("#t-inc").innerHTML = `<tr><th>#</th><th>Level</th><th>Source</th><th>What happened</th><th>Sensors</th><th>Events</th><th>Last</th><th>Status</th></tr>` +
    (rows.map(i => `<tr class="click" data-inc="${i.id}"><td>${i.id}</td><td>${lvs(i.level)}</td><td>${esc(i.host)}<br>${srcTag(i)}</td>
      <td>${esc(i.title)}</td><td>${esc(i.sensors.join(" → "))}</td><td>${i.count}</td><td>${ago(i.last_ts)}</td><td><span class="st ${i.status}">${esc(i.status)}</span></td></tr>`).join("") ||
      `<tr><td colspan="8" class="empty">No incidents match.</td></tr>`);
}

const tried = l => (l || []).length > 6 ? `${l.slice(-6).join(", ")} (+${l.length - 6})` : (l || []).join(", ");

async function loadHosts() {
  const rows = await api(`/api/hosts?hours=${Math.max(st.hours, 168)}`);
  $("#t-hosts").innerHTML = `<tr><th>Level</th><th>Host</th><th>Workstation</th><th>Logon user</th><th>Users tried</th><th>Type</th><th>First seen</th><th>Last seen</th></tr>` +
    (rows.map(h => `<tr class="click" data-host="${esc(h.ip)}"><td>${lvs(h.max_level)}</td><td class="mono">${esc(h.ip)}${h.rdns ? `<br><span class="muted">${esc(h.rdns)}</span>` : ""}</td>
      <td>${esc((h.names.workstation || []).join(", "))}</td><td>${esc((h.names.logon || []).join(", "))}</td><td>${esc(tried(h.names.tried))}</td>
      <td><span class="tag ${h.internal ? "int" : "ext"}">${h.internal ? "internal" : "external"}</span>${h.allowlisted ? ' <span class="tag">allowlisted</span>' : ""}</td><td>${tfmt(h.first_ts)}</td><td>${ago(h.last_ts)}</td></tr>`).join("") ||
      `<tr><td colspan="8" class="empty">No hosts yet.</td></tr>`);
}

async function loadEvents(sensorFilter) {
  const src = $("#esrc").value.trim();
  let rows = await api(`/api/events?hours=${st.hours}&min_level=${$("#emin").value}&limit=1000${src ? "&src=" + encodeURIComponent(src) : ""}`);
  if (typeof sensorFilter === "string") rows = rows.filter(r => r.sensor === sensorFilter);
  $("#t-ev").innerHTML = `<tr><th>Time</th><th>Level</th><th>Source</th><th>Sensor</th><th>Type</th><th>Description</th></tr>` +
    (rows.map(e => `<tr class="click" data-host="${esc(e.src_ip || "")}"><td class="mono">${tfmt(e.ts)}</td><td>${lvs(e.level)}</td><td class="mono">${esc(e.src_ip || e.source || "")}</td>
      <td>${esc(e.sensor || "")} <span class="muted">${esc(e.proto || "")}${e.dst_port ? ":" + esc(e.dst_port) : ""}</span></td><td class="mono">${esc(e.type)}</td><td>${esc(e.desc)}</td></tr>`).join("") ||
      `<tr><td colspan="6" class="empty">No events.</td></tr>`);
}

async function loadDeception() {
  const [sensors, tokens] = await Promise.all([api(`/api/sensors`), api(`/api/tokens`)]);
  const at = (t, name) => (t.planted || "").toUpperCase().replace(/^\\\\/, "").startsWith(name.toUpperCase());
  const works = (t, name) => (t.valid_on || []).some(v => v.toUpperCase().startsWith(name.toUpperCase() + ":"));
  const bait = t => `<div class="bait ${t.count ? "hit" : ""}"><span class="tag">${esc(t.kind)}</span>
      <span>${esc(t.desc)}${t.username ? ` <span class="mono muted">${esc(t.username)}</span>` : ""}</span>
      ${t.count ? `<span class="lv l5" title="used ${t.count}× · last ${ago(t.last)} · by ${esc(t.sources.join(", "))}">${t.count} hit${t.count > 1 ? "s" : ""}</span>` : '<span class="muted">untouched</span>'}</div>`;
  const cards = sensors.map(s => {
    const planted = tokens.filter(t => at(t, s.name)), valid = tokens.filter(t => works(t, s.name) && !at(t, s.name));
    return `<div class="card sensor"><img src="${typeof ICONS !== "undefined" ? ICONS.sensor(s.role, s.online) : ""}" alt="">
      <div><h4>${esc(s.name)}</h4><div class="muted">${esc(s.title || ROLE_TITLE[s.role] || s.role)} · ${esc(s.os || "")}</div>
      <div style="margin:8px 0"><span class="dot ${s.online ? "on" : ""}"></span>${s.online ? "online" : "offline"} · <span class="mono">${esc(s.ip || "")}</span> · seen ${ago(s.last_seen)}</div>
      <div>${(s.services || []).map(x => (s.services_down || []).includes(x)
        ? `<span class="tag mono ext" title="${esc("down: " + (((s.health || {})[x] || {}).reason || "listener not serving") + " · since " + ago(((s.health || {})[x] || {}).since))}">${esc(x)} down</span>`
        : `<span class="tag mono">${esc(x)}</span>`).join("")}</div>
      ${planted.length ? `<div class="bsec">Baits planted here</div>${planted.map(bait).join("")}` : ""}
      ${valid.length ? `<div class="bsec">Stolen credentials that unlock it</div>${valid.map(bait).join("")}` : ""}</div></div>`;
  });
  const docs = tokens.filter(t => t.kind === "document");
  if (docs.length) cards.push(`<div class="card sensor"><img src="${typeof ICONS !== "undefined" ? ICONS.canary() : ""}" alt="">
      <div><h4>Bait documents</h4><div class="muted">Word files that call home when opened</div>
      <div class="bsec">Planted</div>${docs.map(t => bait(t) + `<div class="mono muted" style="font-size:11.5px;margin:-2px 0 6px">${esc(t.planted)}</div>`).join("")}</div></div>`);
  $("#sgrid").innerHTML = cards.join("");
  loadFleet();
  const used = tokens.filter(t => t.count).length;
  $("#baitsum").textContent = `${tokens.length} baits · ${used} used`;
  $("#t-baits").innerHTML = `<tr><th>Hits</th><th>Kind</th><th>Bait</th><th>Planted at</th><th>Works on</th><th>Last used</th><th>Used by</th></tr>` +
    tokens.sort((a, b) => b.count - a.count).map(t => `<tr><td>${t.count ? `<span class="lv l5">${t.count}</span>` : '<span class="muted">0</span>'}</td>
      <td><span class="tag">${esc(t.kind)}</span></td><td>${esc(t.desc)}${t.username ? `<br><span class="mono muted">${esc(t.username)}</span>` : ""}</td>
      <td class="mono">${esc(t.planted)}</td><td>${esc((t.valid_on || []).join(", ") || "—")}</td><td>${t.last ? ago(t.last) : "—"}</td>
      <td class="mono">${esc((t.sources || []).join(", "))}</td></tr>`).join("");
}

/* Fleet + Community Edition decoy slots (D-6, D-8): used = local + remote + pending; used may exceed max. */
const LOCAL_NOTE = "Revoking a decoy on this server does not free a slot; use install.sh remove-decoy.";
function renderSlots(lim) {
  const el = $("#fslots"), msg = $("#ffull"), add = $("#fadd");
  if (!lim || typeof lim.max !== "number" || typeof lim.used !== "number") {
    el.textContent = ""; msg.hidden = true; add.disabled = false; return;
  }
  const over = lim.used > lim.max, full = !!lim.full || lim.used >= lim.max;
  el.className = "slots" + (over ? " over" : full ? " full" : "");
  const ed = editionName(lim.edition);
  el.textContent = `${lim.used} of ${lim.max} decoys${ed ? ` (${ed})` : ""}${over ? " · over the limit" : ""}`;
  el.title = `on this server ${Number(lim.local) || 0} · remote ${Number(lim.remote) || 0} · waiting to join ${Number(lim.pending) || 0}`;
  add.disabled = full;
  add.title = full ? "Decoy limit reached" : "";
  msg.hidden = !full;
  msg.textContent = full ? String(lim.message || `Decoy limit reached (${lim.used} of ${lim.max}).`) : "";
}

async function fleetPost(name, action) {
  $("#ferr").textContent = "";
  const r = await fetch(`/api/fleet/${encodeURIComponent(name)}/${action}`, {method: "POST", credentials: "same-origin",
    headers: {"X-Requested-With": "rpot"}});
  if (r.status === 401) { location.reload(); return; }
  if (!r.ok) {
    let d = {};
    try { d = (await r.json()) || {}; } catch (e) { /* non-JSON error page */ }
    $("#ferr").textContent = d && d.error ? String(d.error).slice(0, 400) : `${action} failed (HTTP ${r.status})`;
  }
  loadFleet().catch(e => partErr("Deception", e));
}

async function loadFleet() {
  const f = await api(`/api/fleet`);
  renderSlots(f.limit);
  const admin = st.role === "admin";              // the wall role never gets Cancel (the API answers 403 anyway)
  if (!$("#frole").options.length) $("#frole").innerHTML = f.roles.map(r => `<option value="${esc(r.id)}">${esc(r.title)}</option>`).join("");
  const rows = f.sensors.map(s => `<tr><td><b>${esc(s.name)}</b></td><td>${esc(ROLE_TITLE[s.role] || s.role)}</td><td class="mono">${esc(s.ip || "")}</td>
      <td>${s.remote ? '<span class="tag">remote</span>' : '<span class="tag">this server</span>'}</td>
      <td>${s.revoked ? '<span class="st">revoked</span>' : '<span class="st open">trusted</span>'}</td>
      <td>${s.revoked ? (s.remote ? `<button class="btn" data-delete="${esc(s.name)}" title="Remove this revoked sensor from the list (its events stay)">Delete</button>`
                                  : `<span class="muted" title="${esc(LOCAL_NOTE)}">still uses a slot</span>`)
           : `<button class="btn" data-revoke="${esc(s.name)}" data-local="${s.remote ? "" : "1"}"${s.remote ? "" : ` title="${esc(LOCAL_NOTE)}"`}>Revoke</button>`}</td></tr>`).join("") +
    f.pending.map(p => `<tr><td><b>${esc(p.name)}</b></td><td>${esc(ROLE_TITLE[p.role] || p.role)}</td><td class="mono">${esc(p.ip || "")}</td>
      <td><span class="tag">remote</span></td><td><span class="st ack">waiting to join</span></td><td><span class="muted">expires ${esc(new Date(p.expires * 1000).toLocaleString())}</span>${admin
        ? ` <button class="btn" data-cancel="${esc(p.name)}" title="Invalidate this join command and free its decoy slot">Cancel</button>` : ""}</td></tr>`).join("");
  const hasLocal = f.sensors.some(s => !s.remote);
  $("#fleet").innerHTML = `<table><tr><th>Sensor</th><th>Role</th><th>IP</th><th>Where</th><th>Trust</th><th></th></tr>${rows}</table>` +
    (hasLocal ? `<p class="fnote">${esc(LOCAL_NOTE)} Revoking a remote sensor or cancelling a pending join frees its slot.</p>` : "");
  $$("#fleet [data-delete]").forEach(b => b.onclick = async () => {
    if (!confirm(`Delete ${b.dataset.delete} from the list? Its past events and incidents are kept.`)) return;
    await fleetPost(b.dataset.delete, "delete");
  });
  $$("#fleet [data-revoke]").forEach(b => b.onclick = async () => {
    const extra = b.dataset.local ? `\n\n${LOCAL_NOTE}` : "\n\nThis frees its decoy slot.";
    if (!confirm(`Revoke ${b.dataset.revoke}? It will no longer be able to report to this manager.${extra}`)) return;
    await fleetPost(b.dataset.revoke, "revoke");
  });
  $$("#fleet [data-cancel]").forEach(b => b.onclick = async () => {
    if (!confirm(`Cancel the pending join for ${b.dataset.cancel}? Its join command stops working and the decoy slot is freed.`)) return;
    await fleetPost(b.dataset.cancel, "cancel");
  });
}

$("#fadd").onclick = async () => {
  $("#ferr").textContent = "";
  const r = await fetch("/api/fleet/enroll", {method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-Requested-With": "rpot"},
    body: JSON.stringify({name: $("#fname").value.trim(), role: $("#frole").value, ip: $("#fip").value.trim()})});
  if (r.status === 401) { location.reload(); return; }
  let d = {};
  try { d = (await r.json()) || {}; } catch (e) { /* non-JSON error page */ }
  if (!r.ok) { $("#ferr").textContent = d.error ? String(d.error).slice(0, 400) : `failed (HTTP ${r.status})`; loadFleet().catch(() => {}); return; }
  $("#fcmd").textContent = String(d.command || "sudo ./install.sh sensor");
  $("#fjoinstr").textContent = String(d.join || "");            // own box: never part of the command (B7)
  if (d.hint) $("#fjoinhint").textContent = String(d.hint);
  $("#fjoin").classList.remove("collapsed");
  loadFleet();
};
function copyFrom(src, btn) {
  $(btn).onclick = () => navigator.clipboard && navigator.clipboard.writeText($(src).textContent).then(() => { $(btn).textContent = "Copied ✓"; setTimeout(() => $(btn).textContent = "Copy", 1500); });
}
copyFrom("#fcmd", "#fcopy");
copyFrom("#fjoinstr", "#fcopyjoin");

/* ---------------- JSON export (incidents + alert records, UTC date range) ---------------- */
const isoDay = d => d.toISOString().slice(0, 10);
function exportDefaults() {
  const now = new Date(srvNow());
  $("#xto").value = isoDay(now);
  $("#xfrom").value = isoDay(new Date(now.getTime() - 6 * 86400e3));     // last 7 UTC days, today included
}
// download name from Content-Disposition, reduced to a safe charset (only ever used as a[download])
function cdFilename(h, fallback) {
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(h || "");
  let n = "";
  if (m) { try { n = decodeURIComponent(m[1]); } catch (e) { n = m[1]; } }
  n = n.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "").slice(0, 100);
  return n || fallback;
}
const mb = b => (Number(b) / 1048576).toFixed(1) + " MB";
function exportError(status, d) {
  const msg = d && d.error ? String(d.error).slice(0, 400) : "";
  if (status === 413) {
    const cnt = [d.incidents != null ? `${Number(d.incidents)} incidents` : "", d.alerts != null ? `${Number(d.alerts)} alert records` : "",
      d.bytes != null ? `about ${mb(d.bytes)}` : ""].filter(Boolean).join(", ");
    return `${msg || "Export too large: narrow the date range"}${cnt ? ` (${cnt}${d.max_bytes != null ? `; limit ${mb(d.max_bytes)}` : ""})` : ""}`;
  }
  if (status === 429) return msg || "Another export is running or too many exports were started; try again in a few minutes.";
  if (status === 403) return msg || "Export is not allowed for this session (admin only).";
  return msg || `Export failed (HTTP ${status}).`;
}
async function exportJson() {
  const err = $("#xerr"), btn = $("#xbtn");
  const frm = $("#xfrom").value, to = $("#xto").value;
  err.textContent = "";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(frm) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) { err.textContent = "Pick both a From and a To date."; return; }
  if (frm > to) { err.textContent = "From must be on or before To."; return; }
  btn.disabled = true;
  btn.textContent = "Exporting…";
  try {
    const r = await fetch(`/api/export?from=${encodeURIComponent(frm)}&to=${encodeURIComponent(to)}`,
      {credentials: "same-origin", headers: {"X-Requested-With": "rpot"}, cache: "no-store"});
    if (r.status === 401) { location.reload(); return; }
    if (!r.ok) {
      let d = {};
      try { d = (await r.json()) || {}; } catch (e) { /* non-JSON error page */ }
      err.textContent = exportError(r.status, d || {});
      return;
    }
    const blob = await r.blob();
    const tail = await blob.slice(Math.max(0, blob.size - 64)).text();
    if (!/"complete"\s*:\s*true\s*\}\s*$/.test(tail))
      err.textContent = "Warning: the export ended early (no completion marker), so the file may be cut off. Try again or narrow the date range.";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = cdFilename(r.headers.get("Content-Disposition"), `redpot-export-${frm}_${to}.json`);
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) {
    err.textContent = `Export failed: ${String(e && e.message || e).slice(0, 200)}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Export JSON";
  }
}

/* ---------------- wiring ---------------- */
function switchView(v) {
  st.view = v;
  $$("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.v === v));
  $$(".view").forEach(s => s.classList.toggle("on", s.id === "v-" + v));
  refresh();
}

const need = (fn, file) => { if (typeof fn !== "function") throw new Error(`${file} did not load`); return fn; };

async function refresh() {
  if (st.wall) {
    try { await need(typeof wallRefresh !== "undefined" && wallRefresh, "wall.js")(); st.failed = 0; partErr("Wall", null); }
    catch (e) { st.failed++; partErr("Wall", e); }
    return;
  }
  // independent parts: the KPIs and the incident list render even if the network map (vis-network) or world map fail
  const views = {
    worldmap: ["World map", () => need(typeof loadWorld !== "undefined" && loadWorld, "worldmap.js")()],
    incidents: ["Incidents", loadIncidents], hosts: ["Hosts", loadHosts], events: ["Events", loadEvents], deception: ["Deception", loadDeception],
  };
  let ok = true;
  const run = async (name, fn) => { try { await part(name, fn); } catch (e) { ok = false; } if (st.errs[name]) ok = false; };
  await run("Summary", loadSummary);
  if (st.view === "overview") {
    await run("Live incidents", loadFeed);
    await run("Network map", () => need(typeof loadGraph !== "undefined" && loadGraph, "netmap.js")(false));
  } else if (views[st.view]) await run(...views[st.view]);
  if (ok) { st.failed = 0; $("#live").classList.remove("off"); }
  else if (++st.failed > 1) $("#live").classList.add("off");
}

document.addEventListener("click", ev => {
  const inc = ev.target.closest("[data-inc]");
  if (inc) return openIncident(inc.dataset.inc);
  const h = ev.target.closest("tr[data-host]");
  if (h && h.dataset.host) return openHost(h.dataset.host);
});
$$("#tabs button").forEach(b => b.onclick = () => switchView(b.dataset.v));
$("#range").onchange = () => { st.hours = +$("#range").value; if (typeof WM !== "undefined") { WM.base = null; WM.seen = {}; WM.data = null; } refresh(); };
$("#gmin").onchange = () => loadGraph(true);
$("#gscope").onchange = () => loadGraph(true);
$("#wmin").onchange = () => loadWorld();
$("#gfit").onclick = () => { if (typeof nmFit === "function") nmFit(true); };
$("#imin").onchange = $("#istatus").onchange = loadIncidents;
exportDefaults();
$("#xbtn").onclick = exportJson;
$("#emin").onchange = () => loadEvents();
$("#esrc").onchange = () => loadEvents();
$("#dclose").onclick = closeDrawer;
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => { if (typeof nmFit === "function") nmFit(false); }, 250); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

// a script that failed to load (404, proxy, extension) is named in the banner; the page keeps working without it
window.addEventListener("error", e => {
  const t = e.target;
  if (t && t.tagName === "SCRIPT") partErr("Script " + (t.src || "").split("/").pop(), new Error("failed to load"));
}, true);
window.addEventListener("load", () => {
  const want = {"vis-network.min.js": typeof vis, "topojson-client.min.js": typeof topojson, "icons.js": typeof ICONS,
    "netmap.js": typeof loadGraph, "worldmap.js": typeof loadWorld, "wall.js": typeof enterWall};
  for (const [f, t] of Object.entries(want)) if (t === "undefined") partErr("Script " + f, new Error("not loaded"));
});
try { legend(); } catch (e) { partErr("Map legend", e); }
(async () => {
  try { st.role = (await api("/api/whoami")).role; } catch (e) { st.role = null; }
  if (location.pathname === "/wall" || location.hash === "#wall") {
    try { need(typeof enterWall !== "undefined" && enterWall, "wall.js")(false); } catch (e) { partErr("Wall", e); }
  }
  await refresh();
  const m = location.hash.match(/^#(incident|host)\/(.+)$/);
  if (m && !st.wall) (m[1] === "incident" ? openIncident(m[2]) : openHost(decodeURIComponent(m[2])));
  setInterval(refresh, 5000);
})();
