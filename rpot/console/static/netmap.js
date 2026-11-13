/* ReD-Pot internal network map — topology layout, icons, animated packet flow, attack-path focus.
   Left: your subnets (zones) with workstations. Right: the ReD-Pot trap zone with the decoy servers.
   Edges carry animated "packets" (colour = severity, density = volume, brightness = recency). */
"use strict";
const NM = {net: null, nodes: null, edges: null, raw: null, layoutKey: "", focus: null, path: [], potImg: null, last: 0, skew: 0};

function legend() {
  const ico = (src, t) => `<span><img src="${src}" alt="" style="width:18px;height:18px;vertical-align:-4px">${t}</span>`;
  $("#legend").innerHTML =
    ico(ICONS.workstation("#6f9cff", 1), "workstation") + ico(ICONS.workstation("#f12c35", 4), "attacker (L4+)") +
    ico(ICONS.sensor("windows-file-server", true), "decoy server") + ico(ICONS.canary(), "bait docs") +
    [2, 3, 4, 5].map(l => `<span><i style="background:${LCOL[l]}"></i>${LV[l]}</span>`).join("");
}

const nmAge = ts => Math.max(0, Date.now() + NM.skew - Date.parse(ts));
const nmRec = ts => Math.max(0.15, Math.exp(-nmAge(ts) / (st.hours * 3600e3 / 4)));

function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`;
}

/* ---------- layout: deterministic positions (no physics hairball) ---------- */
function nmLayout(g) {
  const hosts = g.nodes.filter(n => n.kind === "host");
  const sensors = g.nodes.filter(n => n.kind === "sensor").sort((a, b) => a.label.localeCompare(b.label));
  const canary = g.nodes.filter(n => n.kind === "canary");
  const bySub = {};
  for (const h of hosts) (bySub[h.subnet] = bySub[h.subnet] || []).push(h);
  const subs = Object.keys(bySub).sort((a, b) => (a === "Internet") - (b === "Internet") || a.localeCompare(b, undefined, {numeric: true}));
  // hosts are stacked in columns (max 7 per column) so every connection leaves a host towards the
  // trap zone without crossing the other PCs; the most severe hosts sit in the right-most column.
  const CW = 230, CH = 140, PER = 7, pos = {}, zones = [];
  const cols = {};
  for (const s of subs) cols[s] = Math.ceil(bySub[s].length / PER);
  const maxCols = Math.max(1, ...Object.values(cols));
  let y = 0, maxW = (maxCols - 1) * CW;
  for (const s of subs) {
    const list = bySub[s].sort((a, b) => b.level - a.level || a.ip.localeCompare(b.ip, undefined, {numeric: true}));
    const c = cols[s], rows = Math.min(PER, list.length);
    list.forEach((h, i) => {
      const col = Math.floor(i / PER), row = i % PER;
      pos[h.id] = {x: maxW - col * CW, y: y + 70 + row * CH};
    });
    zones.push({sub: s, ids: list.map(h => h.id), n: list.length});
    y += 70 + rows * CH + 60;
  }
  const leftH = Math.max(0, y - 40);
  const right = [...sensors, ...canary];
  const SX = maxW + 560, SH = 175;
  const rightH = 70 + Math.max(0, right.length - 1) * SH;
  const off = (leftH - rightH) / 2;
  right.forEach((n, i) => { pos[n.id] = {x: SX, y: off + 70 + i * SH}; });
  return {pos, zones, trap: right.map(n => n.id)};
}

function nodeVis(n, L) {
  const p = L.pos[n.id] || {x: 0, y: 0};
  const font = {color: "#e8e8ea", face: "Inter, Segoe UI, sans-serif", size: 14, strokeWidth: 4, strokeColor: "#0a0a0c", multi: "html"};
  if (n.kind === "sensor" || n.kind === "canary") {
    const hot = n.last && nmAge(n.last) < 300e3;
    return {id: n.id, raw: n, x: p.x, y: p.y, shape: "image", size: 40,
      image: n.kind === "canary" ? ICONS.canary() : ICONS.sensor(n.role, n.online, hot),
      label: n.kind === "canary" ? "<b>Bait documents</b>\n<i>beacons</i>" : `<b>${esc(n.label)}</b>\n<i>${esc(ROLE_TITLE[n.role] || n.role)}</i>`,
      font: Object.assign({}, font, {size: 15, ital: {color: "#a7a7b0", size: 12}, bold: {color: "#ffffff", size: 16}}),
      title: `${n.label} — ${ROLE_TITLE[n.role] || n.role}${n.ip ? " · " + n.ip : ""}${n.online === false ? " (offline)" : ""}`};
  }
  const c = LCOL[n.level] || LCOL[1];
  const [ip, ...rest] = n.label.split(" ");
  const name = rest.join(" ");
  const dimmed = NM.focus && NM.focus !== n.ip;
  return {id: n.id, raw: n, x: p.x, y: p.y, shape: "image", size: 28 + (n.level >= 4 ? 4 : 0),
    image: ICONS.workstation(n.level >= 2 ? c : "#6f9cff", n.level, !n.internal), opacity: dimmed ? .25 : 1,
    label: name ? `<b>${esc(name)}</b>\n<code>${esc(ip)}</code>` : `<code>${esc(ip)}</code>`,
    font: Object.assign({}, font, {size: 13, bold: {color: "#ffffff", size: 14}, mono: {color: "#a7a7b0", size: 12, face: "ui-monospace, monospace"}}),
    title: `${n.label} · max ${LV[n.level]} (L${n.level}) · click for timeline`};
}

function edgeVis(e) {
  const rec = nmRec(e.last), c = LCOL[e.level];
  const dim = NM.focus && e.from !== "h:" + NM.focus;
  return {id: e.from + ">" + e.to, from: e.from, to: e.to, raw: e,
    width: (1 + Math.min(4, Math.log2(1 + e.count) * .7)) * (dim ? .6 : 1),
    color: {color: hexA(c, dim ? .06 : .18 + .55 * rec), highlight: c, hover: c},
    smooth: {enabled: true, type: "cubicBezier", forceDirection: "horizontal", roundness: .55},
    arrows: {to: {enabled: false}}, selectionWidth: 1.5, hoverWidth: 1,
    title: `${LV[e.level]} (L${e.level}) · ${e.count} events · ${e.protos}\nlast ${ago(e.last)}`};
}

/* ---------- canvas overlays: zones (below), packets + pulses + path numbers (above) ---------- */
function rr(ctx, x, y, w, h, r) {
  ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
}

function bbox(ids) {
  const P = NM.net.getPositions(ids);
  const xs = ids.map(i => P[i] && P[i].x).filter(v => v != null), ys = ids.map(i => P[i] && P[i].y).filter(v => v != null);
  if (!xs.length) return null;
  return {x0: Math.min(...xs), x1: Math.max(...xs), y0: Math.min(...ys), y1: Math.max(...ys)};
}

function drawZones(ctx) {
  if (!NM.L) return;
  for (const z of NM.L.zones) {
    const b = bbox(z.ids); if (!b) continue;
    const ext = z.sub === "Internet";
    const x = b.x0 - 85, y = b.y0 - 92, w = b.x1 - b.x0 + 170, h = b.y1 - b.y0 + 175;
    rr(ctx, x, y, w, h, 16);
    ctx.fillStyle = ext ? "rgba(255,120,100,.04)" : "rgba(80,140,255,.045)"; ctx.fill();
    ctx.setLineDash([7, 6]); ctx.lineWidth = 1.5; ctx.strokeStyle = ext ? "#5a2a24" : "#26405f"; ctx.stroke(); ctx.setLineDash([]);
    ctx.font = "700 14px ui-monospace, monospace"; ctx.fillStyle = ext ? "#ffb4a8" : "#9ad1ff"; ctx.textAlign = "left";
    ctx.fillText(ext ? "INTERNET" : z.sub, x + 16, y + 26);
    ctx.font = "12px Inter, sans-serif"; ctx.fillStyle = "#77777f";
    ctx.fillText(`${z.n} host${z.n > 1 ? "s" : ""}${ext ? "" : " · your network"}`, x + 16, y + 44);
  }
  const b = bbox(NM.L.trap); if (!b) return;
  const x = b.x0 - 170, y = b.y0 - 110, w = b.x1 - b.x0 + 340, h = b.y1 - b.y0 + 200;
  rr(ctx, x, y, w, h, 18);
  const gr = ctx.createLinearGradient(x, y, x + w, y + h);
  gr.addColorStop(0, "rgba(241,44,53,.10)"); gr.addColorStop(1, "rgba(241,44,53,.03)");
  ctx.fillStyle = gr; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = "#5c1418"; ctx.stroke();
  if (NM.potImg && NM.potImg.complete) ctx.drawImage(NM.potImg, x + 12, y + 8, 34, 34);
  ctx.font = "800 14px Inter, sans-serif"; ctx.fillStyle = "#ff5a62"; ctx.fillText("ReD-Pot TRAP ZONE", x + 52, y + 26);
  ctx.font = "12px Inter, sans-serif"; ctx.fillStyle = "#8d8d96"; ctx.fillText("decoy servers — nobody should touch them", x + 52, y + 42);
}

function edgePoint(id, t, from, to) {
  try {
    const e = NM.net.body.edges[id];
    if (e && e.edgeType && e.edgeType.getPoint) return e.edgeType.getPoint(t);
  } catch (err) { /* fall back to a straight line */ }
  return {x: from.x + (to.x - from.x) * t, y: from.y + (to.y - from.y) * t};
}

function drawOverlay(ctx) {
  if (!NM.raw) return;
  const now = performance.now();
  const P = NM.net.getPositions();
  // packets flowing attacker → decoy
  for (const e of NM.raw.edges) {
    if (e.kind === "member") continue;
    const id = e.from + ">" + e.to, a = P[e.from], b = P[e.to];
    if (!a || !b) continue;
    const dim = NM.focus && e.from !== "h:" + NM.focus;
    const rec = nmRec(e.last);
    if (dim || rec < .2) continue;
    const n = 1 + Math.min(4, Math.round(Math.log2(1 + e.count)));
    const period = Math.max(1100, 3400 - e.level * 420);
    const c = LCOL[e.level];
    for (let k = 0; k < n; k++) {
      const t = ((now / period) + k / n + (id.length % 7) / 7) % 1;
      for (let tr = 0; tr < 5; tr++) {                       // comet tail
        const tt = t - tr * .012; if (tt < 0) continue;
        const p = edgePoint(id, tt, a, b);
        ctx.globalAlpha = rec * (1 - tr / 5);
        ctx.fillStyle = c; ctx.beginPath(); ctx.arc(p.x, p.y, (e.level >= 5 ? 5 : 4) - tr * .6, 0, 7); ctx.fill();
      }
    }
  }
  ctx.globalAlpha = 1;
  // pulses: hosts at L5 (purple alarm) and decoys hit in the last 5 minutes
  for (const n of NM.raw.nodes) {
    const p = P[n.id]; if (!p) continue;
    let col = null;
    if (n.kind === "host" && n.level >= 5 && n.last && nmAge(n.last) < 3600e3) col = LCOL[5];
    else if (n.kind === "host" && n.level >= 4 && n.last && nmAge(n.last) < 900e3) col = LCOL[4];
    else if ((n.kind === "sensor" || n.kind === "canary") && n.last && nmAge(n.last) < 300e3) col = "#f12c35";
    if (!col || (NM.focus && n.kind === "host" && n.ip !== NM.focus)) continue;
    const ph = (now / 1600 + (n.id.length % 5) / 5) % 1;
    ctx.strokeStyle = col; ctx.globalAlpha = (1 - ph) * .9; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.arc(p.x, p.y, 36 + ph * 34, 0, 7); ctx.stroke();
  }
  ctx.globalAlpha = 1;
  // attack path numbers ①②③ on the decoys, in the order the focused host touched them
  NM.path.forEach((hop, i) => {
    const p = P[hop.sensor === "CANARY" ? "s:CANARY" : "s:" + hop.sensor]; if (!p) return;
    const x = p.x - 46, y = p.y - 46;
    ctx.fillStyle = LCOL[hop.lvl] || "#f12c35"; ctx.beginPath(); ctx.arc(x, y, 15, 0, 7); ctx.fill();
    ctx.lineWidth = 3; ctx.strokeStyle = "#0a0a0c"; ctx.stroke();
    ctx.fillStyle = "#fff"; ctx.font = "800 15px Inter, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(String(i + 1), x, y + 1); ctx.textBaseline = "alphabetic"; ctx.textAlign = "left";
  });
}

/* ---------- data load / update ---------- */
async function loadGraph(refit) {
  const g = await api(`/api/graph?hours=${st.hours}&min_level=${$("#gmin").value}&scope=${$("#gscope").value}`);
  if (g.now) NM.skew = Date.parse(g.now) - Date.now();
  // last-seen per decoy for the "hit recently" pulse
  const lastBy = {};
  for (const e of g.edges) if (e.kind !== "member") lastBy[e.to] = lastBy[e.to] > e.last ? lastBy[e.to] : e.last;
  for (const e of g.edges) if (e.kind !== "member") { const h = g.nodes.find(n => n.id === e.from); if (h) h.last = h.last > e.last ? h.last : e.last; }
  g.nodes.forEach(n => { if (n.kind === "sensor" || n.kind === "canary") n.last = lastBy[n.id]; });
  NM.raw = g;
  const L = nmLayout(g);
  NM.L = L;
  const vnodes = g.nodes.filter(n => n.kind !== "subnet").map(n => nodeVis(n, L));
  const vedges = g.edges.filter(e => e.kind !== "member").map(edgeVis);
  const key = vnodes.map(n => n.id).sort().join("|");
  if (!NM.net) {
    NM.potImg = new Image(); NM.potImg.src = ICONS.pot;
    NM.nodes = new vis.DataSet(vnodes); NM.edges = new vis.DataSet(vedges);
    NM.net = new vis.Network($("#graph"), {nodes: NM.nodes, edges: NM.edges}, {
      physics: false, interaction: {hover: true, tooltipDelay: 150, dragNodes: true, zoomView: true},
      nodes: {shapeProperties: {useImageSize: false, interpolation: true}, chosen: {node: (v) => { v.size *= 1.12; }}},
      edges: {chosen: {edge: (v) => { v.width += 1.5; }}}});
    NM.net.on("beforeDrawing", drawZones);
    NM.net.on("afterDrawing", drawOverlay);
    NM.net.on("click", p => {
      if (!p.nodes.length) { if (NM.focus) closeDrawer(); return; }
      const n = NM.nodes.get(p.nodes[0]).raw;
      if (n.kind === "host") openHost(n.ip);
      else switchView("deception");
    });
    NM.layoutKey = key;
    setTimeout(() => nmFit(false), 30);
    nmAnimate();
    return;
  }
  const nid = new Set(vnodes.map(n => n.id)), eid = new Set(vedges.map(e => e.id));
  NM.nodes.remove(NM.nodes.getIds().filter(i => !nid.has(i)));
  NM.edges.remove(NM.edges.getIds().filter(i => !eid.has(i)));
  // keep user-dragged positions unless the set of nodes changed
  if (key === NM.layoutKey) vnodes.forEach(n => { delete n.x; delete n.y; });
  NM.nodes.update(vnodes); NM.edges.update(vedges);
  if (refit || key !== NM.layoutKey) { NM.layoutKey = key; nmFit(true); }
}

/* fit icons AND the zone boxes/labels drawn around them (vis only knows about the icons) */
function nmFit(anim) {
  if (!NM.net) return;
  const P = NM.net.getPositions(), ids = Object.keys(P);
  if (!ids.length) return;
  const xs = ids.map(i => P[i].x), ys = ids.map(i => P[i].y);
  const x0 = Math.min(...xs) - 150, x1 = Math.max(...xs) + 200, y0 = Math.min(...ys) - 140, y1 = Math.max(...ys) + 130;
  const el = $("#graph"), W = el.clientWidth || 800, H = el.clientHeight || 600;
  const scale = Math.min(1.1, W / (x1 - x0), H / (y1 - y0));
  NM.net.moveTo({position: {x: (x0 + x1) / 2, y: (y0 + y1) / 2}, scale,
    animation: anim ? {duration: 500, easingFunction: "easeInOutQuad"} : false});
}

function nmAnimate(ts) {
  requestAnimationFrame(nmAnimate);
  if (!NM.net || st.view !== "overview" || document.hidden) return;
  if (ts - NM.last < 33) return;      // ~30 fps is plenty and keeps CPU low
  NM.last = ts;
  NM.net.redraw();
}

/* focus a host: dim everything else and number its attack path; null = clear */
function netFocus(ip, path) {
  NM.focus = ip || null;
  NM.path = ip ? (path || []) : [];
  if (!NM.raw || !NM.net) return;
  NM.nodes.update(NM.raw.nodes.filter(n => n.kind === "host").map(n => {
    const v = nodeVis(n, NM.L); delete v.x; delete v.y; return v;
  }));
  NM.edges.update(NM.raw.edges.filter(e => e.kind !== "member").map(edgeVis));
}
