/* ReD-Pot world attack map — public (non-internal) sources, offline GeoIP, canvas rendering. */
"use strict";
const WM = {
  world: null, n2a: null, feats: [], centroid: {}, data: null, canvas: null, ctx: null, W: 0, H: 0, dpr: 1,
  arcs: [], seen: {}, hover: null, raf: 0, latTop: 84, latBot: -58, lastDraw: 0, tint: {},
};

async function wmInit() {
  if (WM.world) return;
  const [w, n2a] = await Promise.all([fetch("/static/vendor/countries-110m.json").then(r => r.json()),
    fetch("/static/vendor/iso-numeric-alpha2.json").then(r => r.json())]);
  WM.world = w; WM.n2a = n2a;
  const fc = topojson.feature(w, w.objects.countries);
  WM.feats = fc.features.map(f => {
    const cc = f.id ? n2a[f.id] : ({"Kosovo": "XK", "N. Cyprus": "CY", "Somaliland": "SO"})[f.properties.name];
    const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
    // centroid of the largest ring (for country-only GeoIP)
    let best = null, bestA = 0;
    for (const p of polys) {
      const ring = p[0]; let a = 0, cx = 0, cy = 0;
      for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
        const f1 = ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
        a += f1; cx += (ring[j][0] + ring[i][0]) * f1; cy += (ring[j][1] + ring[i][1]) * f1;
      }
      if (Math.abs(a) > bestA) { bestA = Math.abs(a); best = [cx / (3 * a), cy / (3 * a)]; }
    }
    if (cc && best && !WM.centroid[cc]) WM.centroid[cc] = best;
    return {cc, name: f.properties.name, polys};
  });
  WM.canvas = $("#wmap");
  WM.ctx = WM.canvas.getContext("2d");
  new ResizeObserver(wmResize).observe(WM.canvas.parentElement);
  WM.canvas.addEventListener("mousemove", wmMove);
  WM.canvas.addEventListener("mouseleave", () => { WM.hover = null; $("#wtip").style.display = "none"; });
  WM.canvas.addEventListener("click", () => { if (WM.hover && !st.wall) openHost(WM.hover.ip); });
  wmResize();
}

function wmResize() {
  const zoom = st.wall ? (st.zoom || 1) : 1;
  const box = WM.canvas.parentElement.getBoundingClientRect();
  WM.dpr = (window.devicePixelRatio || 1) * zoom;          // stay sharp when the wall layout is zoomed
  const aspect = 360 / (WM.latTop - WM.latBot);
  WM.W = Math.max(300, box.width / zoom);
  WM.H = Math.round(WM.W / aspect);
  if (st.wall && st.mapMaxH && WM.H > st.mapMaxH) {        // wall: fit height, centre horizontally
    WM.H = Math.round(st.mapMaxH); WM.W = Math.round(WM.H * aspect);
  }
  WM.k = Math.max(1, WM.W / 1100);                          // marker/label scale
  WM.canvas.style.width = WM.W + "px";
  WM.canvas.style.height = WM.H + "px";
  WM.canvas.width = WM.W * WM.dpr; WM.canvas.height = WM.H * WM.dpr;
  WM.base = null;
}

/* recency: 1 = just now, fades exponentially over the selected range, floor 0.12 */
const wmAge = ts => Math.max(0, Date.now() + (WM.skew || 0) - Date.parse(ts));
const wmRec = ts => Math.max(0.12, Math.exp(-wmAge(ts) / (st.hours * 3600e3 / 4)));
const LIVE_MS = 3600e3;

const proj = (lon, lat) => [(lon + 180) / 360 * WM.W, (WM.latTop - Math.max(WM.latBot, Math.min(WM.latTop, lat))) / (WM.latTop - WM.latBot) * WM.H];

function wmPos(p) {
  if (p.lat != null && p.lon != null) return [p.lon, p.lat];
  const c = p.cc && WM.centroid[p.cc];
  if (!c) return null;
  // deterministic jitter so many IPs from one country do not stack exactly
  let h = 0; for (const ch of p.ip) h = (h * 31 + ch.charCodeAt(0)) | 0;
  return [c[0] + ((h & 255) / 255 - .5) * 3, c[1] + (((h >> 8) & 255) / 255 - .5) * 2];
}

/* Decoy positions: every decoy sits at the GeoIP location of its own public address (server-side), decoys on
   private addresses at the configured site (rpotctl.py site) or the manager's public IP. Decoys in the same
   place are drawn as ONE marker labelled with their names. No position known → no marker (never a guessed one). */
function wmSites(d) {
  const groups = {}, byName = {};
  for (const s of d.sensors || []) {
    if (s.lat == null || s.lon == null) continue;
    const k = `${(+s.lat).toFixed(1)},${(+s.lon).toFixed(1)}`;
    const g = groups[k] || (groups[k] = {lat: +s.lat, lon: +s.lon, names: [], online: false, from: s.from});
    g.names.push(s.name); g.online = g.online || !!s.online;
    byName[s.name] = g;
  }
  const site = d.site || {};
  if (site.lat != null) {            // bait documents call the manager → the site / manager position
    const k = `${(+site.lat).toFixed(1)},${(+site.lon).toFixed(1)}`;
    byName.CANARY = groups[k] || (groups[k] = {lat: +site.lat, lon: +site.lon, names: [], online: true, from: site.from});
  }
  WM.groups = Object.values(groups);
  WM.byName = byName;
}
const wmLabel = g => g.names.length ? (g.names.length > 3 ? `${g.names.slice(0, 3).join(", ")} +${g.names.length - 3}` : g.names.join(", "))
  : ((WM.data.site && WM.data.site.name) || "ReD-Pot");
/* targets of one source point = the groups of the decoys it actually attacked */
function wmTargets(p) {
  const out = [];
  for (const n of p.sensors || []) { const g = WM.byName && WM.byName[n]; if (g && !out.includes(g)) out.push(g); }
  return out;
}

function drawBase() {
  // static layer: countries (tinted by attack volume) + graticule
  const c = document.createElement("canvas");
  c.width = WM.canvas.width; c.height = WM.canvas.height;
  const g = c.getContext("2d");
  g.scale(WM.dpr, WM.dpr);
  g.fillStyle = "#08080a"; g.fillRect(0, 0, WM.W, WM.H);
  g.strokeStyle = "#15151a"; g.lineWidth = 1;
  for (let lon = -180; lon <= 180; lon += 30) { const [x] = proj(lon, 0); g.beginPath(); g.moveTo(x, 0); g.lineTo(x, WM.H); g.stroke(); }
  for (let lat = -60; lat <= 80; lat += 20) { const [, y] = proj(0, lat); g.beginPath(); g.moveTo(0, y); g.lineTo(WM.W, y); g.stroke(); }
  for (const f of WM.feats) {
    const t = WM.tint[f.cc] || 0;   // 0..1 = volume share × recency
    g.fillStyle = t ? `rgba(241,44,53,${.08 + .62 * t})` : "#17171c";
    g.strokeStyle = t ? `rgba(255,90,98,${.35 + .65 * t})` : "#2a2a31"; g.lineWidth = t ? .9 : .6;
    g.beginPath();
    for (const poly of f.polys) for (const ring of poly) {
      // unwrap longitudes so rings crossing the antimeridian (Russia, Fiji) stay continuous,
      // then draw a second copy shifted by 360° for the part that falls off the map edge
      let prev = null, lo = 999, hi = -999;
      const un = ring.map(pt => {
        let lon = pt[0];
        if (prev !== null) { while (lon - prev > 180) lon -= 360; while (lon - prev < -180) lon += 360; }
        prev = lon; lo = Math.min(lo, lon); hi = Math.max(hi, lon);
        return [lon, pt[1]];
      });
      const shifts = [0];
      if (hi > 180) shifts.push(-360);
      if (lo < -180) shifts.push(360);
      for (const sh of shifts) {
        un.forEach((pt, i) => { const x = (pt[0] + sh + 180) / 360 * WM.W, y = proj(0, pt[1])[1]; i ? g.lineTo(x, y) : g.moveTo(x, y); });
        g.closePath();
      }
    }
    g.fill("evenodd"); g.stroke();
  }
  WM.base = c;
}

function arcPath(a, b) {
  const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
  const d = Math.hypot(b[0] - a[0], b[1] - a[1]);
  return [a, [mx, my - Math.min(160, d * .35)], b];
}
const qpt = (p, t) => [(1 - t) * (1 - t) * p[0][0] + 2 * (1 - t) * t * p[1][0] + t * t * p[2][0],
  (1 - t) * (1 - t) * p[0][1] + 2 * (1 - t) * t * p[1][1] + t * t * p[2][1]];

function wmFrame(now) {
  WM.raf = requestAnimationFrame(wmFrame);
  if (st.view !== "worldmap" || !WM.data) return;
  if (!WM.base) drawBase();
  const g = WM.ctx;
  g.setTransform(WM.dpr, 0, 0, WM.dpr, 0, 0);
  g.drawImage(WM.base, 0, 0, WM.W, WM.H);
  const xy = gr => proj(gr.lon, gr.lat);
  // persistent faint arcs: attacker → the decoy(s) it attacked
  for (const p of WM.data.points) {
    if (!p._xy) continue;
    for (const t of wmTargets(p)) {
      const a = arcPath(p._xy, xy(t));
      g.strokeStyle = LCOL[p.level]; g.globalAlpha = .05 + .22 * p._rec; g.lineWidth = 1;
      g.beginPath(); g.moveTo(a[0][0], a[0][1]); g.quadraticCurveTo(a[1][0], a[1][1], a[2][0], a[2][1]); g.stroke();
      g.globalAlpha = 1;
    }
  }
  // animated attack comets
  WM.arcs = WM.arcs.filter(x => now - x.t0 < x.dur + 900);
  for (const x of WM.arcs) {
    const t = Math.min(1, (now - x.t0) / x.dur);
    const site = xy(x.to);
    const a = arcPath(x.from, site);
    g.lineWidth = 2;
    for (let k = 0; k < 14; k++) {
      const tt = Math.max(0, t - k * .018), pt = qpt(a, tt);
      g.fillStyle = LCOL[x.level]; g.globalAlpha = (1 - k / 14) * (t < 1 ? 1 : Math.max(0, 1 - (now - x.t0 - x.dur) / 900));
      g.beginPath(); g.arc(pt[0], pt[1], 2.6 - k * .14, 0, 7); g.fill();
    }
    g.globalAlpha = 1;
    if (t >= 1) { // impact ring
      const r = 6 + (now - x.t0 - x.dur) / 30;
      g.strokeStyle = LCOL[x.level]; g.globalAlpha = Math.max(0, 1 - (now - x.t0 - x.dur) / 900);
      g.beginPath(); g.arc(site[0], site[1], r, 0, 7); g.stroke(); g.globalAlpha = 1;
    }
  }
  // sources
  for (const p of WM.data.points) {
    if (!p._xy) continue;
    const [x, y] = p._xy, r = (2.5 + Math.min(7, Math.log2(1 + p.count))) * WM.k;
    if (p.level >= 3 && p._live) {     // pulse only for activity in the last hour
      const ph = ((now / 1400) + (p.ip.length % 7) / 7) % 1;
      g.strokeStyle = LCOL[p.level]; g.globalAlpha = 1 - ph; g.lineWidth = 1.2;
      g.beginPath(); g.arc(x, y, r + ph * 14 * WM.k, 0, 7); g.stroke(); g.globalAlpha = 1;
    }
    g.globalAlpha = .25 + .75 * p._rec;
    g.fillStyle = LCOL[p.level]; g.beginPath(); g.arc(x, y, r, 0, 7); g.fill();
    g.globalAlpha = 1;
    if (WM.hover === p) { g.strokeStyle = "#fff"; g.lineWidth = 2; g.beginPath(); g.arc(x, y, r + 3, 0, 7); g.stroke(); }
  }
  // decoys (one marker per place, labelled with the decoy names)
  const pul = (now / 900) % 1;
  g.font = `600 ${Math.round(12 * WM.k)}px Inter, Segoe UI, sans-serif`; g.textAlign = "left";
  for (const gr of WM.groups || []) {
    const site = xy(gr);
    g.strokeStyle = "#f12c35"; g.globalAlpha = 1 - pul; g.lineWidth = 2;
    g.beginPath(); g.arc(site[0], site[1], (8 + pul * 22) * WM.k, 0, 7); g.stroke(); g.globalAlpha = 1;
    hexAt(g, site[0], site[1], 9 * WM.k);
    const lbl = wmLabel(gr);
    g.lineWidth = 4; g.strokeStyle = "#0a0a0c"; g.strokeText(lbl, site[0] + 14 * WM.k, site[1] + 4 * WM.k);
    g.fillStyle = "#fff"; g.fillText(lbl, site[0] + 14 * WM.k, site[1] + 4 * WM.k);
  }
  if (!(WM.groups || []).length) {     // no decoy position known: say so instead of pinning a wrong country
    const msg = "Decoy location not set (private addresses, no site) — rpotctl.py site -d DIR --name HQ --lat .. --lon ..";
    g.lineWidth = 4; g.strokeStyle = "#0a0a0c"; g.fillStyle = "#e3b341";
    g.strokeText(msg, 12 * WM.k, 20 * WM.k); g.fillText(msg, 12 * WM.k, 20 * WM.k);
  }
}

function hexAt(g, x, y, r) {
  g.beginPath();
  for (let i = 0; i < 6; i++) { const a = Math.PI / 3 * i - Math.PI / 2; const px = x + r * Math.cos(a), py = y + r * Math.sin(a); i ? g.lineTo(px, py) : g.moveTo(px, py); }
  g.closePath(); g.fillStyle = "#0a0a0c"; g.fill(); g.strokeStyle = "#f12c35"; g.lineWidth = 3; g.stroke();
}

function wmMove(ev) {
  if (!WM.data || st.wall) return;
  const r = WM.canvas.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
  let best = null, bd = 12;
  for (const p of WM.data.points) {
    if (!p._xy) continue;
    const d = Math.hypot(p._xy[0] - mx, p._xy[1] - my);
    if (d < bd) { bd = d; best = p; }
  }
  WM.hover = best;
  const tip = $("#wtip");
  WM.canvas.style.cursor = best ? "pointer" : "default";
  if (!best) { tip.style.display = "none"; return; }
  tip.innerHTML = `<b class="mono">${esc(best.ip)}</b> ${lvs(best.level)}<br>${flag(best.cc)} ${esc([best.city, best.country].filter(Boolean).join(", ") || "unknown location")}
    <br><span class="muted">${esc(best.org ? `AS${best.asn} ${best.org}` : "")}</span>
    <br>${best.count} events → ${esc(best.sensors.join(", "))} <span class="muted">(${esc(best.protos || "")})</span><br><span class="age ${best._live ? "live" : ""}">last ${ago(best.last)}</span> <span class="muted">click for timeline</span>`;
  tip.style.display = "block";
  tip.style.left = Math.min(mx + 14, WM.W - 260) + "px";
  tip.style.top = (my + 14) + "px";
}

const flag = cc => `<span class="cc">${esc(cc && cc.length === 2 ? cc : "??")}</span>`;

async function loadWorld() {
  await wmInit();
  const d = await api(`/api/worldmap?hours=${st.hours}&min_level=${$("#wmin").value}`);
  const prev = WM.data;
  WM.data = d;
  WM.skew = Date.parse(d.now) - Date.now();
  wmSites(d);
  for (const p of d.points) {
    const ll = wmPos(p);
    p._xy = ll ? proj(ll[0], ll[1]) : null;
    p._rec = wmRec(p.last);
    p._live = wmAge(p.last) < LIVE_MS;
  }
  // country tint = sqrt(volume share) × recency of the country's latest event, quantised to avoid redraw churn
  const maxEv = Math.max(1, ...d.countries.map(c => c.events));
  const tint = {};
  for (const c of d.countries) if (c.cc !== "??") tint[c.cc] = Math.round(Math.sqrt(c.events / maxEv) * wmRec(c.last) * 20) / 20;
  if (JSON.stringify(tint) !== JSON.stringify(WM.tint)) { WM.tint = tint; WM.base = null; }
  // new activity → launch comets (on first load: replay the most recent ones)
  const now = performance.now();
  let i = 0;
  for (const p of d.points) {
    if (!p._xy) continue;
    const key = p.ip, before = WM.seen[key];
    if (!prev || before !== p.last) {
      for (const t of wmTargets(p)) {
        if (prev || i < 25) WM.arcs.push({from: p._xy, to: t, level: p.level, t0: now + (i++ % 25) * 180, dur: 1300 + Math.random() * 600});
      }
    }
    WM.seen[key] = p.last;
  }
  if (!WM.raf) WM.raf = requestAnimationFrame(wmFrame);

  const tot = d.points.length;
  $("#wstats").innerHTML = `<span><b>${tot}</b> public sources</span><span><b>${d.countries.filter(c => c.cc !== "??").length}</b> countries</span>
    <span><b>${d.points.filter(p => p.level >= 3).length}</b> with intent+</span>${d.nogeo ? `<span class="muted">${d.nogeo} without location</span>` : ""}`;
  $("#wcountries").innerHTML = d.countries.length ? d.countries.map(c => `<div class="row" title="last attack ${ago(c.last)}"><span>${flag(c.cc)} ${esc(c.country)}</span>
    <span class="bar"><i style="width:${Math.max(4, 100 * c.events / maxEv)}%;background:${LCOL[c.level]};opacity:${(.35 + .65 * wmRec(c.last)).toFixed(2)}"></i></span>
    <span class="mono">${c.events} <span class="age ${wmAge(c.last) < 300e3 ? "live" : ""}">${ago(c.last)}</span></span></div>`).join("")
    : `<div class="empty">No public sources in this range.</div>`;
  $("#worgs").innerHTML = d.orgs.map(o => `<div class="row"><span title="AS${esc(o.asn)}">${esc(o.org)}</span><span class="mono muted">AS${esc(o.asn)}</span><span class="mono">${esc(o.events)}</span></div>`).join("") || `<div class="empty">—</div>`;
  $("#wfeed").innerHTML = d.feed.map(e => `<div class="row click" data-ip="${esc(e.src_ip)}"><span>${lvs(e.level)}</span>
    <span>${flag(e.cc)} <span class="mono">${esc(e.src_ip)}</span><br><span class="muted">${esc(e.desc)}</span></span><span class="age ${wmAge(e.ts) < 300e3 ? "live" : ""}">${ago(e.ts)}</span></div>`).join("") || `<div class="empty">—</div>`;
  if (!st.wall) $$("#wfeed [data-ip]").forEach(r => r.onclick = () => openHost(r.dataset.ip));
  $("#wfeedinfo").textContent = `newest first · refreshes every 5 s`;
  wmNotice(d.notice);
  wmSiteInfo(d);
  $("#wattr").textContent = d.geo_sources.length ? `IP geolocation by DB-IP (db-ip.com), CC BY 4.0 · ${d.geo_sources.join(", ")}` :
    "No GeoIP database loaded — run: rpotctl.py geoip -d DEPLOY_DIR, then restart the console";
}

// Why is the map empty? Shown over the map (dashboard: can be closed per reason; wall: always, small).
function wmNotice(n) {
  let box = document.getElementById("wnotice");
  if (!n) { if (box) box.remove(); return; }
  const key = "rpot.wnotice." + n.reasons.join("+");
  let closed = false;
  try { closed = !st.wall && localStorage.getItem(key) === "1"; } catch (e) { /* private window */ }
  if (closed) { if (box) box.remove(); return; }
  const parts = [];
  if (n.reasons.includes("internal_only")) parts.push(`<b>No internet attackers can reach your decoys.</b> All of them are on internal
    addresses — normal for internal deception. This map only shows attackers with <b>public</b> IP addresses.
    ${n.internal_sources ? `<b>${n.internal_sources}</b> internal source(s) in this range are on <b>Overview → Internal network map</b>.` :
    "Attacks from inside your network appear on <b>Overview → Internal network map</b>."}
    <br><span class="muted">To see internet attackers here, add a decoy on a public IP (for example a sensor on a VPS).
    If you forward public ports to a decoy, you can ignore this.</span>`);
  if (n.reasons.includes("quiet")) parts.push(`<b>No public attackers in this time range yet.</b>
    <span class="muted">Choose a longer range, or wait — internet scanners usually arrive within hours.</span>`);
  if (n.reasons.includes("nogeo")) parts.push(`<b>GeoIP database is not installed</b> — attackers cannot be placed on the map.
    <br><span class="muted">On the manager run: <span class="mono">sudo ./install.sh geoip</span></span>`);
  if (!box) {
    box = document.createElement("div");
    box.id = "wnotice"; box.className = "wnotice";
    document.querySelector("#v-worldmap .wwrap").appendChild(box);
  }
  box.innerHTML = `${st.wall ? "" : `<button class="x" title="Hide this notice">×</button>`}<div>${parts.join("<hr>")}</div>`;
  const x = box.querySelector(".x");
  if (x) x.onclick = () => { try { localStorage.setItem(key, "1"); } catch (e) { /* ignore */ } box.remove(); };
}

// Where each decoy is drawn, and why (GeoIP of its own public IP / site / manager IP / not placed).
function wmSiteInfo(d) {
  const box = $("#wsites");
  if (!box) return;
  const why = s => s.from === "geoip" ? `${[s.city, s.cc].filter(Boolean).join(", ") || "GeoIP"}${s.approx ? " (country)" : ""}` :
    s.from === "site" ? `site ${d.site.name || ""}`.trim() : s.from === "manager" ? "manager's public IP" : null;
  const list = (d.sensors || []).map(s => why(s) ? `<span class="mono">${esc(s.name)}</span> <span class="muted">${esc(why(s))}</span>`
    : `<span class="mono">${esc(s.name)}</span> <span style="color:#e3b341">not placed</span>`);
  const unplaced = (d.sensors || []).filter(s => s.lat == null).length;
  box.innerHTML = list.length ? `Decoys on the map: ${list.join(" · ")}` + (unplaced ? `<br><span class="muted">Not placed = private address and no site
    set. Set it with <span class="mono">rpotctl.py site -d DEPLOY_DIR --name HQ --lat 40.18 --lon 44.51</span> (decoys with a public IP are placed by GeoIP).</span>` : "") : "";
}
