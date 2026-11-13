/* ReD-Pot wall mode: full-screen attack map for SOC screens (admin preview via #wall, or read-only /wall link). */
"use strict";
function wallLayout() {
  st.zoom = Math.max(.75, Math.min(3, window.innerWidth / 1600));
  const m = document.querySelector("main");
  m.style.zoom = st.zoom;
  const bar = $("#wallbar"); bar.style.zoom = st.zoom;
  const avail = window.innerHeight / st.zoom - bar.offsetHeight - 24;
  m.style.height = avail + "px";
  st.mapMaxH = avail * .64;
  if (WM.canvas) wmResize();
}

function enterWall(full) {
  st.wall = true; st.view = "worldmap";
  document.body.classList.add("wall");
  $$(".view").forEach(s => s.classList.toggle("on", s.id === "v-worldmap"));
  if (st.hours > 1) { st.hours = 1; $("#range").value = "1"; }
  if (full && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {});
  if (location.pathname !== "/wall") history.replaceState(null, "", "/wall");
  // browsers only allow full screen after a user gesture: first click / key on the wall goes full screen
  const fs = () => { if (!document.fullscreenElement && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {}); };
  document.addEventListener("click", fs, {once: true});
  wallLayout();
  tick(); setInterval(tick, 1000);
  let idle;
  const wake = () => { document.body.classList.remove("nocursor"); clearTimeout(idle); idle = setTimeout(() => document.body.classList.add("nocursor"), 3000); };
  document.addEventListener("mousemove", wake); wake();
}

function leaveWall() {
  if (!st.wall || st.role === "wall") return;   // kiosk (read-only) screens cannot leave
  if (document.fullscreenElement) { document.exitFullscreen().catch(() => {}); return; }  // 1st Esc: leave full screen
  location.href = "/";                                                                 // 2nd Esc: back to console
}

function tick() {
  const d = new Date();
  $("#wtime").textContent = d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false});
  $("#wdate").textContent = d.toLocaleDateString([], {weekday: "short", day: "2-digit", month: "short", year: "numeric"});
}

async function wallRefresh() {
  const t0 = Date.now();
  const s = await api(`/api/summary?hours=24`);
  if (typeof clockCheck === "function") clockCheck(s, t0, Date.now());   // wall "ago" = manager clock, skew banner
  await loadWorld();
  const d = WM.data, m15 = d.points.filter(p => wmAge(p.last) < 900e3);
  const site = d.site.name || "";
  $("#wco").textContent = site && site !== s.company ? `${s.company} · ${site}` : s.company;
  const k = [
    {t: "Sources 15m", n: m15.length, hot: m15.length > 0},
    {t: "Countries 1h", n: d.countries.filter(c => c.cc !== "??").length},
    {t: "Incidents 24h", n: s.real_incidents, hot: s.real_incidents > 0},
    {t: "Critical 24h", n: s.critical, hot: s.critical > 0},
    {t: "Honeytokens 24h", n: s.honeytokens, ht: s.honeytokens > 0},
    {t: "Sensors", n: `${s.sensors_online}/${s.sensors_total}`, bad: s.sensors_online < s.sensors_total},
  ];
  $("#wkpis").innerHTML = k.map(x => `<div class="${x.hot ? "hot" : ""} ${x.ht ? "ht" : ""} ${x.bad ? "bad" : ""}"><b>${esc(x.n)}</b><span>${esc(x.t)}</span></div>`).join("");
  $("#wlive").classList.remove("off");
}

window.addEventListener("resize", () => { if (st.wall) wallLayout(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") leaveWall(); });
