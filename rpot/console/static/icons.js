/* ReD-Pot icon set — inline SVG (renders the same on every OS, unlike emoji). */
"use strict";
const ICONS = (() => {
  const uri = svg => "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  const wrap = (body, w = 120, h = 120) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">${body}</svg>`;

  // server tower used by every decoy role; `badge` = role glyph drawn in the corner disc
  function server(accent, badge, dim) {
    const led = dim ? "#55555c" : accent;
    return wrap(`
      <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#26262d"/><stop offset="1" stop-color="#121216"/></linearGradient></defs>
      <rect x="26" y="8" width="58" height="96" rx="8" fill="url(#g)" stroke="${dim ? "#44444c" : accent}" stroke-width="3"/>
      ${[0, 1, 2].map(i => `<rect x="33" y="${18 + i * 24}" width="44" height="16" rx="3" fill="#0b0b0e" stroke="#33333a"/>
        <circle cx="41" cy="${26 + i * 24}" r="3" fill="${led}"/><rect x="49" y="${24 + i * 24}" width="22" height="3" rx="1.5" fill="#3a3a42"/>`).join("")}
      <rect x="33" y="90" width="44" height="5" rx="2.5" fill="#2c2c33"/>
      <circle cx="88" cy="88" r="24" fill="#0a0a0c" stroke="${dim ? "#44444c" : accent}" stroke-width="3"/>
      <g transform="translate(88 88)">${badge}</g>`);
  }

  const G = {
    folder: c => `<path d="M-13 -8 h9 l3 4 h14 v15 h-26z" fill="none" stroke="${c}" stroke-width="3" stroke-linejoin="round"/>`,
    globe: c => `<circle r="12" fill="none" stroke="${c}" stroke-width="3"/><ellipse rx="5.5" ry="12" fill="none" stroke="${c}" stroke-width="2.5"/>
                 <path d="M-12 0 h24 M-10 -6 h20 M-10 6 h20" stroke="${c}" stroke-width="2"/>`,
    disks: c => `<ellipse cy="-8" rx="12" ry="4.5" fill="none" stroke="${c}" stroke-width="3"/>
                 <path d="M-12 -8 v16 a12 4.5 0 0 0 24 0 v-16 M-12 0 a12 4.5 0 0 0 24 0" fill="none" stroke="${c}" stroke-width="3"/>`,
    castle: c => `<path d="M-14 12 v-16 h5 v4 h4 v-4 h4 v4 h2 v-4 h4 v4 h4 v-4 h5 v16 z M-3 12 v-7 a3 3 0 0 1 6 0 v7" fill="none" stroke="${c}" stroke-width="2.6" stroke-linejoin="round"/>`,
    dns: c => `<text y="5" text-anchor="middle" font-family="monospace" font-weight="700" font-size="13" fill="${c}">DNS</text>`,
  };
  const ROLE = {"windows-file-server": "folder", "linux-web-hosting": "globe", "ftp-backup-server": "disks",
    "windows-domain-controller": "castle", "linux-dns-server": "dns"};

  function sensor(role, online, hot) {
    const c = online ? (hot ? "#ff3b44" : "#f12c35") : "#6f6f78";
    return uri(server(c, (G[ROLE[role]] || G.folder)(c), !online));
  }

  // bait document with an eye = "watching" canary
  function canary() {
    return uri(wrap(`
      <path d="M30 8 h44 l18 18 v86 h-62z" fill="#1a1020" stroke="#d63bff" stroke-width="3" stroke-linejoin="round"/>
      <path d="M74 8 v18 h18" fill="none" stroke="#d63bff" stroke-width="3"/>
      ${[40, 50, 60].map(y => `<rect x="40" y="${y}" width="${y === 60 ? 26 : 40}" height="4" rx="2" fill="#5b2a6b"/>`).join("")}
      <path d="M36 88 q25 -22 50 0 q-25 22 -50 0z" fill="#0a0a0c" stroke="#d63bff" stroke-width="3"/>
      <circle cx="61" cy="88" r="7" fill="#d63bff"/>`));
  }

  // workstation: screen colour follows severity; L4+ shows a red "!" screen, L5 a purple alarm
  function workstation(color, level, external) {
    const screen = level >= 5 ? "#3a0d47" : level >= 4 ? "#3a0d10" : "#101822";
    const glyph = level >= 4
      ? `<text x="60" y="60" text-anchor="middle" font-family="Arial Black,Arial" font-weight="900" font-size="30" fill="${color}">!</text>`
      : `<path d="M30 52 h20 M30 60 h34 M30 44 h28" stroke="${color}" stroke-width="4" stroke-linecap="round" opacity=".85"/>`;
    const body = external
      ? `<circle cx="60" cy="50" r="34" fill="${screen}" stroke="${color}" stroke-width="4"/>
         <ellipse cx="60" cy="50" rx="15" ry="34" fill="none" stroke="${color}" stroke-width="3" opacity=".7"/>
         <path d="M26 50 h68 M30 34 h60 M30 66 h60" stroke="${color}" stroke-width="3" opacity=".7"/>${level >= 4 ? glyph.replace('y="60"', 'y="61"') : ""}`
      : `<rect x="14" y="18" width="92" height="62" rx="7" fill="${screen}" stroke="${color}" stroke-width="4"/>${glyph}
         <path d="M50 80 l-4 16 h28 l-4 -16" fill="#26262d" stroke="#3a3a42" stroke-width="2"/><rect x="36" y="96" width="48" height="6" rx="3" fill="#33333a"/>`;
    return uri(wrap(body));
  }

  // honeypot jar for the trap-zone header
  const pot = uri(wrap(`<path d="M34 34 h52 l-4 8 q16 14 12 38 q-4 26 -34 28 q-30 -2 -34 -28 q-4 -24 12 -38z" fill="#1a0b0d" stroke="#f12c35" stroke-width="4" stroke-linejoin="round"/>
    <rect x="30" y="22" width="60" height="12" rx="4" fill="#f12c35"/><path d="M44 62 q16 10 32 0" stroke="#f12c35" stroke-width="4" fill="none" stroke-linecap="round"/>
    <path d="M58 34 q2 10 -3 16 q-3 4 1 8" stroke="#ff8a1f" stroke-width="4" fill="none" stroke-linecap="round"/>`));

  return {sensor, canary, workstation, pot};
})();
