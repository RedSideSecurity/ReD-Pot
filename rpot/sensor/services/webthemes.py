"""Front pages for the web decoy. Each theme looks like a self-hosted service of THE CLIENT
(company name, mail domain, staff names) — deliberately not a copy of a real product's branding:
copies are trademark problems and easy to fingerprint against the genuine version.

  webmail   — company webmail sign-in → inbox after a valid (bait) login     [default]
  helpdesk  — IT service desk sign-in (DOMAIN\\user) + public knowledge-base list
  intranet  — simple staff intranet with a link to portal administration     [v0.1 look]
"""
import datetime
import hashlib
import html

THEMES = ("webmail", "helpdesk", "intranet")

ICON_MAIL = ("<svg viewBox='0 0 24 24' width='28' height='28' fill='none' stroke='currentColor' stroke-width='1.8'>"
             "<rect x='3' y='5' width='18' height='14' rx='2'/><path d='m3 7 9 6 9-6'/></svg>")
ICON_DESK = ("<svg viewBox='0 0 24 24' width='28' height='28' fill='none' stroke='currentColor' stroke-width='1.8'>"
             "<path d='M4 13a8 8 0 0 1 16 0'/><rect x='2.5' y='13' width='4' height='6' rx='1.5'/>"
             "<rect x='17.5' y='13' width='4' height='6' rx='1.5'/><path d='M20 19a4 4 0 0 1-4 3h-2'/></svg>")


def _color(company):
    """Stable per-company accent colour, so two clients' decoys don't look identical."""
    h = int(hashlib.sha256(company.encode()).hexdigest()[:6], 16)
    palette = ["#1b4f8a", "#0f6e6e", "#5b3f8c", "#8a3b1b", "#2f5d34", "#7a2741", "#1e5a7a", "#4a4f57"]
    return palette[h % len(palette)]


def _favicon(letter, color):
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' "
           f"fill='{color}'/><text x='16' y='22' font-family='Arial' font-size='17' font-weight='700' "
           f"text-anchor='middle' fill='white'>{letter}</text></svg>")
    return "data:image/svg+xml," + svg.replace("#", "%23").replace("<", "%3C").replace(">", "%3E").replace("'", "%27")


BASE_CSS = """*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;color:#1f2328;background:#eef1f5}
a{color:var(--c);text-decoration:none}a:hover{text-decoration:underline}
.wrap{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.brand{display:flex;align-items:center;gap:10px;color:var(--c);margin-bottom:18px}
.brand b{font-size:20px;color:#1f2328}.brand span{color:#6b7280;font-size:13px;display:block;margin-top:-2px}
.card{width:100%;max-width:380px;background:#fff;border:1px solid #dfe3ea;border-radius:10px;padding:28px 28px 22px;box-shadow:0 8px 24px #1f23280f}
.card h1{font-size:19px;margin:0 0 4px}.card p.sub{margin:0 0 18px;color:#6b7280;font-size:13px}
label{display:block;font-size:12.5px;font-weight:600;color:#374151;margin:0 0 5px}
input[type=text],input[type=password],input[type=email]{width:100%;padding:10px 11px;border:1px solid #cfd5de;border-radius:6px;font:inherit;margin-bottom:14px;background:#fbfcfd}
input:focus{outline:2px solid var(--c);outline-offset:-1px;background:#fff}
.row{display:flex;justify-content:space-between;align-items:center;font-size:13px;margin:-4px 0 16px}
.row label{display:inline;font-weight:400;margin:0}
button{width:100%;padding:10px;border:0;border-radius:6px;background:var(--c);color:#fff;font:600 14px inherit;cursor:pointer}
.err{background:#fdecec;color:#9b1c1c;border:1px solid #f5c2c2;border-radius:6px;padding:8px 10px;font-size:13px;margin-bottom:14px}
.foot{margin-top:18px;color:#6b7280;font-size:12px;text-align:center}.foot a{color:#6b7280}
select{border:1px solid #cfd5de;border-radius:5px;padding:3px 6px;font:inherit;font-size:12px;background:#fff;color:#374151}
.top{width:100%;background:var(--c);color:#fff;display:flex;align-items:center;gap:12px;padding:10px 18px}
.top b{font-size:16px}.top .sp{flex:1}.top a{color:#fff;opacity:.9}
.app{display:flex;min-height:calc(100vh - 48px)}
.side{width:200px;background:#fff;border-right:1px solid #dfe3ea;padding:14px 0}
.side div{padding:7px 18px;color:#374151}.side div.on{background:#eef2f8;border-left:3px solid var(--c);font-weight:600}
.list{flex:1;background:#fff}.msg{display:grid;grid-template-columns:200px 1fr 90px;gap:12px;padding:10px 18px;border-bottom:1px solid #eef0f3}
.msg.u{font-weight:600}.msg .d{color:#6b7280;text-align:right;font-size:12.5px}.msg .s span{color:#6b7280;font-weight:400}
.kb{max-width:760px;width:100%;margin-top:22px}.kb h2{font-size:15px;margin:0 0 8px;color:#374151}
.kb a{display:block;background:#fff;border:1px solid #dfe3ea;border-radius:8px;padding:10px 14px;margin-bottom:8px;color:#1f2328}
.kb a small{color:#6b7280;display:block}
@media(max-width:640px){.side{display:none}.msg{grid-template-columns:1fr 70px}.msg .f{display:none}}"""


def _doc(title, company, body, extra_head=""):
    c = _color(company)
    return (f"<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<meta name=\"robots\" content=\"noindex,nofollow\"><title>{html.escape(title)}</title>"
            f"<link rel=\"icon\" href=\"{_favicon(html.escape(company[:1].upper() or 'M'), c)}\">"
            f"<style>:root{{--c:{c}}}{BASE_CSS}</style>{extra_head}</head><body>{body}</body></html>\n")


def _year():
    return datetime.date.today().year


# ----------------------------------------------------------------------------- webmail
def webmail_login(company, mail_domain, err="", user=""):
    e = f'<div class="err">{html.escape(err)}</div>' if err else ""
    body = (f'<div class="wrap"><div class="brand">{ICON_MAIL}<div><b>{html.escape(company)}</b>'
            f'<span>Webmail</span></div></div>'
            f'<form class="card" method="post" action="/login" autocomplete="on">'
            f'<h1>Sign in</h1><p class="sub">Use your company email address and password.</p>{e}'
            f'<input type="hidden" name="_token" value="{hashlib.sha1(company.encode()).hexdigest()[:24]}">'
            f'<label for="u">Email address</label>'
            f'<input type="text" id="u" name="user" value="{html.escape(user)}" placeholder="name@{html.escape(mail_domain)}" autofocus>'
            f'<label for="p">Password</label><input type="password" id="p" name="pass">'
            f'<div class="row"><label><input type="checkbox" name="remember"> Keep me signed in</label>'
            f'<a href="/?_action=reset">Forgot password?</a></div>'
            f'<button type="submit">Sign in</button>'
            f'<div class="foot"><select name="lang"><option>English (US)</option><option>Deutsch</option>'
            f'<option>Français</option><option>Русский</option><option>Հայերեն</option></select></div></form>'
            f'<div class="foot">&copy; {_year()} {html.escape(company)} &middot; IT Service Desk ext. 200 &middot; '
            f'<a href="/?_action=privacy">Privacy</a></div></div>')
    return _doc(f"{company} Webmail :: Welcome", company, body)


def webmail_reset(company, mail_domain):
    body = (f'<div class="wrap"><div class="brand">{ICON_MAIL}<div><b>{html.escape(company)}</b><span>Webmail</span></div></div>'
            f'<div class="card"><h1>Reset password</h1><p class="sub">Password resets are handled by the IT Service Desk.</p>'
            f'<p>Call extension <b>200</b> or write to <a href="mailto:helpdesk@{html.escape(mail_domain)}">'
            f'helpdesk@{html.escape(mail_domain)}</a> from a colleague\'s mailbox.</p>'
            f'<p><a href="/">&larr; Back to sign in</a></p></div></div>')
    return _doc(f"{company} Webmail :: Password", company, body)


SUBJECTS = ["Quarterly report – final numbers", "Re: VPN access for the new laptop", "Updated holiday schedule",
            "Invoice #{n} – please approve", "Server maintenance window this Saturday", "Re: Meeting notes",
            "Password expiry reminder", "New printer on floor 2", "Re: contract draft v3", "Team lunch on Friday",
            "Backup job report – {d}", "Re: access to the shared folder"]
PREVIEWS = ["Please find attached the latest version, comments welcome before Thursday.",
            "IT has enabled your account, use your domain password to connect.",
            "Attached is the updated plan for the upcoming months.", "Kindly approve by end of day.",
            "Services may be unavailable between 22:00 and 02:00.", "Thanks all, summary below.",
            "Your password expires in 7 days. Change it from any domain-joined PC.",
            "Driver is on \\\\fileserver\\Public\\Drivers.", "I've marked the changes in red.",
            "Let me know if you can make it.", "All jobs completed successfully.", "Done – you should see it now."]


def webmail_inbox(company, mail_domain, user, users):
    today = datetime.date.today()
    rows = []
    for i, s in enumerate(SUBJECTS):
        u = users[i % len(users)] if users else {"full_name": "IT Service Desk"}
        d = today - datetime.timedelta(days=i // 3)
        when = "Today" if d == today else d.strftime("%b %d")
        subj = s.format(n=40211 + i * 17, d=d.strftime("%d.%m"))
        rows.append(f'<div class="msg{" u" if i < 3 else ""}"><div class="f">{html.escape(u["full_name"])}</div>'
                    f'<div class="s">{html.escape(subj)} <span>– {html.escape(PREVIEWS[i])}</span></div>'
                    f'<div class="d">{when}</div></div>')
    body = (f'<div class="top">{ICON_MAIL}<b>{html.escape(company)} Webmail</b><span class="sp"></span>'
            f'<span>{html.escape(user)}</span><a href="/logout">Sign out</a></div>'
            f'<div class="app"><div class="side"><div class="on">Inbox <small>(3)</small></div><div>Drafts</div>'
            f'<div>Sent</div><div>Junk</div><div>Trash</div><div>Archive</div></div>'
            f'<div class="list">{"".join(rows)}</div></div>')
    return _doc(f"{company} Webmail :: Inbox", company, body)


# ----------------------------------------------------------------------------- helpdesk
KB = [("KB-0102", "Connecting to the company VPN from home", "Network"),
      ("KB-0117", "Mapping network drives (\\\\fileserver\\Public)", "Windows"),
      ("KB-0131", "Resetting your domain password", "Accounts"),
      ("KB-0145", "Setting up email on your phone", "Email"),
      ("KB-0158", "Requesting access to a shared folder", "Access")]


def helpdesk_login(company, netbios, err="", user=""):
    e = f'<div class="err">{html.escape(err)}</div>' if err else ""
    kb = "".join(f'<a href="/kb/{k.lower()}">{html.escape(t)}<small>{k} &middot; {c}</small></a>' for k, t, c in KB)
    body = (f'<div class="wrap"><div class="brand">{ICON_DESK}<div><b>{html.escape(company)}</b>'
            f'<span>IT Service Desk</span></div></div>'
            f'<form class="card" method="post" action="/login"><h1>Sign in</h1>'
            f'<p class="sub">Use your domain account to open and track requests.</p>{e}'
            f'<label for="u">Username</label>'
            f'<input type="text" id="u" name="user" value="{html.escape(user)}" placeholder="{html.escape(netbios)}\\username" autofocus>'
            f'<label for="p">Password</label><input type="password" id="p" name="pass">'
            f'<button type="submit">Sign in</button>'
            f'<div class="foot">Can\'t sign in? Call ext. <b>200</b></div></form>'
            f'<div class="kb"><h2>Popular knowledge-base articles</h2>{kb}</div>'
            f'<div class="foot">&copy; {_year()} {html.escape(company)} IT</div></div>')
    return _doc(f"{company} IT Service Desk", company, body)


def helpdesk_tickets(company, user, users):
    names = [u["full_name"] for u in users] or ["Service Desk"]
    items = ["Laptop does not connect to Wi-Fi", "New starter account – Finance", "Printer on floor 2 offline",
             "VPN disconnects every hour", "Access to \\\\fileserver\\HR", "Outlook asks for password repeatedly",
             "Install accounting software update", "Replace broken monitor"]
    st = ["Open", "In progress", "Waiting for user", "Resolved"]
    rows = "".join(f'<div class="msg"><div class="f">INC-{20431 + i * 7}</div><div class="s">{html.escape(t)} '
                   f'<span>– {html.escape(names[i % len(names)])}</span></div><div class="d">{st[i % 4]}</div></div>'
                   for i, t in enumerate(items))
    body = (f'<div class="top">{ICON_DESK}<b>{html.escape(company)} IT Service Desk</b><span class="sp"></span>'
            f'<span>{html.escape(user)}</span><a href="/logout">Sign out</a></div>'
            f'<div class="app"><div class="side"><div class="on">My queue</div><div>All open</div><div>Changes</div>'
            f'<div>Knowledge base</div><div>Reports</div></div><div class="list">{rows}</div></div>')
    return _doc(f"{company} IT Service Desk :: Queue", company, body)
