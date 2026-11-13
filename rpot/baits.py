"""Persona + bait generator.

`plan_baits()` / `generate(cfg, outdir)` write per-sensor bait trees (SMB shares, web root, FTP
root, fake home dirs) for the decoys that are REALLY deployed. Every credential, SSH key and
document gets a token id, so using it anywhere is attributable:
"credential from \\\\ARB-FS01\\IT\\passwords.txt used on ARB-WEB01:ssh from 10.0.1.47".

Breadcrumbs form a full mesh over the deployed decoys (real names / FQDNs only):
  FS  \\IT\\passwords.txt + keys\\<web>_deploy.key ─▶ WEB ssh, BKP ftp/ssh, DNS ssh, svc_scan (DC ldap / FS smb)
  DC  SYSVOL Groups.xml (GPP), NETLOGON logon.bat + upload/deploy/reload scripts ─▶ FS smb, BKP ftp, WEB ssh, DNS ssh
  DC  LDAP svc_sql (SPN + password in description) ─▶ Kerberoast / LDAP bind
  WEB /.env (admin seed pw, DB pw re-used on BKP ftp, LDAP bind) + ~deploy ─▶ WEB http, BKP, DC, FS, DNS
  BKP /backups/<web>_portal_db.sql (admin MD5 + hint), /configs/* ─▶ WEB http/ssh, FS/DC (svc_backup), DNS, itself
  DNS ~dnsadmin notes / nsupdate / .smbcredentials ─▶ WEB, BKP, DC, FS, itself
A single decoy still holds a credential that works on itself.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import random
import re
import secrets
import tarfile
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

PROFILES = {
    "bank": {"depts": ["Finance", "Retail Banking", "Risk", "Compliance", "IT", "HR"],
             "docs": ["Loan_Portfolio_Q3", "AML_Review_2026", "Branch_Cash_Limits", "Board_Minutes_Sep"]},
    "hotel": {"depts": ["Front Office", "Finance", "Housekeeping", "F&B", "IT", "HR"],
              "docs": ["Guest_VIP_List", "Room_Rates_2027", "Supplier_Contracts", "Occupancy_Report_Oct"]},
    "government": {"depts": ["Administration", "Finance", "Legal", "Procurement", "IT", "HR"],
                   "docs": ["Tender_Evaluation", "Budget_Draft_2027", "Internal_Audit_Plan", "Citizen_Requests_Q3"]},
    "it": {"depts": ["Engineering", "DevOps", "Sales", "Finance", "IT", "HR"],
           "docs": ["Customer_List", "Roadmap_2027", "AWS_Billing_Oct", "Pentest_Findings"]},
    "generic": {"depts": ["Finance", "Sales", "Operations", "IT", "HR"],
                "docs": ["Customer_List", "Budget_2027", "Contracts_Overview", "Board_Minutes"]},
}

# One global pool for every install (D-1/D-8): regional (Armenian, Georgian, Ukrainian) and
# international names as they appear in company AD directories (no gendered surnames).
# ASCII only: they become usernames.
FIRST = ["Anna", "Davit", "Mariam", "Aram", "Lilit", "Narek", "Elena", "Armen", "Sona", "Tigran",
         "Maria", "Levon", "Nare", "Gor", "Ani", "Hayk", "Gayane", "Ruben", "Astghik", "Karen",
         "Arsen", "Tatevik", "Vahe", "Lusine", "Hovhannes", "Mane", "Suren", "Anahit", "Samvel", "Shushan",
         "Giorgi", "Nino", "Irakli", "Tamar", "Alexander", "Olga", "Dmitry", "Natalia", "Sergey", "Irina",
         "Ivan", "Yulia", "John", "Sarah", "Michael", "Laura", "David", "Emma", "James", "Olivia",
         "Robert", "Sophie", "Daniel", "Julia", "Thomas", "Hannah", "Mark", "Rachel", "Peter", "Kate",
         "Andrew", "Helen", "Paul", "Lisa", "Martin", "Eva", "Lucas", "Nora", "Simon", "Clara"]
LAST = ["Petrosyan", "Hakobyan", "Sargsyan", "Grigoryan", "Harutyunyan", "Avetisyan", "Khachatryan",
        "Martirosyan", "Karapetyan", "Ghazaryan", "Vardanyan", "Gevorgyan", "Hovhannisyan", "Mkrtchyan",
        "Abrahamyan", "Poghosyan", "Simonyan", "Manukyan", "Galstyan", "Aslanyan", "Arakelyan", "Baghdasaryan",
        "Danielyan", "Margaryan", "Mirzoyan", "Stepanyan", "Torosyan", "Zakaryan", "Beridze", "Kapanadze",
        "Gelashvili", "Lomidze", "Tsiklauri", "Japaridze", "Kovalenko", "Shevchenko", "Bondarenko", "Melnyk",
        "Smith", "Miller", "Johnson", "Brown", "Wilson", "Taylor", "Anderson", "Thomas", "Moore", "Clark",
        "Walker", "Hall", "Young", "King", "Wright", "Scott", "Green", "Baker", "Adams", "Nelson",
        "Mueller", "Schmidt", "Fischer", "Weber", "Rossi", "Bianchi", "Dubois", "Martin", "Garcia", "Lopez",
        "Novak", "Kowalski", "Jensen", "Larsen"]
SEASONS = ["Spring", "Summer", "Autumn", "Winter"]


def _pw(rng, company_word):
    style = rng.randrange(4)
    if style == 0:
        return f"{rng.choice(SEASONS)}{rng.randrange(2021, 2027)}!"
    if style == 1:
        return f"{company_word}@{rng.randrange(2019, 2027)}"
    if style == 2:
        return f"{company_word.lower()}{rng.randrange(100, 999)}#"
    return f"P@ssw0rd{rng.randrange(10, 99)}"


USER_FORMATS = {
    "f.last": lambda f, l: f"{f[0]}.{l}",          # a.petrosyan
    "first.last": lambda f, l: f"{f}.{l}",         # anna.petrosyan
    "flast": lambda f, l: f"{f[0]}{l}",            # apetrosyan
    "first_l": lambda f, l: f"{f}_{l[0]}",         # anna_p
}

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def valid_domain(d):
    """DNS domain like corp.example.am / ararat.local (2+ labels, no trailing dot)."""
    return bool(d) and len(d) <= 253 and d.count(".") >= 1 and all(_LABEL.match(x) for x in d.split("."))


def valid_hostname(h):
    """Windows-compatible host name: 1-15 chars, letters/digits/hyphen."""
    return bool(re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,15}(?<!-)", h or ""))


def valid_company(c):
    return bool(c) and len(c) <= 80 and all(ch.isprintable() for ch in c) and not any(ch in c for ch in '<>"\\`$')


_INTERNAL_PREFIX = ("corp", "ad", "int", "internal", "office", "hq", "dc", "lan")


def _check_domain(domain):
    if not isinstance(domain, str) or not valid_domain(domain):
        raise ValueError(f"invalid AD/DNS domain {domain!r} (e.g. corp.example.com or example.local)")
    domain = domain.lower()
    labels = domain.split(".")
    if len(labels) >= 3 and labels[0] in _INTERNAL_PREFIX:
        labels = labels[1:]                               # corp.araratbank.am → araratbank.am
    if labels[0].startswith("xn--"):
        raise ValueError(f"internationalised domain {domain!r} is not supported: use the ASCII form "
                         f"of the company domain (e.g. corp.example.am or example.local)")
    return domain, labels


def company_from_domain(domain):
    """Company display name derived from the core domain label: ararat-bank.am → "Ararat Bank",
    corp.araratbank.am → "Araratbank". Raises ValueError for an invalid or xn-- domain."""
    _, labels = _check_domain(domain)
    company = " ".join(part.capitalize() for part in labels[0].split("-") if part)
    if not valid_company(company):
        raise ValueError(f"cannot derive a company name from {domain!r}")
    return company


def netbios_name(label):
    """NetBIOS domain name an admin would pick from the core DNS label (pentest F-04: "REDSIDE-SECURIT" was a
    15-char cut with a hyphen): hyphens dropped; if that is longer than 15, the first word (when it has at least
    3 characters), else a 15-char cut. ararat-bank → ARARATBANK, redside-security → REDSIDESECURITY,
    northwind-traders-intl → NORTHWIND. Mirrored by installer/redpot_install.py (_netbios_name)."""
    parts = [p for p in str(label).split("-") if p]
    joined = "".join(parts)
    if len(joined) > 15:
        joined = parts[0][:15] if len(parts[0]) >= 3 else joined[:15]
    return joined.upper()


def make_persona(domain, profile="generic", seed=None, n_users=14):
    """Company identity used by every sensor: names, domain, users. CE: the client chooses only
    the domain and the industry profile; everything else is derived from them or from the seed.
    All values are validated because they end up in banners, files, certificates and compose."""
    domain, core = _check_domain(domain)
    company = company_from_domain(domain)
    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    word = "".join(ch for ch in company.split()[0] if ch.isalnum()) or "Corp"
    netbios = netbios_name(core[0])                       # corp.ararat-bank.am → ARARATBANK
    if not valid_hostname(netbios):
        raise ValueError(f"invalid NetBIOS domain {netbios!r} (1-15 letters/digits/hyphen)")
    email_domain = ".".join(core)                         # corp.araratbank.am → araratbank.am
    if email_domain.endswith((".local", ".lan", ".internal", ".corp", ".home.arpa")):
        email_domain = email_domain.split(".")[0] + ".com"
    if not valid_domain(email_domain):
        raise ValueError(f"invalid email domain {email_domain!r}")
    user_format = rng.choice(sorted(USER_FORMATS))        # per install, from the seed; not client-selectable
    prof = PROFILES.get(profile, PROFILES["generic"])
    users, seen = [], set()
    while len(users) < n_users:
        f, l = rng.choice(FIRST), rng.choice(LAST)
        u = USER_FORMATS[user_format](f, l).lower()
        if u in seen:
            continue
        seen.add(u)
        users.append({"username": u, "full_name": f"{f} {l}", "dept": rng.choice(prof["depts"]),
                      "email": f"{u}@{email_domain}"})
    return {"name": company, "word": word, "profile": profile if profile in PROFILES else "generic",
            "domain": domain, "netbios": netbios, "email_domain": email_domain, "user_format": user_format,
            "users": users, "seed": rng.randrange(1 << 30)}


# ---------------------------------------------------------------------------------------
# Office hours, weighted: when people save files on a file server (pentest F-04: every bait had the install
# time's seconds, and hours were uniform over the whole day).
_HOURS = (7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)
_HOUR_W = (2, 8, 12, 13, 12, 6, 9, 12, 12, 10, 7, 3, 2, 1, 1)


def business_time(rng, day):
    """A plausible save time on `day` (naive local datetime): weekends move to the nearest workday (a few stay,
    like real admin work), the hour is office-hours weighted, minutes/seconds/microseconds are random."""
    wd = day.weekday()
    if wd >= 5 and rng.random() < 0.9:
        day = day - timedelta(days=wd - 4) if rng.random() < 0.5 else day + timedelta(days=7 - wd)
    h = rng.choices(_HOURS, _HOUR_W)[0]
    return day.replace(hour=h, minute=rng.randrange(60), second=rng.randrange(60), microsecond=rng.randrange(10 ** 6))


def aged(rng, now, days, spread=20):
    """A save time `days`..`days + spread` days before `now`, at a business_time; never in the future."""
    for _ in range(8):
        t = business_time(rng, now - timedelta(days=days + rng.randrange(0, spread + 1)))
        if t < now - timedelta(hours=1):
            return t
    return (now - timedelta(days=days + 1)).replace(second=rng.randrange(60), microsecond=rng.randrange(10 ** 6))


def _w3c(t):
    """OOXML core.xml date as Word writes it: UTC, whole minutes ("2026-08-14T07:32:00Z")."""
    u = t.astimezone(timezone.utc) if t.tzinfo else t.astimezone().astimezone(timezone.utc)
    return u.strftime("%Y-%m-%dT%H:%M:00Z")


def docx_with_beacon(title, paragraphs, beacon_url, when=None, author=None, editor=None, company="", rng=None):
    """Valid .docx whose body contains a linked (external) 1x1 image → opening it in Word fetches beacon_url.
    when: last save (naive local datetime, = the file mtime the caller sets); core.xml gets created (days to
    months before) / modified (= when) / creator / lastModifiedBy and app.xml the Word 2016+ properties. ZIP
    entries carry the 1980-01-01 DOS date like files saved by Word (never the generation time)."""
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
          '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             f'<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{_x(beacon_url)}" TargetMode="External"/>'
             '</Relationships>')
    paras = "".join(f'<w:p><w:r><w:t xml:space="preserve">{_x(p)}</w:t></w:r></w:p>' for p in paragraphs)
    img = ('<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="9525" cy="9525"/>'
           '<wp:docPr id="1" name="logo"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
           '<pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="logo.png"/><pic:cNvPicPr/></pic:nvPicPr>'
           '<pic:blipFill><a:blip r:link="rId9"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
           '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
           '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
           'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
           'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
           'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>'
           f'<w:p><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>{_x(title)}</w:t></w:r></w:p>{img}{paras}'
           '<w:sectPr/></w:body></w:document>')
    rng = rng or random.Random(zlib.crc32(title.encode()))
    when = when or datetime.now()
    created = when - timedelta(days=rng.randrange(0, 120), hours=rng.randrange(0, 8), minutes=rng.randrange(60))
    author = author or "Administrator"
    editor = editor or author
    rev = 1 if created >= when - timedelta(minutes=1) else rng.randrange(2, 24)
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(title)}</dc:title><dc:subject></dc:subject><dc:creator>{_x(author)}</dc:creator>'
            f'<cp:keywords></cp:keywords><dc:description></dc:description><cp:lastModifiedBy>{_x(editor)}</cp:lastModifiedBy>'
            f'<cp:revision>{rev}</cp:revision>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{_w3c(min(created, when))}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{_w3c(when)}</dcterms:modified></cp:coreProperties>')
    text = " ".join([title, *map(str, paragraphs)])
    words, chars = len(text.split()), len(text.replace(" ", ""))
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
           'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
           f'<Template>Normal.dotm</Template><TotalTime>{rng.randrange(3, 240)}</TotalTime><Pages>1</Pages>'
           f'<Words>{words}</Words><Characters>{chars}</Characters><Application>Microsoft Office Word</Application>'
           f'<DocSecurity>0</DocSecurity><Lines>{len(paragraphs) + 1}</Lines><Paragraphs>{len(paragraphs) + 1}</Paragraphs>'
           f'<ScaleCrop>false</ScaleCrop><Company>{_x(company)}</Company><LinksUpToDate>false</LinksUpToDate>'
           f'<CharactersWithSpaces>{len(text)}</CharactersWithSpaces><SharedDoc>false</SharedDoc>'
           '<HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0000</AppVersion></Properties>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (("[Content_Types].xml", ct), ("_rels/.rels", rels), ("word/document.xml", doc),
                           ("word/_rels/document.xml.rels", drels), ("docProps/core.xml", core),
                           ("docProps/app.xml", app)):
            z.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")   # published by Microsoft (MS-GPPREF)


def gpp_cpassword(pw):
    """Encrypt like Group Policy Preferences did (AES-256-CBC, zero IV, UTF-16LE) → what gpp-decrypt reverses."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    pad = padding.PKCS7(128).padder()
    data = pad.update(pw.encode("utf-16-le")) + pad.finalize()
    enc = Cipher(algorithms.AES(GPP_KEY), modes.CBC(b"\x00" * 16)).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode().rstrip("=")


def _x(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _w(path, data, mtime=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    if mtime:
        ts = mtime.timestamp()
        os.utime(path, (ts, ts))


# ---------------------------------------------------------------------------------------
KIND = {"windows-file-server": "fs", "linux-web-hosting": "web", "ftp-backup-server": "bkp",
        "windows-domain-controller": "dc", "linux-dns-server": "dns"}
TITLE = {"fs": "File server", "web": "Web portal", "bkp": "Backup / FTP", "dc": "Domain controller", "dns": "DNS server"}


def bait_secret(cfg):
    """Manager-only secret behind every token id / password / SSH key: deterministic per deployment AND
    persona (a persona change re-keys all baits). Lives in rpot.json, which sensors never see."""
    s = cfg.get("bait_seed")
    if not s:      # configs from before bait_seed: stable fallback from other manager-only values
        c = cfg.get("console") or {}
        s = hashlib.sha256(f"rpot-bait\0{c.get('admin_token', '')}\0{cfg.get('deployment', '')}".encode()).hexdigest()
    return f"{s}\0{(cfg.get('company') or {}).get('seed', 0)}"


def _d(secret, *parts):
    return hashlib.sha256("\0".join([secret, *map(str, parts)]).encode("utf-8", "surrogatepass")).digest()


def _ed25519(seed32, comment):
    """Deterministic OpenSSH ed25519 key pair (same seed → same key → same fingerprint after a regeneration)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    k = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    blob = base64.b64decode(pub.split()[1])
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return priv, pub + " " + comment, fp


def _tgz(prefix, members, when, owner="root"):
    """Real gzip'd tar (members: [(relpath, text|bytes)]) — `tar tzf` on a stolen backup must work."""
    raw, ts = io.BytesIO(), int(when.timestamp())
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=ts) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for i, (rel, data) in enumerate(members):
                b = data.encode() if isinstance(data, str) else data
                ti = tarfile.TarInfo(f"{prefix}/{rel}")
                back = 86400 * (len(members) - i) * 3 + zlib.crc32(rel.encode()) % 28800    # varied h:m:s per member
                ti.size, ti.mtime, ti.mode, ti.uname, ti.gname = len(b), ts - back, 0o644, owner, owner
                tar.addfile(ti, io.BytesIO(b))
    return raw.getvalue()


def _php(s):
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def _site_files(co, fqdn):
    """Small but plausible PHP portal (what the web decoy's admin login pretends to run)."""
    n = _php(co["name"])
    return [
        (".htaccess", "Options -Indexes\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.php [QSA,L]\n"
                      "<FilesMatch \"^\\.env|composer\\.(json|lock)$\">\n  Require all denied\n</FilesMatch>\n"),
        ("index.php", "<?php\nrequire __DIR__ . '/lib/bootstrap.php';\n\n$page = $_GET['p'] ?? 'home';\n"
                      "if (!preg_match('/^[a-z_]{1,32}$/', $page)) {\n    $page = 'home';\n}\nrender($page);\n"),
        ("config.php", f"<?php\n// values come from /var/www/portal/.env (see deploy notes)\nreturn [\n"
                       f"    'app_name' => '{n} Portal',\n    'url'      => 'https://{fqdn}',\n"
                       "    'db'       => [\n        'host' => getenv('DB_HOST') ?: '127.0.0.1',\n        'name' => getenv('DB_DATABASE') ?: 'portal',\n"
                       "        'user' => getenv('DB_USERNAME'),\n        'pass' => getenv('DB_PASSWORD'),\n    ],\n"
                       "    'session'  => ['name' => 'PHPSESSID', 'lifetime' => 7200],\n];\n"),
        ("lib/bootstrap.php", "<?php\ndeclare(strict_types=1);\n\n$config = require __DIR__ . '/../config.php';\nrequire __DIR__ . '/db.php';\n"
                              "require __DIR__ . '/view.php';\n\nsession_name($config['session']['name']);\nsession_start();\n"),
        ("lib/db.php", "<?php\nfunction db(): PDO\n{\n    static $pdo = null;\n    global $config;\n    if ($pdo === null) {\n"
                       "        $c = $config['db'];\n        $pdo = new PDO(\"mysql:host={$c['host']};dbname={$c['name']};charset=utf8mb4\", $c['user'], $c['pass'],\n"
                       "                       [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);\n    }\n    return $pdo;\n}\n"),
        ("lib/view.php", "<?php\nfunction render(string $page): void\n{\n    global $config;\n    $title = $config['app_name'];\n"
                         "    $file = __DIR__ . '/../views/' . $page . '.php';\n    if (!is_file($file)) {\n        http_response_code(404);\n"
                         "        $file = __DIR__ . '/../views/404.php';\n    }\n    include __DIR__ . '/../views/layout.php';\n}\n"),
        ("views/layout.php", "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title><?= htmlspecialchars($title) ?></title>\n"
                             "<link rel=\"stylesheet\" href=\"/assets/css/site.css\"></head>\n<body><header><?= htmlspecialchars($title) ?></header>\n"
                             "<main><?php include $file; ?></main>\n<footer>&copy; <?= date('Y') ?></footer></body></html>\n"),
        ("views/home.php", f"<h2>Welcome to the {_x(co['name'])} staff portal</h2>\n<p>Sign in with your domain account.</p>\n"),
        ("views/404.php", "<h2>Page not found</h2>\n"),
        ("admin/login.php", "<?php\nrequire __DIR__ . '/../lib/bootstrap.php';\n\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n"
                            "    $st = db()->prepare('SELECT id, password_md5 FROM users WHERE username = ?');\n"
                            "    $st->execute([$_POST['username'] ?? '']);\n    $u = $st->fetch();\n"
                            "    // TODO: migrate to password_hash() (ticket IT-412)\n"
                            "    if ($u && hash_equals($u['password_md5'], md5($_POST['password'] ?? ''))) {\n"
                            "        $_SESSION['uid'] = $u['id'];\n        header('Location: /admin/');\n        exit;\n    }\n"
                            "    $error = 'Invalid username or password.';\n}\ninclude __DIR__ . '/../views/login.php';\n"),
        ("assets/css/site.css", "body{font-family:Segoe UI,Arial,sans-serif;background:#f4f5f7;margin:0;color:#222}\n"
                                "header{background:#1f3a5f;color:#fff;padding:14px 28px;font-size:18px}\n"
                                "main{max-width:860px;margin:30px auto;background:#fff;padding:28px;border-radius:6px}\n"
                                "footer{text-align:center;color:#888;font-size:12px;margin:30px}\n"),
        ("robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"),
    ]


def _csv(rng, name, users, today):
    """Department spreadsheet export: columns + row count differ per file (no two files the same size)."""
    who = [u["full_name"] for u in users] or ["Accounts"]
    cur = rng.choice(["AMD", "USD", "EUR"])
    n = rng.randrange(18, 140)
    if rng.random() < 0.5:
        out = ["Date;Reference;Counterparty;Description;Amount;Currency;Approved by"]
        for i in range(n):
            d = today - timedelta(days=rng.randrange(5, 400))
            out.append(f"{d:%d.%m.%Y};{name[:3].upper()}-{d:%y}{rng.randrange(1000, 99999):05d};"
                       f"{rng.choice(['LLC', 'CJSC', 'OJSC', 'Ltd'])} {rng.choice(LAST)};"
                       f"{rng.choice(['Invoice', 'Prepayment', 'Refund', 'Service fee', 'Lease', 'Licence'])} {rng.randrange(1, 12)}/{d:%Y};"
                       f"{rng.randrange(10, 9_000_000) / 100:.2f};{cur};{rng.choice(who)}")
    else:
        out = ["id,period,account,cost_centre,budget,actual,variance,owner"]
        for i in range(1, n):
            b, a = rng.randrange(1000, 900000), rng.randrange(1000, 900000)
            out.append(f"{i},{rng.choice(['Q1', 'Q2', 'Q3', 'Q4'])}-{rng.randrange(2024, 2027)},{rng.randrange(1000, 9999)},"
                       f"CC{rng.randrange(10, 99)},{b},{a},{b - a},{rng.choice(who)}")
    return "\r\n".join(out) + "\r\n"


def _age_dirs(root):
    """Directory mtimes = their newest child (a tree written at install time must not all say 'today')."""
    for d, dirs, files in os.walk(root, topdown=False):
        ts = [os.path.getmtime(os.path.join(d, x)) for x in dirs + files]
        if ts:
            os.utime(d, (max(ts), max(ts)))


def _seasonal(r):
    return f"{r.choice(SEASONS)}{r.randrange(2022, 2027)}!"


def plan_baits(cfg, outdir, sensors=None, holders=None, prior=None):
    """Breadcrumb planner.

    sensors: every deployed decoy [{name, role, ip}] — local AND remote ones the manager knows;
    holders: names whose bait trees are written to outdir/<NAME>/ (default: all of `sensors`);
    prior:   tokens that already exist (same id → same secret: baits already stolen stay valid).
    Returns ALL planned tokens (each has "holder" = the decoy the bait lives on); callers keep theirs.

    * every crumb names only deployed decoys, by their real names / FQDNs;
    * every decoy holds credentials for each OTHER decoy (full mesh: a lateral path whatever roles exist)
      plus one that works on itself, so a single decoy is self-contained;
    * ids / secrets / keys derive from bait_secret(cfg) + holder + target name: adding a decoy keeps every
      existing token (ids, passwords, keys; valid_on only grows) and just adds crumbs for the new one."""
    co = cfg["company"]
    sec = bait_secret(cfg)
    prior = prior if prior is not None else (cfg.get("tokens") or {})
    S, seen = [], set()
    for s in (sensors if sensors is not None else cfg.get("sensors", [])):
        n = (s.get("name") or "").upper()
        if n and n not in seen and not s.get("revoked") and s.get("role") in KIND:
            seen.add(n)
            S.append({"name": n, "role": s["role"], "ip": s.get("ip"), "k": KIND[s["role"]]})
    holders = {h.upper() for h in holders} if holders is not None else set(seen)
    of = lambda k: sorted(s["name"] for s in S if s["k"] == k)
    FS, WEB, BKP, DC, DNS = of("fs"), of("web"), of("bkp"), of("dc"), of("dns")
    ip_of = {s["name"]: s["ip"] for s in S}
    domain, word, nb, ed = co["domain"], co["word"], co["netbios"], co.get("email_domain", co["domain"])
    fq = lambda n: f"{n.lower()}.{domain}"
    prof = PROFILES.get(co.get("profile"), PROFILES["generic"])
    canary = ((cfg.get("console") or {}).get("canary_url") or "").rstrip("/")
    web_ip = next((ip_of[w] for w in WEB if ip_of.get(w)), None)
    beacon = f"http://{web_ip}/assets" if web_ip else f"{canary}/c"   # documents call home to the web decoy
    today = datetime.now()
    month = (today.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    rng_of = lambda *p: random.Random(int.from_bytes(_d(sec, *p), "big"))
    trng = rng_of("time", today.strftime("%Y-%m-%d"))
    old = lambda days: aged(trng, today, days)            # F-04: per-file office-hours time, random seconds
    tid_of = lambda h, slot: "t" + _d(sec, "id", h, slot).hex()[:12]
    tokens, files, honey, authkeys = {}, {}, [], {}
    used = {t.get("password") for t in prior.values() if t.get("kind") == "credential"}
    dom_on = [f"{d}:{x}" for d in DC for x in ("ldap", "smb", "kerberos")] + [f"{f}:smb" for f in FS]

    def put(h, rel, data, when):
        files[(h, rel)] = (data, when)

    def cred(h, slot, username, valid_on, planted, desc, style=None):
        tid, p = tid_of(h, slot), prior.get(tid_of(h, slot)) or {}
        if p.get("kind") == "credential" and str(p.get("username")).lower() == username.lower() and p.get("password"):
            pw = p["password"]
        else:
            r = rng_of("pw", h, slot)
            gen = (lambda: style(r)) if style else (lambda: _pw(r, word))
            pw = gen()
            for i in range(60):
                if pw not in used:
                    break
                pw = gen() if i < 30 else gen() + str(r.randrange(10, 99))
            used.add(pw)
        tokens[tid] = {"kind": "credential", "username": username, "password": pw,
                       "valid_on": list(dict.fromkeys(v for v in valid_on if v)), "planted": planted, "desc": desc, "holder": h}
        return pw

    def domain_acct(h, slot, user, full, planted, desc, ad_desc="", spn=None):
        pw = cred(h, slot, user, dom_on, planted, desc)
        honey.append({"username": user, "full_name": full, "description": ad_desc, "token": tid_of(h, slot),
                      "admin": False, **({"spn": spn} if spn else {})})
        return pw

    def doc(h, slot, planted, desc):
        tid = tid_of(h, slot)
        tokens[tid] = {"kind": "document", "planted": planted, "desc": desc, "url": f"{beacon}/{tid}.png", "holder": h}
        return tokens[tid]["url"]

    def doc_people(h, slot, *depts):
        """creator / lastModifiedBy of a document: staff of the owning department(s) when there are any."""
        r = rng_of("docpeople", h, slot)
        staff = [u for u in co["users"] if u.get("dept") in depts] or co["users"] or [{"full_name": "Administrator"}]
        a = r.choice(staff)["full_name"]
        return {"author": a, "editor": a if r.random() < 0.4 else r.choice(staff)["full_name"]}

    web_ssh = lambda h, t, at: cred(h, f"ssh>{t}", "deploy", [f"{t}:ssh"], at, f"{t} deploy SSH password")
    bkp_ftp = lambda h, t, at: cred(h, f"ftp>{t}", "backup", [f"{t}:ftp", f"{t}:ssh"], at, f"{t} backup FTP/SSH password")
    dns_ssh = lambda h, t, at: cred(h, f"dns>{t}", "dnsadmin", [f"{t}:ssh"], at, f"{t} DNS admin SSH password")

    # ---------------- Windows file server: \\FS\IT is the admin's notebook ----------------
    for h in FS:
        unc, rng = f"\\\\{h}", rng_of("fs", h)
        pwf = f"{unc}\\IT\\passwords.txt"
        L = [f"IT accounts - DO NOT SHARE  (updated {old(40):%d.%m.%Y})", "=" * 45, ""]
        L += [f"{t} ({fq(t)})  ssh   deploy / {web_ssh(h, t, pwf)}" for t in WEB]
        L += [f"{t} ({fq(t)})  ftp   backup / {bkp_ftp(h, t, pwf)}" for t in BKP]
        L += [f"{t} ({fq(t)})  ssh   dnsadmin / {dns_ssh(h, t, pwf)}" for t in DNS]
        scan = domain_acct(h, "dom", "svc_scan", "Scan Service", pwf, f"scan-to-folder domain account (passwords.txt on {h})",
                           "Scan to folder (MFP)")
        L += [f"MFP scan-to-folder ({unc}\\Public)   {nb}\\svc_scan / {scan}"]
        for t in WEB:
            kf = f"{t.lower()}_deploy.key"
            priv, pub, fp = _ed25519(_d(sec, "key", h, t), f"deploy@{t.lower()}")
            tokens[tid_of(h, f"key>{t}")] = {"kind": "sshkey", "username": "deploy", "fingerprint": fp, "public": pub,
                                             "valid_on": [f"{t}:ssh"], "planted": f"{unc}\\IT\\keys\\{kf}",
                                             "desc": f"{t} deploy SSH private key", "holder": h}
            authkeys.setdefault(t, []).append(pub)
            put(h, f"shares/IT/keys/{kf}", priv, old(200))
            put(h, f"shares/IT/keys/{kf}.pub", pub + "\n", old(200))
        if WEB:
            L += ["", "deploy keys are in the keys\\ folder"]
        put(h, "shares/IT/passwords.txt", "\r\n".join(L) + "\r\n", old(40))
        rows = [f"{TITLE[s['k']]}: {s['name']} ({fq(s['name'])}{', ' + s['ip'] if s.get('ip') else ''})" for s in S]
        when = old(90)
        put(h, "shares/IT/Network_Overview.docx",
            docx_with_beacon(f"{co['name']} - Network overview", [f"Domain: {domain}", *rows,
                             "Admin credentials are kept in passwords.txt on this share."],
                             doc(h, "doc-it", f"{unc}\\IT\\Network_Overview.docx", f"IT network overview document on {h}"),
                             when=when, company=co["name"], rng=rng_of("docmeta", h, "it"),
                             **doc_people(h, "it", "IT")), when)
        put(h, "shares/IT/Scripts/map_drives.bat",
            f"@echo off\r\nnet use Z: {unc}\\Public /persistent:yes\r\nnet use Y: {unc}\\Finance\r\n", old(300))
        when = old(15)
        put(h, "shares/Finance/Salaries_2026.docx",
            docx_with_beacon("Salaries 2026 - CONFIDENTIAL",
                             [f"{u['full_name']}\t{u['dept']}\t{rng.randrange(450, 2400) * 1000} AMD" for u in co["users"]],
                             doc(h, "doc-salaries", f"{unc}\\Finance\\Salaries_2026.docx", f"salary document on {h}"),
                             when=when, company=co["name"], rng=rng_of("docmeta", h, "salaries"),
                             **doc_people(h, "salaries", "HR", "Finance")), when)
        for d in prof["docs"][:3]:
            put(h, f"shares/Finance/{d}.csv", _csv(rng_of("csv", h, d), d, co["users"], today), old(30 + rng.randrange(90)))
        put(h, "shares/HR/Employees.csv", "username,full_name,department,email\r\n" + "".join(
            f"{u['username']},{u['full_name']},{u['dept']},{u['email']}\r\n" for u in co["users"]), old(25))
        put(h, "shares/HR/Onboarding_Checklist.txt", "1. Create AD account\r\n2. Default password: Welcome1! (must change)\r\n"
                                                     "3. Map drives (IT\\Scripts\\map_drives.bat)\r\n", old(400))
        put(h, "shares/Public/README.txt", f"Public share for {co['name']} staff. Departmental data is under {unc}\\<Department>.\r\n", old(500))
        put(h, "shares/Public/Phone_List.csv", "name,ext\r\n" + "".join(f"{u['full_name']},{rng.randrange(100, 499)}\r\n"
                                                                         for u in co["users"]), old(80))

    # ---------------- Windows domain controller: SYSVOL / NETLOGON / AD ----------------
    for h in DC:
        unc, rng = f"\\\\{h}", rng_of("dc", h)
        guid = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        gpp = cred(h, "gpp", "srv_localadm", [f"{d}:ldap" for d in DC] + [f"{f}:smb" for f in FS],
                   f"{unc}\\SYSVOL\\{domain}\\Policies\\{guid}\\Machine\\Preferences\\Groups\\Groups.xml",
                   "GPP local Administrator cpassword (gpp-decrypt)")
        prn = domain_acct(h, "print", "svc_print", "Print Service", f"{unc}\\NETLOGON\\logon.bat",
                          "print service account in logon script", "Print spooler account")
        sql = domain_acct(h, "sql", "svc_sql", "SQL Service", f"{h}:ldap (svc_sql description)",
                          "Kerberoastable SQL service account (password in AD description)", spn=f"MSSQLSvc/{fq(h)}:1433")
        honey[-1]["description"] = f"MSSQL svc - pwd {sql}"
        sysvol = f"shares/SYSVOL/{domain}"
        put(h, f"{sysvol}/Policies/{guid}/Machine/Preferences/Groups/Groups.xml",
            '<?xml version="1.0" encoding="utf-8"?>\r\n<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">'
            '<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="srv_localadm" image="2" '
            f'changed="{old(700):%Y-%m-%d %H:%M:%S}" uid="{{{rng.randbytes(4).hex().upper()}-1F3B-4D2A-9C1E-{rng.randbytes(6).hex().upper()}}}">'
            f'<Properties action="U" newName="srv_localadm" fullName="Server Local Admin" description="" cpassword="{gpp_cpassword(gpp)}" '
            'changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/>'
            '</User></Groups>\r\n', old(700))
        put(h, f"{sysvol}/Policies/{guid}/GPT.INI", "[General]\r\nVersion=17\r\ndisplayName=Default Domain Policy\r\n", old(700))
        scripts = {"logon.bat": (f"@echo off\r\nREM {co['name']} logon script\r\n"
                                 + "".join(f"net use Z: \\\\{f}\\Public /persistent:no\r\n" for f in FS[:1])
                                 + f"net use P: {unc}\\NETLOGON /user:{nb}\\svc_print {prn}\r\n"
                                 f"rundll32 printui.dll,PrintUIEntry /in /n {unc}\\HP-Floor2\r\n", old(500))}
        nl = unc + "\\NETLOGON\\"
        for t in BKP:
            f_ = f"ftp_{t.lower()}.txt"
            pw = bkp_ftp(h, t, nl + f_)
            scripts[f_] = (f"backup\r\n{pw}\r\nbinary\r\ncd /uploads\r\nmput *.bak\r\nquit\r\n", old(260))
            scripts[f"upload_{t.lower()}.cmd"] = (f"@echo off\r\nREM nightly SQL .bak upload to {t}\r\n"
                                                  f"cd /d D:\\SQLBackup\r\nftp -i -s:%~dp0{f_} {fq(t)}\r\n", old(260))
        for t in WEB:
            f_ = f"deploy_{t.lower()}.cmd"
            pw = web_ssh(h, t, nl + f_)
            scripts[f_] = (f"@echo off\r\nREM push portal release to {t}\r\npscp -batch -pw {pw} "
                           f"-r D:\\Releases\\portal\\* deploy@{fq(t)}:/var/www/portal/\r\n", old(180))
        for t in DNS:
            f_ = f"dns_reload_{t.lower()}.cmd"
            pw = dns_ssh(h, t, nl + f_)
            scripts[f_] = (f"@echo off\r\nplink -batch -pw {pw} dnsadmin@{fq(t)} \"sudo rndc reload {domain}\"\r\n", old(220))
        for f_, (txt, when) in scripts.items():              # NETLOGON is SYSVOL\<domain>\scripts on a real DC
            put(h, f"shares/NETLOGON/{f_}", txt, when)
            put(h, f"{sysvol}/scripts/{f_}", txt, when)

    # ---------------- FTP / backup ----------------
    for h in BKP:
        rng = rng_of("bkp", h)
        for t in WEB:
            dump = f"{t.lower()}_portal_db_{month}.sql"
            adm = cred(h, f"admin>{t}", "admin", [f"{t}:http"], f"{h}:/backups/{dump}",
                       f"{t} portal admin (MD5 + hint in DB dump)", style=_seasonal)
            rows = [f"(1,'admin','admin@{ed}','{hashlib.md5(adm.encode()).hexdigest()}','2023-02-11')"]
            for i, u in enumerate(co["users"][:10], start=2):
                rows.append(f"({i},'{u['username']}','{u['email']}','{rng.randbytes(16).hex()}','2024-0{rng.randrange(1, 9)}-1{rng.randrange(0, 9)}')")
            put(h, f"ftp/backups/{dump}",
                f"-- MySQL dump 10.13  Distrib 8.0.39, for Linux (x86_64)\n-- Host: localhost    Database: portal ({fq(t)})\n\n"
                "CREATE TABLE `users` (`id` int, `username` varchar(64), `email` varchar(128), `password_md5` char(32), `created` date);\n"
                "INSERT INTO `users` VALUES " + ",\n".join(rows) + ";\n\n"
                f"-- TODO(it): admin password was reset to the seasonal one ({adm[:3]}...), change after audit\n", old(10))
            put(h, f"ftp/backups/{t.lower()}_portal_site_{month}.tar.gz", _tgz("portal", _site_files(co, fq(t)), old(10), "www-data"), old(10))
            f_ = f"pull_{t.lower()}.sh"
            put(h, f"ftp/configs/{f_}", f"#!/bin/sh\n# weekly copy of the portal web root from {t}\n"
                f"sshpass -p '{web_ssh(h, t, f'{h}:/configs/{f_}')}' rsync -az deploy@{fq(t)}:/var/www/portal/ /srv/ftp/backups/portal/\n", old(120))
        if FS or DC:
            bk = domain_acct(h, "dom", "svc_backup", "Backup Service", f"{h}:/configs/backup_job.ps1", f"backup job domain account ({h})",
                             "Veeam/robocopy nightly", spn=f"backup/{fq(h)}")
            put(h, "ftp/configs/backup_job.ps1",
                f"# nightly copy to {h}\r\n$user = '{nb}\\svc_backup'\r\n$pass = '{bk}'\r\n"
                + "".join(f"robocopy \\\\{f}\\Finance D:\\bk\\{f}\\Finance /MIR\r\n" for f in FS)
                + "".join(f"Backup-GPO -All -Path D:\\bk\\GPO -Server {fq(d)}\r\n" for d in DC), old(150))
        for t in DNS:
            put(h, f"ftp/configs/zones_{t.lower()}.sh", f"#!/bin/sh\nsshpass -p '{dns_ssh(h, t, f'{h}:/configs/zones_{t.lower()}.sh')}' "
                f"scp dnsadmin@{fq(t)}:/etc/bind/db.{domain} /srv/ftp/backups/zones/\n", old(90))
        for t in BKP:
            if t != h:
                put(h, f"ftp/configs/mirror_{t.lower()}.sh", f"#!/bin/sh\nlftp -u backup,'{bkp_ftp(h, t, f'{h}:/configs/mirror_{t.lower()}.sh')}' "
                    f"-e 'mirror -R /srv/ftp/backups /backups; quit' {fq(t)}\n", old(90))
        put(h, "ftp/configs/upload.netrc", f"machine {fq(h)}\n  login backup\n  password "
            f"{cred(h, 'self', 'backup', [f'{h}:ftp', f'{h}:ssh'], f'{h}:/configs/upload.netrc', f'{h} backup FTP/SSH password (upload.netrc)')}\n", old(200))
        put(h, f"ftp/backups/{h.lower()}_etc_{month}.tar.gz", _tgz("etc", [
            ("hostname", f"{h.lower()}\n"),
            ("hosts", "127.0.0.1\tlocalhost\n" + "".join(f"{s['ip']}\t{fq(s['name'])} {s['name'].lower()}\n" for s in S if s.get("ip"))),
            ("vsftpd.conf", "listen=YES\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\nchroot_local_user=YES\n"
                            "local_root=/srv/ftp\npasv_min_port=40000\npasv_max_port=40100\n"),
            ("cron.d/backup", "# m h dom mon dow user command\n30 1 * * * backup /usr/local/bin/rotate-backups /srv/ftp/backups 14\n"),
        ], old(10)), old(10))
        put(h, "home/backup/.bash_history", "ls /srv/ftp/backups\ndu -sh /srv/ftp\n" + "".join(
            f"sh /srv/ftp/configs/pull_{t.lower()}.sh\n" for t in WEB) + "exit\n", old(7))

    # ---------------- Linux DNS server (home dir: reached after an SSH login) ----------------
    for h in DNS:
        at = f"{h}:/home/dnsadmin/ops-notes.txt"
        notes = [f"sudo on {h.lower()}: dnsadmin / {cred(h, 'self', 'dnsadmin', [f'{h}:ssh'], at, f'{h} dnsadmin password (ops notes)')}"]
        notes += [f"web push {fq(t)}: deploy / {web_ssh(h, t, at)}" for t in WEB]
        notes += [f"zone copies -> ftp://{fq(t)}  backup / {bkp_ftp(h, t, at)}" for t in BKP]
        notes += [f"secondary {fq(t)}: dnsadmin / {dns_ssh(h, t, at)}" for t in DNS if t != h]
        put(h, "home/dnsadmin/ops-notes.txt", "\n".join(notes) + "\n", old(60))
        if DC:
            p = f"{h}:/home/dnsadmin/nsupdate-gss.txt"
            put(h, "home/dnsadmin/nsupdate-gss.txt", f"# secure dynamic updates against AD\nkinit svc_dnsupdate@{domain.upper()}   "
                f"(pw {domain_acct(h, 'dom-dc', 'svc_dnsupdate', 'DNS Update Service', p, f'DNS update domain account ({h})', 'BIND GSS-TSIG updates')})\n"
                f"nsupdate -g\n> server {fq(DC[0])}\n", old(120))
        if FS:
            p = f"{h}:/home/dnsadmin/.smbcredentials"
            put(h, "home/dnsadmin/.smbcredentials", f"username=svc_zonecopy\npassword="
                f"{domain_acct(h, 'dom-fs', 'svc_zonecopy', 'Zone Copy Service', p, f'zone copy domain account ({h})', 'DNS zone export to file share')}\n"
                f"domain={nb}\n", old(150))
        put(h, "home/dnsadmin/.bash_history",
            f"sudo rndc reload {domain}\nsudo nano /etc/bind/db.{domain}\nnamed-checkzone {domain} /etc/bind/db.{domain}\n"
            f"dig axfr {domain} @127.0.0.1\n" + "".join(f"smbclient //{fq(f)}/IT -A ~/.smbcredentials\n" for f in FS[:1]) + "exit\n", old(3))
        put(h, "home/dnsadmin/zone-notes.txt",
            (f"secondary: {fq(DC[0])} (AD-integrated)\n" if DC else "single master, no secondaries\n")
            + "TSIG key for transfers in /etc/bind/keys/transfer.key\n", old(90))

    # ---------------- Linux web hosting (last: needs the deploy keys planted above) ----------------
    for h in WEB:
        envp = f"{h}:/.env"
        db = cred(h, "db", "webadmin", [f"{b}:ftp" for b in BKP], envp,
                  ("portal DB password, re-used on " + ", ".join(f"{b} FTP" for b in BKP)) if BKP
                  else "portal DB password (MySQL only, no decoy accepts it)")
        adm = cred(h, "admin", "admin", [f"{h}:http"], envp, f"{h} portal admin (seed password in .env)", style=_seasonal)
        env = (f"APP_NAME=\"{co['name']} Portal\"\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://{fq(h)}\n\n"
               f"DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=portal\nDB_USERNAME=webadmin\nDB_PASSWORD={db}\n\n"
               f"# first login, change after go-live\nPORTAL_ADMIN_USER=admin\nPORTAL_ADMIN_PASSWORD={adm}\n")
        if DC:
            lp = domain_acct(h, "dom-dc", "svc_web", "Portal LDAP", envp, f"portal LDAP bind account ({h} .env)", "Portal SSO bind")
            env += (f"\nLDAP_HOST={fq(DC[0])}\nLDAP_PORT=389\nLDAP_BASE_DN={','.join('DC=' + x for x in domain.split('.'))}\n"
                    f"LDAP_USERNAME=svc_web@{domain}\nLDAP_PASSWORD={lp}\n")
        if BKP:
            env += f"\n# nightly dump goes to {BKP[0].lower()} via ftp (same creds)\n"
        put(h, "www/.env", env, old(120))
        put(h, "www/robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", old(300))
        at = f"{h}:/home/deploy/notes.txt"
        notes = [f"backups -> {b.lower()} (ftp, user backup)" for b in BKP] + ["portal admin: see .env / db"]
        notes += [f"dns: dnsadmin@{fq(t)} / {dns_ssh(h, t, at)}" for t in DNS]
        notes += [f"staging {fq(t)}: deploy / {web_ssh(h, t, at)}" for t in WEB if t != h]
        put(h, "home/deploy/notes.txt", "\n".join(notes) + "\n", old(60))
        hist = ["cd /var/www/portal", "git pull", "sudo systemctl reload apache2"]
        hist += [f"ftp {fq(b)}" for b in BKP[:1]] + ["mysqldump -u webadmin -p portal > /tmp/portal.sql", "ls -la /var/backups"]
        if FS:
            p = f"{h}:/home/deploy/.smbcredentials"
            put(h, "home/deploy/.smbcredentials", f"username=svc_webshare\npassword="
                f"{domain_acct(h, 'dom-fs', 'svc_webshare', 'Portal File Share', p, f'portal file-share domain account ({h})', 'Portal uploads share')}\n"
                f"domain={nb}\n", old(150))
            hist.append(f"sudo mount -t cifs //{fq(FS[0])}/Public /mnt/public -o credentials=/home/deploy/.smbcredentials")
        put(h, "home/deploy/.bash_history", "\n".join(hist + ["exit"]) + "\n", old(5))
        if authkeys.get(h):
            put(h, "home/deploy/.ssh/authorized_keys", "".join(k + "\n" for k in authkeys[h]), old(200))

    # AD honey users (LDAP listing, Kerberoast SPNs): every domain account planted anywhere
    hu = list({x["username"]: x for x in reversed(honey)}.values())[::-1]
    for h in DC:
        put(h, "ldap/honey_users.json", json.dumps(hu, indent=1), old(30))
        # Kerberos/NTLM keys of the bait accounts (never their plaintext): the DC decoy issues real TGT/TGS
        # and verifies NTLM binds with them (rpot/sensor/services/adauth.py). One entry per sAMAccountName;
        # "valid" = this DC accepts the logon (otherwise the right password still raises L5, logon refused).
        from rpot.sensor.services.adauth import derive_keys
        realm, names, krb = domain.upper(), {x["username"].lower() for x in hu}, {}
        for tid, t in tokens.items():
            if t.get("kind") != "credential" or not t.get("password"):
                continue
            von = t.get("valid_on") or []
            if t["username"].lower() not in names and not any(v.startswith(f"{h}:") for v in von):
                continue
            ok = f"{h}:ldap" in von or f"{h}:kerberos" in von
            cur = krb.get(t["username"])
            if cur is None or (ok and not cur["valid"]):
                krb[t["username"]] = {"token": tid, "valid": ok, "keys": derive_keys(t["username"], t["password"], realm)}
        put(h, "ldap/krb_keys.json", json.dumps({"realm": realm, "accounts": krb}, indent=1), old(30))

    for (h, rel), (data, when) in files.items():
        if h in holders:
            _w(os.path.join(outdir, h, *rel.split("/")), data, when)
    for h in holders:
        if os.path.isdir(os.path.join(outdir, h)):
            _age_dirs(os.path.join(outdir, h))
    return tokens


def generate(cfg, outdir, roles=None, sensors=None):
    """Plant the baits of THIS manager's local decoys: cfg['tokens'] + trees in outdir/<SENSOR>/.
    sensors (default cfg['remote_sensors']): other deployed decoys (remote) crumbs may point to.
    Tokens already in cfg['tokens'] keep their secrets → call again after adding a decoy to cfg['sensors']."""
    local = [s["name"].upper() for s in cfg.get("sensors", [])]
    extra = [x for x in (sensors if sensors is not None else cfg.get("remote_sensors") or [])
             if (x.get("name") or "").upper() not in local]
    allt = plan_baits(cfg, outdir, list(cfg.get("sensors", [])) + extra, holders=local, prior=dict(cfg.get("tokens") or {}))
    tokens = cfg.setdefault("tokens", {})
    tokens.clear()
    tokens.update({k: v for k, v in allt.items() if v["holder"] in local})
    return tokens
