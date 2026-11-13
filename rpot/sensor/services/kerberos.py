"""Kerberos KDC decoy (88/tcp+udp, 464 kpasswd) for the Domain Controller role.

It answers like a DC, and issues REAL tickets for the bait accounts whose keys it holds (adauth.BaitKeys):
* AS-REQ, existing user, no pre-auth  → KDC_ERR_PREAUTH_REQUIRED (25) + ETYPE-INFO2 (kerbrute "VALID USERNAME")
* AS-REQ, unknown user                → KDC_ERR_C_PRINCIPAL_UNKNOWN (6)
* AS-REQ, bait account, correct PA-ENC-TIMESTAMP → AS-REP with a TGT (encrypted with the per-install krbtgt
  key) — honeytoken.used (L5); a bait with no access on this DC → KDC_ERR_CLIENT_REVOKED (still L5: right password)
* AS-REQ, wrong password               → KDC_ERR_PREAUTH_FAILED (24) + auth.failed (feeds spraying detection)
* disabled accounts (krbtgt, Guest)   → KDC_ERR_CLIENT_REVOKED (18)
* TGS-REQ with a TGT from this KDC    → TGS-REP. A honey SPN (svc_sql's MSSQLSvc/…, by SPN or account name)
  gets a ticket encrypted with that account's key, so a cracked Kerberoast hash yields exactly the bait
  password — honeytoken.used (L5). Decoy computer SPNs get tickets too; anything else → S_PRINCIPAL_UNKNOWN.
* TGS-REQ without a valid TGT         → KRB_AP_ERR_MODIFIED (41)
A bait username seen without its secret (user lists, AS-REP roasting, wrong password) is only
honeytoken.attempt (L4) — L5 needs the correct secret. Over UDP a ticket reply becomes
KRB_ERR_RESPONSE_TOO_BIG (52) like Windows (the client retries over TCP).

Events: kerberos.as_req (3), kerberos.tgs_req (3), kerberos.enum (3, user enumeration summary),
auth.failed / auth.success, honeytoken.used (5), honeytoken.attempt (4).
"""
import json
import os
import secrets
import struct
import threading
import time
from datetime import datetime, timezone

from rpot.sensor.base import serve_tcp, serve_udp
from rpot.sensor.services import ber as B
from rpot.sensor.services.adauth import AES128, AES256, RC4, BaitKeys, kdc_secret, machine_key

AS_REQ, TGS_REQ, AS_REP, TGS_REP, AP_REQ = 0x6A, 0x6C, 0x6B, 0x6D, 0x6E
ERR = {6: "C_PRINCIPAL_UNKNOWN", 7: "S_PRINCIPAL_UNKNOWN", 14: "ETYPE_NOSUPP", 18: "CLIENT_REVOKED", 24: "PREAUTH_FAILED",
       25: "PREAUTH_REQUIRED", 37: "AP_ERR_SKEW", 41: "AP_ERR_MODIFIED", 52: "RESPONSE_TOO_BIG", 68: "WRONG_REALM"}
ENUM_FULL = 25            # per source: first N distinct usernames are individual events, then summaries
TGT_LIFE, RENEW_LIFE, SKEW = 10 * 3600, 7 * 86400, 300
KEYLEN = {AES256: 32, AES128: 16, RC4: 16}
SERVICES = ("host", "cifs", "ldap", "http", "gc", "rpcss", "wsman", "termsrv", "restrictedkrbhost", "dns", "e3514235-4b06-11d1-ab04-00c04fc2dcd2")


def ktime(t=None):
    return B.tlv(0x18, datetime.fromtimestamp(t or time.time(), timezone.utc).strftime("%Y%m%d%H%M%SZ").encode())


def parse_ktime(v):
    return datetime.strptime(B.as_str(v)[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()


def principal(name_type, *names):
    return B.seq(B.ctx(0, B.integer(name_type)), B.ctx(1, B.seq(*[B.gstring(n) for n in names])))


def kflags(*bits):
    v = 0
    for b in bits:
        v |= 1 << (31 - b)
    return B.tlv(0x03, b"\x00" + v.to_bytes(4, "big"))


def enc_data(etype, cipher, kvno=None):
    return B.seq(B.ctx(0, B.integer(etype)), *([B.ctx(1, B.integer(kvno))] if kvno is not None else []),
                 B.ctx(2, B.octets(cipher)))


def enc_key(etype, key):
    return B.seq(B.ctx(0, B.integer(etype)), B.ctx(1, B.octets(key)))


def _crypt(op, etype, key, usage, data):
    from impacket.krb5.crypto import Key, _enctype_table
    c = _enctype_table[etype]
    return c.encrypt(Key(etype, key), usage, data, None) if op == "enc" else c.decrypt(Key(etype, key), usage, data)


def _encdata(v):
    """EncryptedData element list → (etype, cipher)."""
    return B.as_int(B.find(v, 0xA0)[0][1]), bytes(B.find(v, 0xA2)[0][1])


def krb_error(code, realm, sname, cname=None, e_data=None):
    body = [B.ctx(0, B.integer(5)), B.ctx(1, B.integer(30)), B.ctx(4, ktime()), B.ctx(5, B.integer(int(time.time() * 1e6) % 1000000)),
            B.ctx(6, B.integer(code))]
    if cname:
        body += [B.ctx(7, B.gstring(realm)), B.ctx(8, principal(1, cname))]
    body += [B.ctx(9, B.gstring(realm)), B.ctx(10, principal(2, *sname))]
    if e_data is not None:
        body.append(B.ctx(12, B.octets(e_data)))
    return B.app(30, B.seq(*body))


def etype_info2(salt, etypes=(AES256, AES128, RC4)):
    entries = [B.seq(B.ctx(0, B.integer(e)), *([B.ctx(1, B.gstring(salt))] if e != RC4 else [])) for e in etypes]
    return B.seq(B.ctx(1, B.integer(19)), B.ctx(2, B.octets(B.seq(*entries))))


def method_data(salt):
    pa = lambda t, v: B.seq(B.ctx(1, B.integer(t)), B.ctx(2, B.octets(v)))
    return B.seq(etype_info2(salt), pa(2, b""), pa(16, b""), pa(15, b""))


def _pname(v):
    """PrincipalName element list → (type, [components])."""
    t = B.find(v, 0xA0)
    strs = B.find(v, 0xA1)[0][1]
    return (B.as_int(t[0][1]) if t else 1), [B.as_str(s)[:100] for _, s in strs][:8]


def parse_kdc_req(data):
    """→ dict(type, cname, realm, sname, preauth, etypes, padata{type: bytes}, cname_t, sname_t, nonce) ;
    ValueError on garbage."""
    tag, outer = B.one(data)
    if tag not in (AS_REQ, TGS_REQ) or not isinstance(outer, list) or not outer or outer[0][0] != 0x30:
        raise ValueError("not a KDC-REQ")
    req = outer[0][1]
    padata = B.find(req, 0xA3) or []
    body = B.find(req, 0xA4)
    if not body or not isinstance(body[0][1], list):
        raise ValueError("no req-body")
    rb = body[0][1]

    def pn(v):
        if not v:
            return None
        try:
            return _pname(v[0][1])
        except (TypeError, IndexError, AttributeError):
            return None
    pa = {}
    for _, p in (padata[0][1] if padata and isinstance(padata[0][1], list) else []):
        try:
            v = B.find(p, 0xA2)
            pa.setdefault(B.as_int(B.find(p, 0xA1)[0][1]), bytes(v[0][1]) if v and isinstance(v[0][1], bytes) else b"")
        except (TypeError, IndexError):
            pass
    et = B.find(rb, 0xA8)
    etypes = [B.as_int(v) for _, v in (et[0][1] if et and isinstance(et[0][1], list) else [])][:16]
    realm = B.find(rb, 0xA2)
    nonce = B.find(rb, 0xA7)
    cn, sn = pn(B.find(rb, 0xA1)), pn(B.find(rb, 0xA3))
    return {"type": "as" if tag == AS_REQ else "tgs", "cname": "/".join(cn[1])[:200] if cn else None,
            "realm": B.as_str(realm[0][1]) if realm else "", "sname": "/".join(sn[1])[:200] if sn else None,
            "pa": list(pa), "preauth": 2 in pa, "etypes": etypes, "padata": pa,
            "cname_t": cn, "sname_t": sn, "nonce": B.as_int(nonce[0][1]) & 0xFFFFFFFF if nonce and isinstance(nonce[0][1], bytes) else 0}


class KDC:
    def __init__(self, ctx):
        self.ctx = ctx
        self.realm = ctx.domain.upper()
        self.honey, self.spns = {}, {}
        try:
            with open(os.path.join(ctx.bait_dir, "ldap", "honey_users.json")) as f:
                for h in json.load(f)[:50]:
                    self.honey[h["username"].lower()] = h
                    if h.get("spn"):
                        self.spns[h["spn"].lower()] = h
        except (OSError, ValueError, KeyError, TypeError):
            pass
        self.keys = BaitKeys(ctx.bait_dir)
        self.secret = kdc_secret(ctx.data_dir)
        self.krbtgt = machine_key(self.secret, "krbtgt")
        self.seen, self.lock = {}, threading.Lock()

    def users(self):
        u = {x["username"].lower() for x in (self.ctx.cfg.get("company") or {}).get("users", [])}
        u |= set(self.honey) | set(self.keys.accounts) | {"administrator"}
        u |= {f"{n.lower()}$" for n in self.hosts()}
        return u

    def hosts(self):
        from rpot.sensor.services.ldap import workstations      # the LDAP directory's workstation accounts (RC-27)
        ws = {w[0].lower() for w in workstations(self.ctx)}
        return set(n.lower() for n in (self.ctx.cfg.get("zone_roles") or {})) | {self.ctx.name.lower()} | ws

    def _enum_gate(self, src):
        """Kerbrute sends thousands of names: individual events for the first ones, then one summary per 100."""
        now = time.time()
        with self.lock:
            n, first = self.seen.get(src, (0, now))
            if now - first > 600:
                n, first = 0, now
            n += 1
            self.seen[src] = (n, first)
            if len(self.seen) > 20000:
                self.seen.clear()
        return n

    def _bait(self, lu):
        """(token id, honey record or None) when a username is a bait account, else None."""
        acct = self.keys.get(lu)
        if lu in self.honey or acct:
            return (acct or {}).get("token") or self.honey.get(lu, {}).get("token"), self.honey.get(lu)
        if lu and self.ctx.tokens.username_is_bait(lu):
            return self.ctx.tokens.bait_user(lu)[0], None
        return None

    def _attempt(self, src, port, proto, session, user, tid, desc):
        k, now = (src[0], user.lower(), desc), time.time()
        with self.lock:                                     # one per source/account/kind per 10 min
            if now - self.seen.get(k, 0) < 600:
                return
            self.seen[k] = now
        self.ctx.emit("honeytoken.attempt", src, port, proto, session, token=tid, username=user, desc=desc,
                      planted=f"{self.ctx.name} baits")

    # ----------------------------------------------------------------- AS exchange
    def _preauth(self, pa, acct):
        """PA-ENC-TIMESTAMP → ('ok' | 'skew' | 'bad', etype)."""
        try:
            _, v = B.one(pa)
            etype, cipher = _encdata(v)
        except (ValueError, TypeError, IndexError):
            return "bad", None
        key = (acct or {}).get("keys", {}).get(etype)
        if not key:
            return "bad", etype
        try:
            plain = _crypt("dec", etype, key, 1, cipher)
            _, ts = B.one(plain)
            t = parse_ktime(B.find(ts, 0xA0)[0][1])
        except Exception:                                   # wrong key → checksum error; garbage → anything
            return "bad", etype
        return ("ok" if abs(time.time() - t) <= SKEW else "skew"), etype

    def _ticket(self, sname_t, srealm, etype, key, kvno, flags, sk_etype, sk, crealm, cname_t, now):
        etp = B.app(3, B.seq(B.ctx(0, flags), B.ctx(1, enc_key(sk_etype, sk)), B.ctx(2, B.gstring(crealm)),
                             B.ctx(3, principal(cname_t[0], *cname_t[1])),
                             B.ctx(4, B.seq(B.ctx(0, B.integer(0)), B.ctx(1, B.octets(b"")))),
                             B.ctx(5, ktime(now)), B.ctx(6, ktime(now)), B.ctx(7, ktime(now + TGT_LIFE)),
                             B.ctx(8, ktime(now + RENEW_LIFE))))
        return B.app(1, B.seq(B.ctx(0, B.integer(5)), B.ctx(1, B.gstring(srealm)), B.ctx(2, principal(sname_t[0], *sname_t[1])),
                              B.ctx(3, enc_data(etype, _crypt("enc", etype, key, 2, etp), kvno))))

    def _kdc_rep(self, app_rep, app_enc, usage, r, cname_t, ticket, reply_etype, reply_key, sk_etype, sk, flags,
                 sname_t, now, padata=None):
        ekp = B.app(app_enc, B.seq(B.ctx(0, enc_key(sk_etype, sk)),
                                   B.ctx(1, B.seq(B.seq(B.ctx(0, B.integer(0)), B.ctx(1, ktime(now))))),
                                   B.ctx(2, B.integer(r["nonce"])),
                                   *([B.ctx(3, B.tlv(0x18, b"20370914024805Z"))] if app_enc == 25 else []),
                                   B.ctx(4, flags), B.ctx(5, ktime(now)), B.ctx(6, ktime(now)), B.ctx(7, ktime(now + TGT_LIFE)),
                                   B.ctx(8, ktime(now + RENEW_LIFE)), B.ctx(9, B.gstring(self.realm)),
                                   B.ctx(10, principal(sname_t[0], *sname_t[1]))))
        return B.app(app_rep, B.seq(B.ctx(0, B.integer(5)), B.ctx(1, B.integer(app_rep & 0x1F)),
                                    *([B.ctx(2, B.seq(padata))] if padata else []),
                                    B.ctx(3, B.gstring(self.realm)), B.ctx(4, principal(cname_t[0], *cname_t[1])),
                                    B.ctx(5, ticket), B.ctx(6, enc_data(reply_etype, _crypt("enc", reply_etype, reply_key, usage, ekp)))))

    def _as_rep(self, r, acct, etype):
        now = time.time()
        sk_etype = next((e for e in r["etypes"] if e in KEYLEN), etype)
        sk = secrets.token_bytes(KEYLEN[sk_etype])
        cname_t = (1, [acct["sam"]])
        tgs = (2, ["krbtgt", self.realm])
        flags = kflags(1, 8, 9, 10, 15)                    # forwardable renewable initial pre-authent canonicalize
        ticket = self._ticket(tgs, self.realm, AES256, self.krbtgt, 2, flags, sk_etype, sk, self.realm, cname_t, now)
        salt = etype_info2(self.realm + acct["sam"], (etype,))
        return self._kdc_rep(AS_REP & 0x1F, 25, 3, r, cname_t, ticket, etype, acct["keys"][etype], sk_etype, sk, flags,
                             tgs, now, padata=salt)

    # ----------------------------------------------------------------- TGS exchange
    def _tgt(self, pa):
        """PA-TGS-REQ (AP-REQ) → dict(crealm, cname_t, sk_etype, sk, reply_key, reply_etype, usage) if the TGT
        was issued by this KDC and the authenticator decrypts, else None."""
        try:
            tag, ap = B.one(pa)
            if tag != AP_REQ:
                return None
            a = ap[0][1]
            tkt = B.find(a, 0xA3)[0][1][0][1]                # [3] Ticket → [APPLICATION 1] → SEQUENCE
            etype, cipher = _encdata(B.find(tkt, 0xA3)[0][1])
            if etype != AES256:
                return None
            _, etp = B.one(_crypt("dec", AES256, self.krbtgt, 2, cipher))
            etp = etp[0][1]
            kv = B.find(etp, 0xA1)[0][1]
            sk_etype, sk = B.as_int(B.find(kv, 0xA0)[0][1]), bytes(B.find(kv, 0xA1)[0][1])
            if parse_ktime(B.find(etp, 0xA7)[0][1]) < time.time() - SKEW or sk_etype not in KEYLEN:
                return None
            out = {"crealm": B.as_str(B.find(etp, 0xA2)[0][1]), "cname_t": _pname(B.find(etp, 0xA3)[0][1]),
                   "sk_etype": sk_etype, "sk": sk, "reply_etype": sk_etype, "reply_key": sk, "usage": 8}
            ae, ac = _encdata(B.find(a, 0xA4)[0][1])
            _, auth = B.one(_crypt("dec", sk_etype, sk, 7, ac))
            sub = B.find(auth[0][1], 0xA6)
            if sub:
                se, sv = B.as_int(B.find(sub[0][1], 0xA0)[0][1]), bytes(B.find(sub[0][1], 0xA1)[0][1])
                if se in KEYLEN:
                    out.update(reply_etype=se, reply_key=sv, usage=9)
            return out
        except Exception:                                   # forged / foreign / garbage ticket
            return None

    def _service(self, sname_t):
        """Requested server principal → (kind, honey record, {etype: key}) or None (unknown principal)."""
        parts = sname_t[1] if sname_t else []
        if not parts:
            return None
        low = [p.lower() for p in parts]
        if low[0] == "krbtgt":
            return ("krbtgt", None, {AES256: self.krbtgt})
        if len(parts) == 1:                                 # account name: svc_sql / CORP\svc_sql / svc_sql@REALM
            acct = low[0].split("\\")[-1].split("@")[0]
            h = self.honey.get(acct)
            if h and h.get("spn"):
                return ("honey", h, self._honey_keys(h))
            if acct.rstrip("$") in self.hosts() and acct.endswith("$"):
                return ("machine", None, {AES256: machine_key(self.secret, acct.rstrip("$"))})
            return None
        spn = "/".join(low)
        h = self.spns.get(spn) or next((v for k, v in self.spns.items() if spn.split(":")[0] == k.split(":")[0]), None)
        if h:
            return ("honey", h, self._honey_keys(h))
        host = low[1].split(":")[0]
        dom = self.ctx.domain.lower()
        short = host[:-len(dom) - 1] if host.endswith("." + dom) else host
        if low[0] in SERVICES and short in self.hosts() and "." not in short:
            return ("machine", None, {AES256: machine_key(self.secret, short)})
        return None

    def _honey_keys(self, h):
        acct = self.keys.get(h["username"])
        if acct:
            return acct["keys"]
        rnd = machine_key(self.secret, "svc:" + h["username"])           # old bait tree: uncrackable random key
        return {AES256: rnd, RC4: rnd[:16]}

    def _tgs(self, r, src, port, proto, session):
        ctx, realm = self.ctx, self.realm
        sname_t = r["sname_t"] or (1, [])
        tgt = self._tgt(r["padata"].get(1, b"")) if 1 in r["padata"] else None
        svc = self._service(sname_t)
        who = "/".join(tgt["cname_t"][1]) if tgt else None
        honey = svc[1] if svc and svc[0] == "honey" else None
        if not honey:
            spn = (r["sname"] or "").lower()
            honey = self.spns.get(spn) or next((v for k, v in self.spns.items() if spn and spn.split(":")[0] == k.split(":")[0]), None)
        if not tgt:
            ctx.emit("kerberos.tgs_req", src, port, proto, session, spn=r["sname"], realm=r["realm"][:100],
                     etypes=r["etypes"], result=ERR[41])
            if honey:
                self._attempt(src, port, proto, session, honey["username"], honey.get("token"),
                              f"service ticket request for honey SPN {honey.get('spn')} without a valid TGT")
            return krb_error(41, realm, (r["sname"] or "krbtgt").split("/"))
        if not svc:
            ctx.emit("kerberos.tgs_req", src, port, proto, session, spn=r["sname"], realm=r["realm"][:100],
                     etypes=r["etypes"], result=ERR[7], client=who)
            return krb_error(7, realm, sname_t[1] or ["krbtgt"])
        kind, h, keys = svc
        etype = next((e for e in r["etypes"] if e in keys), None)
        if etype is None:
            ctx.emit("kerberos.tgs_req", src, port, proto, session, spn=r["sname"], etypes=r["etypes"], result=ERR[14], client=who)
            return krb_error(14, realm, sname_t[1])
        now = time.time()
        sk = secrets.token_bytes(KEYLEN[etype])
        flags = kflags(1, 8, 10, 15)                       # forwardable renewable pre-authent canonicalize
        ticket = self._ticket(sname_t, realm, etype, keys[etype], 2, flags, etype, sk, tgt["crealm"], tgt["cname_t"], now)
        rep = self._kdc_rep(TGS_REP & 0x1F, 26, tgt["usage"], r, tgt["cname_t"], ticket, tgt["reply_etype"], tgt["reply_key"],
                            etype, sk, flags, sname_t, now)
        ctx.emit("kerberos.tgs_req", src, port, proto, session, spn=r["sname"], realm=r["realm"][:100], etypes=r["etypes"],
                 result="TICKET_ISSUED", etype=etype, client=who)
        if h:
            ctx.emit("honeytoken.used", src, port, proto, session, token=h.get("token"), username=h["username"], success=True,
                     desc=f"Kerberoasting of honey SPN {h.get('spn')} (service ticket issued, etype {etype}, requested by {who})",
                     planted=f"{ctx.name}:ldap ({h['username']})")
        return rep

    # ----------------------------------------------------------------- entry point
    def handle(self, data, src, port, proto, session=None, udp=False):
        ctx = self.ctx
        try:
            r = parse_kdc_req(data)
        except ValueError:
            ctx.emit("proto.interaction", src, port, proto, session, detail="non-Kerberos data")
            return None
        rep = self._tgs(r, src, port, proto, session) if r["type"] == "tgs" else self._as(r, src, port, proto, session)
        if udp and rep and rep[0] in (AS_REP, TGS_REP):    # Windows: > MaxDatagramReplySize → retry over TCP
            return krb_error(52, self.realm, ["krbtgt", self.realm])
        return rep

    def _as(self, r, src, port, proto, session):
        ctx, realm = self.ctx, self.realm
        user = (r["cname"] or "").split("/")[0]
        lu = user.lower()
        if r["realm"] and r["realm"].upper() not in (realm, ctx.netbios.upper()):
            ctx.emit("kerberos.as_req", src, port, proto, session, username=user, realm=r["realm"][:100], result="WRONG_REALM")
            return krb_error(68, realm, ["krbtgt", realm], user)
        acct = self.keys.get(lu)
        bait = self._bait(lu)
        users = self.users()
        verdict, etype = None, None
        if lu in ("krbtgt", "guest"):
            code = 18
        elif lu not in users:
            code = 6
        elif r["preauth"]:
            verdict, etype = self._preauth(r["padata"][2], acct)
            sname = [p.lower() for p in (r["sname_t"] or (2, ["krbtgt"]))[1]]
            if verdict == "ok" and acct["valid"] and sname[:1] == ["krbtgt"]:
                code = 0
            else:
                code = {"ok": 18, "skew": 37}.get(verdict, 24)
        else:
            code = 25
        n = self._enum_gate(src[0])
        if n <= ENUM_FULL or code != 6 or bait:
            ctx.emit("kerberos.as_req", src, port, proto, session, username=user, preauth=r["preauth"],
                     exists=code != 6, result=ERR.get(code, "TGT_ISSUED"), etypes=r["etypes"])
        elif n % 100 == 0:
            ctx.emit("kerberos.enum", src, port, proto, session, count=n, last=user)
        if verdict in ("ok", "skew"):                       # the bait's real secret was used
            ctx.emit("honeytoken.used", src, port, proto, session, token=acct.get("token"), username=user, success=code == 0,
                     desc="bait account authenticated to Kerberos (correct password" +
                          (", TGT issued)" if code == 0 else ")"), planted=f"{ctx.name} baits")
            if code == 0:
                ctx.emit("auth.success", src, port, proto, session, username=user, method="kerberos")
        elif code == 24:
            ctx.emit("auth.failed", src, port, proto, session, username=user, password=None, method="kerberos")
            if bait:
                self._attempt(src, port, proto, session, user, bait[0], "bait account: Kerberos pre-authentication with a wrong password")
        elif bait:
            self._attempt(src, port, proto, session, user, bait[0],
                          "bait account name in a Kerberos AS-REQ (no password: user list / AS-REP roasting)")
        if code == 0:
            return self._as_rep(r, acct, etype)
        salt = realm + (acct["sam"] if acct else user)
        return krb_error(code, realm, ["krbtgt", realm], user, method_data(salt) if code == 25 else None)


def start_kerberos(ctx, svc):
    port = svc["port"]
    kdc = KDC(ctx)
    proto = "kpasswd" if port == 464 else "kerberos"

    def tcp(conn, addr, session):
        for _ in range(10):
            hdr = conn.recv(4)
            if len(hdr) < 4:
                return
            n = struct.unpack(">I", hdr)[0]
            if n > 64 * 1024 or proto == "kpasswd":
                ctx.emit("proto.interaction", addr, port, proto, session, detail=f"{proto} request")
                return
            data = b""
            while len(data) < n:
                c = conn.recv(n - len(data))
                if not c:
                    return
                data += c
            r = kdc.handle(data, addr, port, proto, session)
            if not r:
                return
            conn.sendall(struct.pack(">I", len(r)) + r)

    serve_tcp(ctx, port, tcp, proto)
    serve_udp(ctx, port, lambda data, addr: kdc.handle(data, addr, port, proto, udp=True), proto)
