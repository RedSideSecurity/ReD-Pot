"""LDAP / LDAPS / Global Catalog decoy for the Domain Controller role.

What an attacker sees is an Active Directory DC:
* rootDSE (anonymous) → naming contexts, dnsHostName, functional levels — what nmap / ldapsearch -s base,
  BloodHound, CrackMapExec use to fingerprint a DC.
* Anonymous search of the directory → the real Windows "000004DC … successful bind must be completed" error.
* Simple bind → checked against the honeytokens (GPP / logon-script / svc_sql description passwords).
  A planted credential "works": the directory returns persona users, computers, and the honey
  service accounts (Kerberoastable svc_sql with its SPN + password in its description).
* NTLM binds — Sicily (ldap3, NetExec) and SASL GSS-SPNEGO (impacket GetUserSPNs / GetADUsers, BloodHound.py):
  CHALLENGE with the persona's target info, NTLMv2 verified against the bait accounts' NT hashes
  (adauth.BaitKeys); a sealed SASL bind switches the connection to NTLM session security like Windows.
  Kerberos SASL tokens are refused (invalidCredentials).
* Search filters are evaluated (and/or/not, equality, presence, substrings, AD bit-wise matching rules).

Events: ldap.rootdse (2), ldap.bind (3), ldap.search (3), + auth.failed / honeytoken.used / auth.success /
honeytoken.attempt (bait name with a wrong secret, 4).
"""
import json
import os
import struct
import time
import zlib
from datetime import datetime, timezone

from rpot.sensor.base import serve_tcp, tls_context
from rpot.sensor.services import ber as B
from rpot.sensor.services.adauth import BaitKeys, NTLMServer, NTLMSeal, filetime

MAX_MSG = 64 * 1024
SUCCESS, OPERATIONS_ERROR, PROTOCOL_ERROR, AUTH_METHOD_NOT_SUPPORTED, NO_SUCH_OBJECT, INVALID_CREDENTIALS = 0, 1, 2, 7, 32, 49
UNWILLING, SASL_IN_PROGRESS = 53, 14
ERR_BIND_FIRST = ("000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind "
                  "must be completed on the connection., data 0, v4563\x00")
ERR_BAD_CREDS = "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563\x00"
ERR_SASL = "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 0, v4563\x00"
OID_NTLMSSP = bytes.fromhex("060a2b0601040182370202 0a".replace(" ", ""))


def recv_msg(conn):
    """One BER element from the stream (bounded)."""
    hdr = _exact(conn, 2)
    if hdr is None:
        return None
    n = hdr[1]
    extra = b""
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4:
            raise ValueError("bad length")
        extra = _exact(conn, k)
        if extra is None:
            return None
        n = int.from_bytes(extra, "big")
    if n > MAX_MSG:
        raise ValueError("message too large")
    body = _exact(conn, n) if n else b""
    if body is None:
        return None
    return hdr + extra + body


def _exact(conn, n):
    buf = b""
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def dn_of(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def sam_of(name, netbios, domain):
    """'CORP\\user' / 'user@corp.local' / 'CN=user,…' / 'user' → 'user' (lower)."""
    n = (name or "").strip()
    if "\\" in n:
        n = n.split("\\", 1)[1]
    elif "@" in n:
        n = n.split("@", 1)[0]
    elif n.upper().startswith("CN="):
        n = n[3:].split(",", 1)[0]
    return n.lower()


def gtime(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


def _attr(name, vals):
    vals = vals if isinstance(vals, list) else [vals]
    return B.seq(B.octets(name), B.tlv(0x31, b"".join(B.octets(v) for v in vals)))


def _entry(mid, dn, attrs, want):
    want = {w.lower() for w in want}
    sel = [(k, v) for k, v in attrs.items() if v not in (None, [], "")
           and (not want or "*" in want or k.lower() in want)]
    return B.seq(B.integer(mid), B.app(4, B.octets(dn) + B.seq(*[_attr(k, v) for k, v in sel])))


def _result(mid, op, code, diag="", matched=""):
    return B.seq(B.integer(mid), B.app(op, B.enum(code) + B.octets(matched) + B.octets(diag)))


def _bind_resp(mid, code, diag="", matched=b"", sasl=None):
    body = B.enum(code) + B.octets(matched) + B.octets(diag)
    return B.seq(B.integer(mid), B.app(1, body + (B.tlv(0x87, sasl) if sasl is not None else b"")))


def _stable(s, mod):
    return zlib.crc32(s.lower().encode()) % mod


def sid_bytes(sub):
    """S-1-5-<sub…> → binary objectSid."""
    return bytes([1, len(sub)]) + (5).to_bytes(6, "big") + b"".join(struct.pack("<I", x) for x in sub)


class Directory:
    """The fake AD content, built from the persona + bait honey users + zone."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.dom = ctx.domain.lower()
        self.base = dn_of(self.dom)
        self.dsid = [21, 1000000000 + _stable(self.dom + "a", 10**9), 1000000000 + _stable(self.dom + "b", 10**9),
                     1000000000 + _stable(self.dom + "c", 10**9)]
        self.honey, self._cache = [], None
        p = os.path.join(ctx.bait_dir, "ldap", "honey_users.json")
        try:
            with open(p) as f:
                self.honey = json.load(f)[:50]
        except (OSError, ValueError):
            pass

    def sid(self, rid):
        return sid_bytes(self.dsid + [rid])

    def rootdse(self):
        c, b = self.ctx, self.base
        site = "Default-First-Site-Name"
        return {
            "currentTime": gtime(), "subschemaSubentry": f"CN=Aggregate,CN=Schema,CN=Configuration,{b}",
            "dsServiceName": f"CN=NTDS Settings,CN={c.name},CN=Servers,CN={site},CN=Sites,CN=Configuration,{b}",
            "namingContexts": [b, f"CN=Configuration,{b}", f"CN=Schema,CN=Configuration,{b}",
                               f"DC=DomainDnsZones,{b}", f"DC=ForestDnsZones,{b}"],
            "defaultNamingContext": b, "rootDomainNamingContext": b,
            "configurationNamingContext": f"CN=Configuration,{b}",
            "schemaNamingContext": f"CN=Schema,CN=Configuration,{b}",
            "serverName": f"CN={c.name},CN=Servers,CN={site},CN=Sites,CN=Configuration,{b}",
            "supportedControl": ["1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801", "1.2.840.113556.1.4.473",
                                 "1.2.840.113556.1.4.528", "1.2.840.113556.1.4.417", "1.2.840.113556.1.4.619"],
            "supportedLDAPVersion": ["3", "2"],
            "supportedLDAPPolicies": ["MaxPoolThreads", "MaxDatagramRecv", "MaxReceiveBuffer", "InitRecvTimeout",
                                      "MaxConnections", "MaxConnIdleTime", "MaxPageSize", "MaxQueryDuration"],
            "highestCommittedUSN": str(int(time.time()) % 900000 + 100000),
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            "dnsHostName": c.fqdn, "ldapServiceName": f"{self.dom}:{c.name.lower()}$@{self.dom.upper()}",
            "supportedCapabilities": ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791",
                                      "1.2.840.113556.1.4.1935", "1.2.840.113556.1.4.2080", "1.2.840.113556.1.4.2237"],
            "isSynchronized": "TRUE", "isGlobalCatalogReady": "TRUE",
            "domainFunctionality": "7", "forestFunctionality": "7", "domainControllerFunctionality": "7",
        }

    def pwd_epoch(self):
        """Stable, per-install anchor (2022-01-01 … +3 years) for pwdLastSet: a fixed base date made svc_sql's
        pwdLastSet identical on every install — a cross-install fingerprint. Stable across restarts."""
        if getattr(self, "_pwd_epoch", None) is None:
            ps = getattr(self.ctx, "persona_secret", None)
            try:
                sec = int.from_bytes(ps("ldap-pwdlastset")[:8], "big") if ps else _stable(self.dom + "pwd", 2**31)
            except Exception:
                sec = _stable(self.dom + "pwd", 2**31)
            self._pwd_epoch = 1640995200 + sec % (3 * 365 * 86400)
        return self._pwd_epoch

    # --- the directory content (pentest F-04: a 30-object stub with builtin groups in CN=Users and dangling
    # memberOf was a tell). Every object a fresh Server 2019 domain has, plus the company OU tree, staff,
    # workstations and the bait accounts; member / memberOf are derived from one membership table, so every
    # memberOf target exists and the primary group is never listed (like AD).
    def objects(self):
        now = time.time()
        if self._cache is None or now - self._cache[0] > 300:
            self._cache = (now, self._build(now))
        return self._cache[1]

    def created(self):
        """Per-install dcpromo time: 30..400 days before the first pwdLastSet anchor."""
        return self.pwd_epoch() - 30 * 86400 - _stable(self.dom + "created", 370 * 86400)

    def _day(self, t, key):
        """Same day as t, at an office-hours time (07:00-18:00 UTC) with its own seconds: objects created by an
        admin over months must not share a time of day (that was the bait-file tell)."""
        return int(t) // 86400 * 86400 + 7 * 3600 + _stable(self.dom + key + "#t", 11 * 3600)

    def company_ou(self):
        return f"OU={_dn_esc((self.ctx.cfg.get('company') or {}).get('name') or self.ctx.netbios)},{self.base}"

    def _build(self, now):
        b, objs, members = self.base, [], {}
        t0 = self.created()
        U, G, BI = f"CN=Users,{b}", f"OU=Groups,{self.company_ou()}", f"CN=Builtin,{b}"
        sch = lambda c: f"CN={c},CN=Schema,CN=Configuration,{b}"

        def add(dn, attrs, t=None, critical=False):
            t = t0 + len(objs) if t is None else t
            a = dict(attrs)
            a.setdefault("distinguishedName", dn)
            a.setdefault("name", dn.split(",", 1)[0].split("=", 1)[1].replace("\\", ""))
            a.update({"instanceType": "4", "objectGUID": _guid(self.dom, dn), "whenCreated": gtime(t),
                      "whenChanged": gtime(max(t, a.pop("_changed", t))), "uSNCreated": str(4000 + len(objs) * 7)})
            if critical:
                a["isCriticalSystemObject"] = "TRUE"
            objs.append((dn, a))
            return dn

        def cont(dn, desc, cls="container", cat="Container", **kw):
            return add(dn, {"objectClass": ["top", cls], "cn": dn.split(",")[0][3:], "description": desc,
                            "objectCategory": sch(cat), **kw}, critical=True)

        def ou(dn, desc=None, t=None, **kw):
            return add(dn, {"objectClass": ["top", "organizationalUnit"], "ou": dn.split(",")[0][3:],
                            "description": desc, "objectCategory": sch("Organizational-Unit"), **kw}, t)

        def group(dn, sam, sid, gtype, desc, t=None, critical=True, admin=False):
            local = gtype in (DOMAIN_LOCAL, BUILTIN_LOCAL)
            return add(dn, {"objectClass": ["top", "group"], "cn": sam, "sAMAccountName": sam, "objectSid": sid,
                            "groupType": str(gtype), "sAMAccountType": "536870912" if local else "268435456",
                            "description": desc, "objectCategory": sch("Group"), "adminCount": "1" if admin else None},
                       t, critical)

        ddp, ddcp = "{31B2F340-016D-11D2-945F-00C04FB984F9}", "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
        pol = f"CN=Policies,CN=System,{b}"
        add(b, {"objectClass": ["top", "domain", "domainDNS"], "name": self.dom.split(".")[0],
                "dc": self.dom.split(".")[0], "objectSid": sid_bytes(self.dsid), "ms-DS-MachineAccountQuota": "10",
                "minPwdLength": "7", "lockoutThreshold": "0", "pwdProperties": "1", "maxPwdAge": "-36288000000000",
                "minPwdAge": "-864000000000", "pwdHistoryLength": "24", "lockoutDuration": "-18000000000",
                "msDS-Behavior-Version": "7", "gPLink": f"[LDAP://CN={ddp},{pol};0]",
                "objectCategory": sch("Domain-DNS")}, t0 - 5)
        cont(U, "Default container for upgraded user accounts")
        cont(f"CN=Computers,{b}", "Default container for upgraded computer accounts")
        add(f"OU=Domain Controllers,{b}", {"objectClass": ["top", "organizationalUnit"], "ou": "Domain Controllers",
                                          "description": "Default container for domain controllers",
                                          "gPLink": f"[LDAP://CN={ddcp},{pol};0]",
                                          "objectCategory": sch("Organizational-Unit")}, critical=True)
        cont(BI, None, "builtinDomain", "Builtin-Domain", objectSid=sid_bytes([32]))
        cont(f"CN=ForeignSecurityPrincipals,{b}", "Default container for security identifiers (SIDs) associated "
             "with objects from external, trusted domains")
        cont(f"CN=System,{b}", "Builtin system settings")
        cont(f"CN=Program Data,{b}", "Default location for storage of application data.")
        cont(f"CN=Microsoft,CN=Program Data,{b}", "Default location for storage of Microsoft application data.")
        cont(f"CN=Managed Service Accounts,{b}", "Default container for managed service accounts")
        cont(f"CN=Keys,{b}", "Default container for key credential objects")
        cont(f"CN=LostAndFound,{b}", "Default container for orphaned objects", "lostAndFound", "Lost-And-Found")
        cont(f"CN=Infrastructure,{b}", None, "infrastructureUpdate", "Infrastructure-Update")
        cont(f"CN=NTDS Quotas,{b}", "Quota specifications container", "msDS-QuotaContainer", "ms-DS-Quota-Container")
        cont(f"CN=TPM Devices,{b}", None, "msTPM-InformationObjectsContainer", "ms-TPM-Information-Objects-Container")
        cont(f"CN=AdminSDHolder,CN=System,{b}", None)
        cont(pol, None)
        cont(f"CN=Password Settings Container,CN=System,{b}", None, "msDS-PasswordSettingsContainer",
             "ms-DS-Password-Settings-Container")
        cont(f"CN=MicrosoftDNS,CN=System,{b}", None)
        for guid, disp in ((ddp, "Default Domain Policy"), (ddcp, "Default Domain Controllers Policy")):
            add(f"CN={guid},{pol}", {"objectClass": ["top", "container", "groupPolicyContainer"], "cn": guid,
                                     "displayName": disp, "flags": "0", "versionNumber": str(3 + _stable(guid + self.dom, 20)),
                                     "gPCFunctionalityVersion": "2",
                                     "gPCFileSysPath": f"\\\\{self.dom}\\sysvol\\{self.dom}\\Policies\\{guid}",
                                     "objectCategory": sch("Group-Policy-Container")}, critical=True)
        fsp = {}
        for sub, cn in (([4], "S-1-5-4"), ([11], "S-1-5-11"), ([17], "S-1-5-17"), ([9], "S-1-5-9")):
            fsp[cn] = add(f"CN={cn},CN=ForeignSecurityPrincipals,{b}",
                          {"objectClass": ["top", "foreignSecurityPrincipal"], "cn": cn, "objectSid": sid_bytes(sub),
                           "objectCategory": sch("Foreign-Security-Principal")})

        # builtin (S-1-5-32-x) and default domain groups
        bi = {n: group(f"CN={n},{BI}", n, sid_bytes([32, rid]), BUILTIN_LOCAL, desc, admin=rid in (544, 548, 549, 550, 551))
              for n, rid, desc in BUILTIN_GROUPS}
        dg = {n: group(f"CN={n},{U}", n, self.sid(rid), scope, desc,
                       admin=n in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Domain Controllers",
                                   "Read-only Domain Controllers", "Enterprise Key Admins", "Key Admins"))
              for n, rid, scope, desc in DOMAIN_GROUPS}

        # users: built-ins, staff (company OU, per department), bait service accounts (CN=Users)
        co = self.ctx.cfg.get("company") or {}
        comp = self.company_ou()
        ou(comp, f"{co.get('name') or self.ctx.netbios}", t0 + 3600 + _stable(self.dom + "ou", 3 * 86400))
        t_ou = t0 + 4 * 86400
        ou(f"OU=Users,{comp}", None, t_ou)
        ou(G, None, t_ou + 60)
        ou(f"OU=Workstations,{comp}", None, t_ou + 120)
        ou(f"OU=Servers,{comp}", None, t_ou + 180)
        depts = sorted({u.get("dept") or "Staff" for u in co.get("users", [])})
        dept_g = {}
        for i, d in enumerate(depts):
            ou(f"OU={_dn_esc(d)},OU=Users,{comp}", None, t_ou + 300 + i * 40)
            dept_g[d] = group(f"CN={_dn_esc(d)} Staff,{G}", f"{d} Staff", self.sid(1120 + i), GLOBAL,
                              f"All {d} staff", t_ou + 900 + i * 40, critical=False)
        it_g = group(f"CN=IT Support,{G}", "IT Support", self.sid(1103), GLOBAL, "Helpdesk and server administration",
                     t_ou + 600, critical=False)
        shares_g = group(f"CN=File Share Users,{G}", "File Share Users", self.sid(1119), DOMAIN_LOCAL,
                         "Read access to departmental shares", t_ou + 700, critical=False)
        members.setdefault(shares_g, []).extend(dept_g.values())
        members.setdefault(bi["Remote Desktop Users"], []).append(it_g)

        uac_on, out = 66048, []
        out.append(("Administrator", "Administrator", U, "Built-in account for administering the computer/domain",
                    uac_on, 500, None, None, [dg["Domain Admins"], dg["Enterprise Admins"], dg["Schema Admins"],
                                              dg["Group Policy Creator Owners"], bi["Administrators"]], t0 - 3600, 513))
        out.append(("Guest", "Guest", U, "Built-in account for guest access to the computer/domain", 66082, 501,
                    None, None, [bi["Guests"]], t0 - 3600, 514))
        out.append(("DefaultAccount", "DefaultAccount", U, "A user account managed by the system.", 66082, 503,
                    None, None, [bi["System Managed Accounts Group"]], t0 - 3600, 513))
        out.append(("krbtgt", "krbtgt", U, "Key Distribution Center Service Account", 514, 502, "kadmin/changepw",
                    None, [dg["Denied RODC Password Replication Group"]], t0 + 2, 513))
        for i, u in enumerate(co.get("users", [])):
            d = u.get("dept") or "Staff"
            grp = [dept_g[d]] + ([it_g] if d == "IT" else [])
            tc = self._day(t_ou + 2 * 86400 + _stable(self.dom + u["username"], max(86400, self.pwd_epoch() - t_ou - 3 * 86400)),
                           u["username"])
            out.append((u["username"], u["full_name"], f"OU={_dn_esc(d)},OU=Users,{comp}", d, uac_on, 1104 + i, None,
                        u.get("email"), grp, tc, 513))
        for i, h in enumerate(self.honey):
            grp = [dg["Domain Admins"]] if h.get("admin") else []
            tc = self._day(t_ou + 86400 + _stable(self.dom + h["username"], max(86400, self.pwd_epoch() - t_ou - 2 * 86400)),
                           h["username"])
            out.append((h["username"], h.get("full_name", h["username"]), U, h.get("description", ""), uac_on,
                        1601 + i, h.get("spn"), None, grp, tc, 513))
        for sam, cn, parent, desc, uac, rid, spn, mail, grp, tc, pgid in out:
            pls = self.pwd_epoch() + _stable(self.dom + sam, 400 * 86400) if rid >= 1000 or rid == 500 else tc
            pls = max(pls, tc + 600)
            dn = add(f"CN={_dn_esc(cn)},{parent}", {
                "objectClass": ["top", "person", "organizationalPerson", "user"], "cn": cn,
                "sAMAccountName": sam, "userPrincipalName": f"{sam}@{self.dom}" if rid >= 1000 else None,
                "description": desc, "userAccountControl": str(uac),
                "servicePrincipalName": spn, "mail": mail, "displayName": cn if rid >= 1000 else None,
                "objectCategory": sch("Person"), "sAMAccountType": "805306368", "objectSid": self.sid(rid),
                "primaryGroupID": str(pgid), "pwdLastSet": str(filetime(pls)) if uac & 2 == 0 or rid == 502 else "0",
                "adminCount": "1" if rid in (500, 502) or dg["Domain Admins"] in grp else None,
                "lastLogon": str(filetime(now - _stable(sam + "l", 9 * 86400) - 3600)) if uac & 2 == 0 else "0",
                "lastLogonTimestamp": str(filetime(now - _stable(sam + "lt", 12 * 86400) - 7200)) if uac & 2 == 0 else None,
                "logonCount": str(_stable(sam + "c", 900) + 3) if uac & 2 == 0 else "0",
                "_changed": pls}, tc, critical=rid < 1000)
            for g in grp:
                members.setdefault(g, []).append(dn)

        # computers: decoys (DC in OU=Domain Controllers) + the staff's workstations
        roles = self.ctx.cfg.get("zone_roles") or {}
        for i, n in enumerate(dict.fromkeys([self.ctx.name] + list(roles))):
            role = roles.get(n, self.ctx.role.get("id"))
            win = (role or "").startswith("windows")
            dc = role == "windows-domain-controller"
            fq = f"{n.lower()}.{self.dom}"
            spn = [f"HOST/{fq}", f"HOST/{n}", f"RestrictedKrbHost/{fq}", f"RestrictedKrbHost/{n}"]
            if dc:
                spn += [f"ldap/{fq}", f"ldap/{fq}/{self.dom}", f"GC/{fq}/{self.dom}", f"DNS/{fq}",
                        f"E3514235-4B06-11D1-AB04-00C04FC2DCD2/{_guid_str(self.dom, n)}/{self.dom}"]
            elif win:
                spn += [f"TERMSRV/{fq}", f"TERMSRV/{n}", f"WSMAN/{fq}", f"WSMAN/{n}"]
            self._computer(add, n, f"OU=Domain Controllers,{b}" if dc else f"CN=Computers,{b}",
                           "Windows Server 2019 Standard" if win else "Linux", "10.0 (17763)" if win else None,
                           532480 if dc else 4096, 1000 + i, 516 if dc else 515, spn, now,
                           t0 + 1 if dc else self._day(t_ou + 86400 * (2 + i), n))
        for i, (n, osn, osv, _user) in enumerate(workstations(self.ctx)):
            fq = f"{n.lower()}.{self.dom}"
            self._computer(add, n, f"OU=Workstations,{comp}", osn, osv, 4096, 1150 + i, 515,
                           [f"HOST/{fq}", f"HOST/{n}", f"RestrictedKrbHost/{fq}", f"RestrictedKrbHost/{n}",
                            f"TERMSRV/{fq}", f"TERMSRV/{n}"], now,
                           self._day(t_ou + 86400 * (3 + _stable(self.dom + n, 300)), n))

        # default memberships of a fresh domain (WS2019 dcpromo)
        m = members
        m.setdefault(bi["Administrators"], []).extend([dg["Enterprise Admins"], dg["Domain Admins"]])
        m.setdefault(bi["Users"], []).extend([dg["Domain Users"], fsp["S-1-5-4"], fsp["S-1-5-11"]])
        m.setdefault(bi["Guests"], []).append(dg["Domain Guests"])
        m.setdefault(bi["Pre-Windows 2000 Compatible Access"], []).append(fsp["S-1-5-11"])
        m.setdefault(bi["Windows Authorization Access Group"], []).append(fsp["S-1-5-9"])
        m.setdefault(bi["IIS_IUSRS"], []).append(fsp["S-1-5-17"])
        m.setdefault(dg["Denied RODC Password Replication Group"], []).extend(
            [dg[g] for g in ("Read-only Domain Controllers", "Group Policy Creator Owners", "Domain Admins",
                             "Cert Publishers", "Enterprise Admins", "Schema Admins", "Domain Controllers")])
        idx = {dn.lower(): a for dn, a in objs}
        for g, mem in m.items():
            mem = list(dict.fromkeys(mem))
            idx[g.lower()]["member"] = mem
            for x in mem:
                idx[x.lower()].setdefault("memberOf", []).append(g)
        return objs

    def _computer(self, add, n, parent, osn, osv, uac, rid, pgid, spn, now, tc):
        fq = f"{n.lower()}.{self.dom}"
        stale = _stable(self.dom + n + "s", 10) == 0 and pgid == 515
        last = now - (60 + _stable(n, 80)) * 86400 if stale else now - _stable(n + "lt", 9 * 86400) - 1800
        return add(f"CN={n},{parent}", {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"], "cn": n,
            "sAMAccountName": f"{n}$", "dNSHostName": fq, "operatingSystem": osn, "operatingSystemVersion": osv,
            "userAccountControl": str(uac), "servicePrincipalName": spn,
            "objectCategory": f"CN=Computer,CN=Schema,CN=Configuration,{self.base}", "objectSid": self.sid(rid),
            "sAMAccountType": "805306369", "primaryGroupID": str(pgid),
            "pwdLastSet": str(filetime(max(tc + 600, last - _stable(n + "p", 25 * 86400)))),
            "lastLogonTimestamp": str(filetime(last)), "_changed": last}, tc, critical=pgid == 516)

    def search(self, base, scope, filt):
        """Objects under base (scope 0 base / 1 one level / 2 subtree) matching the filter element."""
        bl = base.lower()
        if not bl.endswith(self.base.lower()):
            return None
        out = []
        for dn, attrs in self.objects():
            d = dn.lower()
            if scope == 0 and d != bl or scope == 1 and d.split(",", 1)[-1] != bl or not d.endswith(bl):
                continue
            if match(filt, attrs):
                out.append((dn, attrs))
        return out


GLOBAL, DOMAIN_LOCAL, BUILTIN_LOCAL, UNIVERSAL = -2147483646, -2147483644, -2147483643, -2147483640
BUILTIN_GROUPS = (
    ("Administrators", 544, "Administrators have complete and unrestricted access to the computer/domain"),
    ("Users", 545, "Users are prevented from making accidental or intentional system-wide changes and can run most "
                   "applications"),
    ("Guests", 546, "Guests have the same access as members of the Users group by default, except for the Guest "
                    "account which is further restricted"),
    ("Print Operators", 550, "Members can administer printers installed on domain controllers"),
    ("Backup Operators", 551, "Backup Operators can override security restrictions for the sole purpose of backing up "
                              "or restoring files"),
    ("Replicator", 552, "Supports file replication in a domain"),
    ("Remote Desktop Users", 555, "Members in this group are granted the right to logon remotely"),
    ("Network Configuration Operators", 556, "Members in this group can have some administrative privileges to manage "
                                             "configuration of networking features"),
    ("Performance Monitor Users", 558, "Members of this group can access performance counter data locally and "
                                       "remotely"),
    ("Performance Log Users", 559, "Members of this group may schedule logging of performance counters, enable trace "
                                   "providers, and collect event traces both locally and via remote access to this "
                                   "computer"),
    ("Distributed COM Users", 562, "Members are allowed to launch, activate and use Distributed COM objects on this "
                                   "machine."),
    ("IIS_IUSRS", 568, "Built-in group used by Internet Information Services."),
    ("Cryptographic Operators", 569, "Members are authorized to perform cryptographic operations."),
    ("Event Log Readers", 573, "Members of this group can read event logs from local machine"),
    ("Certificate Service DCOM Access", 574, "Members of this group are allowed to connect to Certification "
                                             "Authorities in the enterprise"),
    ("RDS Remote Access Servers", 575, "Servers in this group enable users of RemoteApp programs and personal virtual "
                                       "desktops access to these resources."),
    ("RDS Endpoint Servers", 576, "Servers in this group run virtual machines and host sessions where users RemoteApp "
                                  "programs and personal virtual desktops run."),
    ("RDS Management Servers", 577, "Servers in this group can perform routine administrative actions on servers "
                                    "running Remote Desktop Services."),
    ("Hyper-V Administrators", 578, "Members of this group have complete and unrestricted access to all features of "
                                    "Hyper-V."),
    ("Access Control Assistance Operators", 579, "Members of this group can remotely query authorization attributes "
                                                 "and permissions for resources on this computer."),
    ("Remote Management Users", 580, "Members of this group can access WMI resources over management protocols (such "
                                     "as WS-Management via the Windows Remote Management service). This applies only "
                                     "to WMI namespaces that grant access to the user."),
    ("System Managed Accounts Group", 581, "Members of this group are managed by the system."),
    ("Storage Replica Administrators", 582, "Members of this group have complete and unrestricted access to all "
                                            "features of Storage Replica."),
    ("Server Operators", 549, "Members can administer domain servers"),
    ("Account Operators", 548, "Members can administer domain user and group accounts"),
    ("Pre-Windows 2000 Compatible Access", 554, "A backward compatibility group which allows read access on all users "
                                                "and groups in the domain"),
    ("Incoming Forest Trust Builders", 557, "Members of this group can create incoming, one-way trusts to this forest"),
    ("Windows Authorization Access Group", 560, "Members of this group have access to the computed "
                                                "tokenGroupsGlobalAndUniversal attribute on User objects"),
    ("Terminal Server License Servers", 561, "Members of this group can update user accounts in Active Directory with "
                                             "information about license issuance, for the purpose of tracking and "
                                             "reporting TS Per User CAL usage"),
)
DOMAIN_GROUPS = (
    ("Domain Computers", 515, GLOBAL, "All workstations and servers joined to the domain"),
    ("Domain Controllers", 516, GLOBAL, "All domain controllers in the domain"),
    ("Schema Admins", 518, UNIVERSAL, "Designated administrators of the schema"),
    ("Enterprise Admins", 519, UNIVERSAL, "Designated administrators of the enterprise"),
    ("Cert Publishers", 517, DOMAIN_LOCAL, "Members of this group are permitted to publish certificates to the "
                                           "directory"),
    ("Domain Admins", 512, GLOBAL, "Designated administrators of the domain"),
    ("Domain Users", 513, GLOBAL, "All domain users"),
    ("Domain Guests", 514, GLOBAL, "All domain guests"),
    ("Group Policy Creator Owners", 520, GLOBAL, "Members in this group can modify group policy for the domain"),
    ("RAS and IAS Servers", 553, DOMAIN_LOCAL, "Servers in this group can access remote access properties of users"),
    ("Allowed RODC Password Replication Group", 571, DOMAIN_LOCAL, "Members in this group can have their passwords "
                                                                   "replicated to all read-only domain controllers in "
                                                                   "the domain"),
    ("Denied RODC Password Replication Group", 572, DOMAIN_LOCAL, "Members in this group cannot have their passwords "
                                                                  "replicated to any read-only domain controllers in "
                                                                  "the domain"),
    ("Read-only Domain Controllers", 521, GLOBAL, "Members of this group are Read-Only Domain Controllers in the "
                                                  "domain"),
    ("Enterprise Read-only Domain Controllers", 498, UNIVERSAL, "Members of this group are Read-Only Domain "
                                                                "Controllers in the enterprise"),
    ("Cloneable Domain Controllers", 522, GLOBAL, "Members of this group that are domain controllers may be cloned."),
    ("Protected Users", 525, GLOBAL, "Members of this group are afforded additional protections against "
                                     "authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 "
                                     "for more information."),
    ("Key Admins", 526, GLOBAL, "Members of this group can perform administrative actions on key objects within the "
                                "domain."),
    ("Enterprise Key Admins", 527, UNIVERSAL, "Members of this group can perform administrative actions on key "
                                              "objects within the forest."),
    ("DnsAdmins", 1101, DOMAIN_LOCAL, "DNS Administrators Group"),
    ("DnsUpdateProxy", 1102, GLOBAL, "DNS clients who are permitted to perform dynamic updates on behalf of some "
                                     "other clients (such as DHCP servers)."),
)


def _dn_esc(v):
    """RFC 4514 escaping of an RDN value (company / department names come from the persona)."""
    v = str(v)
    out = "".join("\\" + c if c in ',+"\\<>;=' else c for c in v)
    return "\\" + out if out[:1] in ("#", " ") else out


def _guid(dom, dn):
    return zlib.crc32((dom + "|" + dn.lower()).encode()).to_bytes(4, "little") + \
        __import__("hashlib").sha256((dom + "#" + dn.lower()).encode()).digest()[:12]


def _guid_str(dom, n):
    g = _guid(dom, "ntds:" + n)
    return "{:08x}-{:04x}-{:04x}-{}-{}".format(int.from_bytes(g[:4], "little"), int.from_bytes(g[4:6], "little"),
                                               int.from_bytes(g[6:8], "little"), g[8:10].hex(), g[10:].hex())


WS_OS = (("Windows 10 Enterprise", "10.0 (19045)"), ("Windows 11 Enterprise", "10.0 (22631)"),
         ("Windows 10 Pro", "10.0 (19045)"))


def workstations(ctx):
    """One workstation per staff member (stable per install): (NAME, operatingSystem, version, username). The
    name follows the decoys' own prefix (RS-DC-01 → RS-WS-014 / RS-LT-022), else the NetBIOS domain's first 4."""
    users = (ctx.cfg.get("company") or {}).get("users", [])
    name = (ctx.name or "").upper()
    pre = name.split("-")[0] if "-" in name and 1 <= len(name.split("-")[0]) <= 5 else (ctx.netbios or "WS")[:4].upper()
    seed = (ctx.domain or "").lower()
    out, used = [], set()
    for u in users:
        kind = "LT" if _stable(seed + u["username"] + "k", 3) == 0 else "WS"
        n = _stable(seed + u["username"], 180) + 10
        while n in used:
            n += 1
        used.add(n)
        osn, osv = WS_OS[_stable(seed + u["username"] + "os", len(WS_OS))]
        out.append((f"{pre}-{kind}-{n:03d}"[:15], osn, osv, u["username"]))
    return out


CATEGORY = {"user": "person", "person": "person", "computer": "computer", "group": "group", "domain": "domain-dns",
            "domaindns": "domain-dns", "organizationalunit": "organizational-unit", "container": "container",
            "grouppolicycontainer": "group-policy-container", "foreignsecurityprincipal": "foreign-security-principal",
            "builtindomain": "builtin-domain"}


def _vals(attrs, name):
    for k, v in attrs.items():
        if k.lower() == name and v not in (None, "", []):
            return [x if isinstance(x, bytes) else str(x) for x in (v if isinstance(v, list) else [v])]
    return []


def _low(x):
    return x.decode("latin-1").lower() if isinstance(x, bytes) else x.lower()


def match(el, attrs, depth=0):
    """RFC 4511 filter evaluation (enough of it for AD tooling). Unknown filter types are lenient (True)."""
    tag, v = el
    if depth > 20:
        return False
    try:
        if tag == 0xA0:
            return all(match(c, attrs, depth + 1) for c in v)
        if tag == 0xA1:
            return any(match(c, attrs, depth + 1) for c in v)
        if tag == 0xA2:
            return not match(v[0], attrs, depth + 1)
        if tag == 0x87:                                                      # present
            a = B.as_str(v).lower()
            return a == "objectclass" or bool(_vals(attrs, a))
        if tag in (0xA3, 0xA8):                                              # equality / approx
            a, val = B.as_str(v[0][1]).lower(), B.as_str(v[1][1]).lower()
            if a == "objectcategory":
                want = CATEGORY.get(val, val.split(",")[0].replace("cn=", ""))
                return any(_low(x).split(",")[0].replace("cn=", "") == want for x in _vals(attrs, a))
            return any(_low(x) == val for x in _vals(attrs, a))
        if tag == 0xA4:                                                      # substrings
            a = B.as_str(v[0][1]).lower()
            for x in _vals(attrs, a):
                s, pos, ok = _low(x), 0, True
                for t, part in v[1][1]:
                    p = B.as_str(part).lower()
                    if t == 0x80:
                        ok = s.startswith(p)
                        pos = len(p)
                    elif t == 0x81:
                        i = s.find(p, pos)
                        ok, pos = i >= 0, i + len(p)
                    elif t == 0x82:
                        ok = s.endswith(p) and len(s) - len(p) >= pos
                    if not ok:
                        break
                if ok:
                    return True
            return False
        if tag in (0xA5, 0xA6):                                              # >= / <=
            a, val = B.as_str(v[0][1]).lower(), B.as_str(v[1][1])
            for x in _vals(attrs, a):
                try:
                    l, r = int(x), int(val)
                except ValueError:
                    l, r = _low(x), val.lower()
                if (l >= r) if tag == 0xA5 else (l <= r):
                    return True
            return False
        if tag == 0xA9:                                                      # extensible (AD bit-wise rules)
            f = {t: B.as_str(x) for t, x in v}
            rule, a, val = f.get(0x81, ""), f.get(0x82, "").lower(), f.get(0x83, "")
            if rule in ("1.2.840.113556.1.4.803", "1.2.840.113556.1.4.804"):
                bits = int(val)
                xs = [int(x) for x in _vals(attrs, a) if not isinstance(x, bytes)]
                return any((x & bits) == bits if rule.endswith("803") else bool(x & bits) for x in xs)
            return any(_low(x) == val.lower() for x in _vals(attrs, a)) if a else True
    except (IndexError, TypeError, ValueError, AttributeError):
        return False
    return True


def _spnego(cred):
    """GSS-SPNEGO credentials → (inner token, wrapped?) ; raw NTLMSSP is accepted like Windows does."""
    if cred.startswith(b"NTLMSSP\x00"):
        return cred, False
    tag, v = B.one(cred)
    if tag == 0x60:                                    # GSS InitialContextToken: OID + NegTokenInit [0]
        init = B.find(v, 0xA0)[0][1]
        tok = B.find(init, 0xA2)
    elif tag == 0xA1:                                  # NegTokenResp
        tok = B.find(v[0][1], 0xA2)
    else:
        raise ValueError("not SPNEGO")
    if not tok or not isinstance(tok[0][1], bytes):
        raise ValueError("no mech token")
    return bytes(tok[0][1]), True


def _negresp(state, token=None):
    body = B.ctx(0, B.enum(state)) + (B.ctx(1, OID_NTLMSSP) if token else b"") + (B.ctx(2, B.octets(token)) if token else b"")
    return B.tlv(0xA1, B.seq(body))


def start_ldap(ctx, svc):
    port = svc["port"]
    tls = tls_context(ctx, [ctx.fqdn, ctx.domain]) if svc.get("tls") else None
    proto = "ldaps" if tls else ("gc" if port in (3268, 3269) else "ldap")
    dir_ = Directory(ctx)
    keys = BaitKeys(ctx.bait_dir)

    def ntlm_done(st, res, method, addr, session):
        """Outcome of an NTLM AUTHENTICATE → True when the bind succeeds."""
        user = res["user"]
        lu = user.split("@")[0].split("\\")[-1].lower()
        acct = res["account"]
        ctx.emit("ldap.bind", addr, port, proto, session, method=method, username=f"{res['domain']}\\{user}"[:200],
                 workstation=res["host"] or None)
        if res["ok"]:
            ok = acct["valid"]
            ctx.emit("honeytoken.used", addr, port, proto, session, token=acct.get("token"), username=user, success=ok,
                     desc="bait account NTLM bind to LDAP (correct password)", planted=f"{ctx.name} baits")
            if ok:
                ctx.emit("auth.success", addr, port, proto, session, username=user, method="ntlm")
                st.update(bound="user", who=lu)
            return ok
        if not user:
            ctx.emit("auth.failed", addr, port, proto, session, username=None, password=None, method="ntlm-anonymous")
            return False
        ctx.emit("auth.failed", addr, port, proto, session, username=lu, password=None, method="ntlm")
        tid = (acct or {}).get("token") or (ctx.tokens.bait_user(lu)[0] if ctx.tokens.username_is_bait(lu) else None)
        if acct or tid:
            ctx.emit("honeytoken.attempt", addr, port, proto, session, token=tid, username=user,
                     desc="bait account: LDAP NTLM bind with a wrong password", planted=f"{ctx.name} baits")
        return False

    def bind(st, mid, op, addr, session):
        """→ (response bytes, seal-after-send or None)."""
        try:
            name = B.as_str(op[1][1])
            atag, aval = op[2]
        except (IndexError, TypeError):
            return _bind_resp(mid, PROTOCOL_ERROR), None
        st["ntlm"] = st["ntlm"] if atag in (0x8B, 0xA3) else None
        if atag == 0x80:                                       # simple
            pw = B.as_str(aval)
            st.update(bound=None, who=None)
            if not name and not pw:
                st["bound"] = "anonymous"
                ctx.emit("ldap.bind", addr, port, proto, session, method="anonymous")
                return _bind_resp(mid, SUCCESS), None
            user = sam_of(name, ctx.netbios, ctx.domain)
            ctx.emit("ldap.bind", addr, port, proto, session, method="simple", username=name[:200])
            if pw and ctx.check_cred(user, pw, "ldap", addr, port, session, proto=proto):
                st.update(bound="user", who=user)
                return _bind_resp(mid, SUCCESS), None
            if not pw:                                         # unauthenticated bind (RFC 4513 5.1.2)
                ctx.emit("auth.failed", addr, port, proto, session, username=user, password=None)
            return _bind_resp(mid, UNWILLING if not pw else INVALID_CREDENTIALS, "" if not pw else ERR_BAD_CREDS), None
        if atag == 0x89:                                       # sicilyPackageDiscovery
            ctx.emit("ldap.bind", addr, port, proto, session, method="sicily-discovery")
            return _bind_resp(mid, SUCCESS, matched=b"NTLM"), None
        if atag in (0x8A, 0x8B):                               # sicilyNegotiate / sicilyResponse
            try:
                if atag == 0x8A:
                    st["ntlm"] = NTLMServer(ctx, keys)
                    return _bind_resp(mid, SUCCESS, matched=st["ntlm"].challenge(bytes(aval))), None
                if not st["ntlm"]:
                    return _bind_resp(mid, PROTOCOL_ERROR), None
                res = st["ntlm"].authenticate(bytes(aval))
            except ValueError:
                ctx.emit("ldap.bind", addr, port, proto, session, method="sicily-ntlm", detail="malformed NTLM")
                return _bind_resp(mid, PROTOCOL_ERROR), None
            st["ntlm"] = None
            st.update(bound=None, who=None)
            ok = ntlm_done(st, res, "sicily-ntlm", addr, session)
            return _bind_resp(mid, SUCCESS if ok else INVALID_CREDENTIALS, "" if ok else ERR_BAD_CREDS), None
        if atag == 0xA3:                                       # SASL
            try:
                mech = B.as_str(aval[0][1])[:30]
                cred = bytes(aval[1][1]) if len(aval) > 1 else b""
            except (IndexError, TypeError):
                return _bind_resp(mid, PROTOCOL_ERROR), None
            if mech.upper() == "GSS-SPNEGO" and cred:
                try:
                    tok, wrapped = _spnego(cred)
                except (ValueError, IndexError, TypeError):
                    tok, wrapped = b"", True
                if tok.startswith(b"NTLMSSP\x00") and tok[8:9] == b"\x01":
                    try:
                        st["ntlm"] = NTLMServer(ctx, keys)
                        ch = st["ntlm"].challenge(tok)
                    except ValueError:
                        return _bind_resp(mid, PROTOCOL_ERROR), None
                    return _bind_resp(mid, SASL_IN_PROGRESS, sasl=_negresp(1, ch) if wrapped else ch), None
                if tok.startswith(b"NTLMSSP\x00") and tok[8:9] == b"\x03" and st["ntlm"]:
                    try:
                        res = st["ntlm"].authenticate(tok)
                    except ValueError:
                        return _bind_resp(mid, PROTOCOL_ERROR), None
                    srv, st["ntlm"] = st["ntlm"], None
                    st.update(bound=None, who=None)
                    if ntlm_done(st, res, "sasl:GSS-SPNEGO(NTLM)", addr, session):
                        f = res["flags"]
                        seal = NTLMSeal(f, res["session_key"], seal=bool(f & 0x20)) if f & 0x30 and not tls else None
                        return _bind_resp(mid, SUCCESS, sasl=_negresp(0) if wrapped else None), seal
                    return _bind_resp(mid, INVALID_CREDENTIALS, ERR_BAD_CREDS), None
                mech = "GSS-SPNEGO(Kerberos)" if tok[:1] in (b"\x60", b"\x6e") else mech
            ctx.emit("ldap.bind", addr, port, proto, session, method="sasl:" + mech, username=name[:200] or None)
            if mech.upper() in ("GSSAPI", "GSS-SPNEGO(KERBEROS)", "GSS-SPNEGO"):
                return _bind_resp(mid, INVALID_CREDENTIALS, ERR_SASL), None
            return _bind_resp(mid, AUTH_METHOD_NOT_SUPPORTED), None
        ctx.emit("ldap.bind", addr, port, proto, session, method=f"unknown:{atag:#x}", username=name[:200] or None)
        return _bind_resp(mid, AUTH_METHOD_NOT_SUPPORTED), None

    def handle(conn, addr, session):
        st = {"bound": None, "who": None, "ntlm": None, "seal": None}
        pending, n = [], 0
        while n < 200:
            if not pending:
                if st["seal"]:                                 # NTLM-sealed SASL frames: 4-byte length + sig + data
                    hdr = _exact(conn, 4)
                    if hdr is None:
                        return
                    ln = struct.unpack(">I", hdr)[0]
                    if not 16 <= ln <= MAX_MSG:
                        return
                    frame = _exact(conn, ln)
                    if frame is None:
                        return
                    plain, pos = st["seal"].unwrap(frame), 0
                    while pos < len(plain):
                        _, _, end = B.read_tlv(plain, pos)
                        pending.append(plain[pos:end])
                        pos = end
                    if not pending:
                        return
                else:
                    raw = recv_msg(conn)
                    if raw is None:
                        return
                    pending.append(raw)
            raw = pending.pop(0)
            n += 1
            try:
                tag, msg = B.one(raw)
                mid = B.as_int(msg[0][1])
                op_tag, op = msg[1]
            except (ValueError, IndexError, TypeError):
                ctx.emit("proto.interaction", addr, port, proto, session, detail="malformed LDAP")
                return
            if op_tag == 0x42:                                         # unbind
                return
            if op_tag == 0x50:                                         # abandon: no response
                continue
            out, seal_next = process(st, mid, op_tag, op, addr, session)
            if out:
                out = B.win(out)                                       # Windows length encoding
                conn.sendall(st["seal"].wrap(out) if st["seal"] else out)
            if seal_next:
                st["seal"] = seal_next

    def process(st, mid, op_tag, op, addr, session):
        if op_tag == 0x60:                                             # bind
            return bind(st, mid, op, addr, session)
        if op_tag == 0x63:                                             # search
            try:
                base = B.as_str(op[0][1])
                scope = B.as_int(op[1][1])
                size = B.as_int(op[3][1]) or 1000
                filt = op[6]
                want = [B.as_str(v) for _, v in (op[7][1] if len(op) > 7 else [])]
            except (IndexError, TypeError):
                return _result(mid, 5, PROTOCOL_ERROR), None
            fstr = B.walk_strings([filt])
            if base == "" and scope == 0:
                ctx.emit("ldap.rootdse", addr, port, proto, session, attrs=want[:20])
                return _entry(mid, "", dir_.rootdse(), want) + _result(mid, 5, SUCCESS), None
            ctx.emit("ldap.search", addr, port, proto, session, base=base[:200], scope=scope,
                     filter=" ".join(x.decode("utf-8", "replace") for x in fstr)[:300], attrs=want[:20],
                     bound=st["who"] or st["bound"] or None)
            if st["bound"] != "user":
                return _result(mid, 5, OPERATIONS_ERROR, ERR_BIND_FIRST), None
            res = dir_.search(base, scope, filt)
            if res is None:
                return _result(mid, 5, NO_SUCH_OBJECT, f"0000208D: NameErr: DSID-0310028B, problem 2001 "
                                                    f"(NO_OBJECT), data 0, best match of:\n\t'{dir_.base}'\n\x00",
                               dir_.base), None
            out = b"".join(_entry(mid, dn, a, want) for dn, a in res[:min(size, 1000)])
            return out + _result(mid, 5, SUCCESS), None
        if op_tag == 0x77:                                             # extended (StartTLS, whoami)
            ctx.emit("proto.interaction", addr, port, proto, session, detail="ldap extended op")
            return B.seq(B.integer(mid), B.app(24, B.enum(UNWILLING) + B.octets("") + B.octets(""))), None
        # add / modify / delete / modrdn / compare → write attempts against AD
        bound = st["bound"]
        ctx.emit("ldap.search" if op_tag == 0x6E else "ldap.modify", addr, port, proto, session,
                 op={0x66: "modify", 0x68: "add", 0x4A: "delete", 0x6C: "modrdn", 0x6E: "compare"}.get(op_tag, hex(op_tag)),
                 bound=st["who"] or bound or None)
        return _result(mid, (op_tag & 0x1F) + 1, OPERATIONS_ERROR if bound != "user" else 50,
                       ERR_BIND_FIRST if bound != "user" else ""), None

    serve_tcp(ctx, port, handle, proto, tls=tls)
