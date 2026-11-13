"""Deployment config (rpot.json) + role catalog helpers."""
import glob
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROLES_DIR = os.environ.get("RPOT_ROLES", os.path.join(ROOT, "roles"))


def load_roles():
    roles = {}
    for f in sorted(glob.glob(os.path.join(ROLES_DIR, "*.json"))):
        with open(f) as fh:
            r = json.load(fh)
        roles[r["id"]] = r
    return roles


def load_config(path):
    with open(path) as f:
        return json.load(f)


CONFIG_VERSION = 2          # rpot.json schema of CE 1.0 (network.mode host|bridge, sensors[].iface)
NET_MODES = ("host", "bridge")


def check_version(cfg):
    """Commands that change an existing install refuse any other rpot.json schema (CE 1.0 has no migration)."""
    v = cfg.get("version") if isinstance(cfg, dict) else None
    if v != CONFIG_VERSION:
        raise ValueError(f"rpot.json schema version {v!r} is not {CONFIG_VERSION}: "
                         "CE 1.0 supports fresh installs only (reinstall the manager)")
    return cfg


def save_config(cfg, path):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def sensor_entry(cfg, name):
    for s in cfg.get("sensors", []):
        if s["name"].upper() == name.upper():
            return s
    raise KeyError(f"sensor {name!r} not in config")


CRED_ITER = 5000   # PBKDF2 rounds: cheap per login attempt, expensive to brute-force a whole wordlist


def cred_hash(username, password, salt):
    import hashlib
    raw = f"{str(username).lower()}\0{password}".encode("utf-8", "surrogatepass")
    return hashlib.pbkdf2_hmac("sha256", raw, salt.encode(), CRED_ITER).hex()


def user_hash(username, salt):
    import hashlib
    return hashlib.sha256((salt + "\0" + str(username).lower()).encode("utf-8", "surrogatepass")).hexdigest()


def _md4(data):
    """MD4 (RFC 1320) in pure Python — OpenSSL 3 no longer ships it, and NT hashes need it."""
    import struct
    msk = 0xFFFFFFFF
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & msk
    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for i in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[i:i + 64])
        a, b, c, d = h
        for k in range(16):
            a, b, c, d = d, rol((a + ((b & c) | (~b & d)) + x[k]) & msk, (3, 7, 11, 19)[k % 4]), b, c
        for k in range(16):
            a, b, c, d = d, rol((a + ((b & c) | (b & d) | (c & d)) + x[(k % 4) * 4 + k // 4] + 0x5A827999) & msk,
                                (3, 5, 9, 13)[k % 4]), b, c
        for k in range(16):
            a, b, c, d = d, rol((a + (b ^ c ^ d) + x[(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[k]] + 0x6ED9EBA1) & msk,
                                (3, 9, 11, 15)[k % 4]), b, c
        h = [(v + n) & msk for v, n in zip(h, (a, b, c, d))]
    return struct.pack("<4I", *h)


def nt_hash(password):
    """NT hash = MD4(UTF-16LE(password)) — what NTLM proves knowledge of."""
    return _md4(str(password).encode("utf-16le", "surrogatepass"))


def _ntlm_bait(t):
    """Credentials that NTLM decoys (SMB/RDP) must be able to verify: valid on an SMB/RDP service, or a
    domain account (valid on LDAP, or nowhere = "no real access" service account an attacker would
    still try on a Windows server)."""
    v = t.get("valid_on") or []
    return not v or any(x.rsplit(":", 1)[-1] in ("smb", "rdp", "ldap") for x in v)


def sensor_token_view(tokens, salt, role):
    """What a SENSOR may know about honeytokens: salted hashes only — no plaintext bait passwords,
    no usernames, no file locations / descriptions (the manager enriches events by token id).
    Document beacon ids go only to web decoys (they serve /assets/<id>.png).
    Windows decoys also get the NT hash of the domain/SMB/RDP bait credentials: NTLM never sends the
    password, so a correct bait password can only be recognised from it (trade-off: an NT hash is
    password-equivalent for NTLM, but only for fake bait accounts that exist nowhere but on decoys)."""
    out = {}
    win = str(role or "").startswith("windows-")
    for tid, t in tokens.items():
        k = t.get("kind")
        if k == "credential":
            out[tid] = {"kind": k, "cred": cred_hash(t["username"], t["password"], salt),
                        "user": user_hash(t["username"], salt), "valid_on": t.get("valid_on", [])}
            if win and _ntlm_bait(t):
                out[tid]["nt"] = nt_hash(t["password"]).hex()
        elif k == "sshkey":
            out[tid] = {"kind": k, "fingerprint": t["fingerprint"], "user": user_hash(t["username"], salt),
                        "valid_on": t.get("valid_on", [])}
        elif k == "document" and role == "linux-web-hosting":
            out[tid] = {"kind": k}
    return out


def zone_view(sensors):
    """Decoy names → IPs (and roles) for the DNS / DC decoys' fake company zone."""
    zone, roles = {}, {}
    for x in sensors or []:
        if x.get("revoked") or not x.get("name"):
            continue
        n = x["name"].upper()
        roles[n] = x.get("role")
        if x.get("ip"):
            zone[n] = x["ip"]
    return {"zone": zone, "zone_roles": roles}


class TokenIndex:
    """Fast lookups of planted honeytokens. Works with the full manager view (plaintext) and with
    the hashed sensor view produced by sensor_token_view()."""

    def __init__(self, cfg):
        self.tokens = cfg.get("tokens", {})
        self.salt = cfg.get("token_salt") or (cfg.get("company") or {}).get("token_salt") or ""
        self.by_cred, self.by_hash, self.by_key, self.users = {}, {}, {}, set()
        self.user_tid = {}            # user hash → token id (username-only detection, e.g. SMB/NTLM)
        self.by_nt = {}               # user hash → [(token id, NT hash bytes)] (NTLM verification)
        for tid, t in self.tokens.items():
            if t["kind"] == "credential":
                if "password" in t:
                    self.by_cred[(t["username"].lower(), t["password"])] = tid
                    self.users.add(user_hash(t["username"], self.salt))
                if "cred" in t:
                    self.by_hash[t["cred"]] = tid
                nt = bytes.fromhex(t["nt"]) if t.get("nt") else (nt_hash(t["password"]) if "password" in t else None)
                uh = t.get("user") or user_hash(t["username"], self.salt)
                if nt:
                    self.by_nt.setdefault(uh, []).append((tid, nt))
            elif t["kind"] == "sshkey":
                self.by_key[t["fingerprint"]] = tid
            uh = t.get("user") or (user_hash(t["username"], self.salt) if t.get("username") else None)
            if uh:
                self.users.add(uh)
                if t["kind"] == "credential" or uh not in self.user_tid:
                    self.user_tid.setdefault(uh, tid)

    def credential(self, username, password):
        """Return (token_id, token) if username/password is a planted credential."""
        if username is None or password is None:
            return None, None
        tid = self.by_cred.get((str(username).lower(), str(password)))
        if not tid and self.by_hash and len(str(password)) <= 128:
            tid = self.by_hash.get(cred_hash(username, password, self.salt))
        return (tid, self.tokens[tid]) if tid else (None, None)

    # generic names that sit in every wordlist: seeing one alone is not proof of bait use
    # (a matching PASSWORD still is — credential() is unaffected)
    COMMON = frozenset({"admin", "administrator", "root", "backup", "deploy", "test", "guest", "user", "webadmin"})

    def username_is_bait(self, username):
        return bool(username) and str(username).lower() not in self.COMMON and user_hash(username, self.salt) in self.users

    def bait_user(self, username):
        """(token id, token) of the bait account behind a username — for protocols where only the name is
        seen (NTLM never reveals the password). Generic names never match (see COMMON)."""
        if not self.username_is_bait(username):
            return None, None
        tid = self.user_tid.get(user_hash(username, self.salt))
        return (tid, self.tokens[tid]) if tid else (None, None)

    def ntlm_candidates(self, username):
        """[(token id, token, NT hash)] of the bait credentials behind a username that this index can
        verify an NTLM response for (generic names included: the response proves the password)."""
        if not username:
            return []
        return [(tid, self.tokens[tid], nt) for tid, nt in self.by_nt.get(user_hash(username, self.salt), [])]

    def key(self, fingerprint):
        tid = self.by_key.get(fingerprint)
        return (tid, self.tokens[tid]) if tid else (None, None)

    def key_user_ok(self, token, username):
        if "username" in token:
            return username == token["username"]
        return user_hash(username, self.salt) == token.get("user")

    def valid_on(self, token, sensor, service):
        return f"{sensor.upper()}:{service}" in token.get("valid_on", [])
