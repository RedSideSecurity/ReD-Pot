"""SSH emulator (paramiko): realistic banner, password + public-key auth, simulated shell.

Nothing the attacker types is ever executed. The shell answers a small set of commands
from the persona and the bait home directory; everything else gets a believable error.
Events: ssh.client (2: version string), auth.failed (3), honeytoken.used (5),
auth.success (4), cmd.exec (4), ssh.download (4: wget/curl URL recorded, not fetched).
"""
import os
import posixpath
import re
import threading
import time

import logging

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # attacker garbage must not flood container logs

from rpot.sensor import base
from rpot.sensor.base import serve_tcp, safe_join

# RC-31 (N-3 review): every SSH session channel is served by its own thread, so channels are capped like OpenSSH's
# MaxSessions (default 10) per connection and charged to the decoy-wide budget (base.take_aux, kind "ssh-channel":
# per source IP, decoy-wide, thread headroom). A refused channel open gets what OpenSSH answers over MaxSessions:
# SSH_OPEN_ADMINISTRATIVELY_PROHIBITED ("open failed").
MAX_CHANNELS = 10
CHANNEL_KIND = "ssh-channel"


class _Server(paramiko.ServerInterface):
    def __init__(self, ctx, addr, port, session):
        self.ctx, self.addr, self.port, self.session = ctx, addr, port, session
        self.user = None
        self.req = {}  # chanid -> {"event": Event, "exec": cmd or None}
        self.attempts = 0
        self.channels, self.lock, self.budget = set(), threading.Lock(), base.BUDGET   # open channel ids (slots held)

    def release(self, chanid):
        """Channel finished: give its slot back (once)."""
        with self.lock:
            if chanid not in self.channels:
                return
            self.channels.discard(chanid)
        self.budget.give_aux(self.addr[0], CHANNEL_KIND)
        self.req.pop(chanid, None)

    def release_all(self):
        for cid in list(self.channels):
            self.release(cid)

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        self.attempts += 1
        if self.ctx.check_cred(username, password, "ssh", self.addr, self.port, self.session):
            self.user = username
            return paramiko.AUTH_SUCCESSFUL
        time.sleep(1.5)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fp = key.fingerprint  # "SHA256:..."
        tid, tok = self.ctx.tokens.key(fp)
        if tid:
            ok = self.ctx.tokens.valid_on(tok, self.ctx.name, "ssh") and self.ctx.tokens.key_user_ok(tok, username)
            self.ctx.emit("honeytoken.used", self.addr, self.port, "ssh", self.session, token=tid, username=username,
                          planted=tok.get("planted"), desc=tok.get("desc"), success=ok)
            if ok:
                self.user = username
                self.ctx.emit("auth.success", self.addr, self.port, "ssh", self.session, username=username, method="publickey")
                return paramiko.AUTH_SUCCESSFUL
        else:
            self.ctx.emit("auth.failed", self.addr, self.port, "ssh", self.session, username=username,
                          method="publickey", key_fp=fp)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind != "session":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        with self.lock:
            if len(self.channels) >= MAX_CHANNELS:
                why, limit = "per_connection", MAX_CHANNELS
            else:
                why = self.budget.take_aux(self.addr[0], CHANNEL_KIND)
                limit = self.budget.aux_limit(why)
                if why is None:
                    self.channels.add(chanid)
                    return paramiko.OPEN_SUCCEEDED
        if why in ("per_connection", "per_ip"):
            base.exhaustion(self.ctx, self.addr, self.port, "ssh", "ssh_channel", why, limit, session=self.session,
                            username=self.user)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def _r(self, channel):
        return self.req.setdefault(channel.get_id(), {"event": threading.Event(), "exec": None})

    def check_channel_shell_request(self, channel):
        self._r(channel)["event"].set()
        return True

    def check_channel_exec_request(self, channel, command):
        r = self._r(channel)
        r["exec"] = command.decode("utf-8", "replace")[:2000]
        r["event"].set()
        return True

    def check_channel_env_request(self, *a):
        return True

    def check_channel_window_change_request(self, *a):
        return True


class FakeShell:
    """Simulated bash: a small parser (quotes, $VAR/${VAR}/$(…), ;, &&, ||, |, redirections) over a
    fixed set of fake commands. Nothing is ever executed; files are only read from the bait tree."""

    NET_DELAY = 1.5           # seconds before a (simulated) failed outbound connection gives up

    def __init__(self, ctx, user, home_root, addr=None, port=None, session=None):
        self.ctx, self.user = ctx, user
        self.addr, self.port, self.session = addr, port, session
        self.home = f"/home/{user}" if user != "root" else "/root"
        self.cwd = self.home
        self.home_root = home_root  # bait dir with home/<user> (and ftp/ = /srv/ftp on the backup role)
        self.host = ctx.name.lower()
        self.env = {"HOME": self.home, "USER": user, "LOGNAME": user, "SHELL": "/bin/bash", "HOSTNAME": self.host,
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                    "TERM": "xterm-256color", "SHLVL": "1", "PWD": self.cwd}
        self.rc = 0
        self.vfs = {}             # files this session wrote with > / >> (memory only, never on disk; capped)

    def prompt(self):
        cwd = "~" + self.cwd[len(self.home):] if self.cwd.startswith(self.home) else self.cwd
        return f"{self.user}@{self.host}:{cwd}$ "

    def _real(self, path):
        p = posixpath.normpath(posixpath.join(self.cwd, path))
        if p.startswith("/home/"):
            return safe_join(self.home_root, "home", p[len("/home/"):]), p
        if p == "/srv/ftp" or p.startswith("/srv/ftp/"):     # backup role: SSH sees what FTP serves
            ftp = os.path.join(self.home_root, "ftp")
            if os.path.isdir(ftp):
                return safe_join(ftp, p[len("/srv/ftp"):]), p
        return None, p

    # ---------------------------------------------------------------------------------- parsing
    def _var(self, name):
        if name == "?":
            return str(self.rc)
        if name == "$":
            return "1290"
        if name == "PWD":
            return self.cwd
        return self.env.get(name, "")

    def _tokens(self, line, depth=0):
        """→ list of ("w", word) / ("op", ";"|"&&"|"||"|"|") / ("r", (fd, op, target))."""
        toks, i, n = [], 0, len(line)
        word, has = [], False

        def flush():
            nonlocal word, has
            if has:
                toks.append(("w", "".join(word)))
            word, has = [], False

        def dollar(i):                       # at line[i] == "$" → (text, next index)
            if i + 1 < n and line[i + 1] == "{":
                j = line.find("}", i + 2)
                if j > 0:
                    return self._var(line[i + 2:j].split(":")[0]), j + 1
            if i + 1 < n and line[i + 1] == "(":
                lvl, j = 1, i + 2
                while j < n and lvl:
                    lvl += {"(": 1, ")": -1}.get(line[j], 0)
                    j += 1
                sub = self.run(line[i + 2:j - 1], depth + 1) if depth < 3 else ""
                return sub.replace("\x04", "").rstrip("\n"), j
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[?$#0-9]", line[i + 1:])
            if m:
                return self._var(m.group(0)), i + 1 + len(m.group(0))
            return "$", i + 1

        while i < n:
            c = line[i]
            if c in " \t":
                flush()
                i += 1
            elif c == "\\" and i + 1 < n:
                word.append(line[i + 1]); has = True; i += 2
            elif c == "'":
                j = line.find("'", i + 1)
                j = n if j < 0 else j
                word.append(line[i + 1:j]); has = True; i = j + 1
            elif c == '"':
                i += 1
                has = True
                while i < n and line[i] != '"':
                    if line[i] == "\\" and i + 1 < n and line[i + 1] in '"$\\`':
                        word.append(line[i + 1]); i += 2
                    elif line[i] == "$":
                        t, i = dollar(i)
                        word.append(t)
                    else:
                        word.append(line[i]); i += 1
                i += 1
            elif c == "$":
                t, i = dollar(i)
                word.append(t)
                has = True
            elif c == "#" and not has:
                break
            elif c == "`":
                j = line.find("`", i + 1)
                j = n if j < 0 else j
                word.append(self.run(line[i + 1:j], depth + 1).replace("\x04", "").rstrip("\n") if depth < 3 else "")
                has = True
                i = j + 1
            elif c in ";|&<>" or (c.isdigit() and not has and re.match(r"\d+[<>]", line[i:])):
                flush()
                if line.startswith("&>", i):                                   # &>file / &>>file
                    m = re.match(r"&>>?\s*([^\s;|&<>]*)", line[i:])
                    toks.append(("r", ("&", ">", m.group(1))))
                    i += len(m.group(0))
                elif c in ";|&":
                    op = line[i:i + 2] if line[i:i + 2] in ("&&", "||") else c
                    toks.append(("op", ";" if op == "&" else op))
                    i += len(op)
                else:                                                          # [n]> [n]>> [n]>&m [n]<
                    m = re.match(r"(\d*)(>>|>&|>|<)\s*(&?\d+(?![^\s;|&<>])|[^\s;|&<>]*)", line[i:])
                    toks.append(("r", (m.group(1) or ("0" if m.group(2) == "<" else "1"), m.group(2), m.group(3))))
                    i += len(m.group(0))
            else:
                word.append(c); has = True; i += 1
        flush()
        return toks

    @staticmethod
    def _split(line):
        """Split at top-level ; && || | & (quotes, $(…), `…` respected) → [(connector, [cmd, …])].
        Words are expanded later, per command, so `X=1; echo $X` behaves like bash."""
        lists, pipe, cur, i, n = [], [], [], 0, len(line)
        conn, q, par, bq = ";", None, 0, False
        while i < n:
            c = line[i]
            if c == "\\" and q != "'" and i + 1 < n:
                cur.append(line[i:i + 2]); i += 2
                continue
            if q:
                q = None if c == q else q
            elif bq:
                bq = c != "`"
            elif c in "'\"":
                q = c
            elif c == "`":
                bq = True
            elif line.startswith("$(", i):
                par += 1; cur.append("$("); i += 2
                continue
            elif c == ")" and par:
                par -= 1
            elif par:
                pass
            elif c == "#" and (not cur or cur[-1] in " \t"):
                break
            elif c in ";|&" and not (c == "&" and (line[i - 1:i] == ">" or line[i + 1:i + 2] == ">")):
                op = line[i:i + 2] if line[i:i + 2] in ("&&", "||") else c
                pipe.append("".join(cur)); cur = []
                if op == "|":
                    pass
                else:
                    lists.append((conn, pipe))
                    conn, pipe = (";" if op == "&" else op), []
                i += len(op)
                continue
            cur.append(c); i += 1
        pipe.append("".join(cur))
        lists.append((conn, pipe))
        return [(cn, [x.strip() for x in p]) for cn, p in lists if any(x.strip() for x in p)]

    def run(self, line, depth=0):
        """Return output text for one command line (no execution, simulated). "\\x04" = logout."""
        out = []
        for conn, pipe in self._split(line.strip()[:4096]):
            if (conn == "&&" and self.rc != 0) or (conn == "||" and self.rc == 0):
                continue
            stdin, o, e, rc = None, "", "", 0
            for k, raw in enumerate(pipe):
                try:
                    toks = self._tokens(raw, depth)
                except Exception:
                    toks = [("w", x) for x in raw.split()]
                o, e, rc = self._simple(toks, stdin)
                if k < len(pipe) - 1:
                    out.append(e)
                    stdin = o
            out.append(o + e)
            self.rc = rc
            if "\x04" in o:
                break
        return "".join(out)

    def _simple(self, toks, stdin):
        argv = [t[1] for t in toks if t[0] == "w"]
        redirs = [t[1] for t in toks if t[0] == "r"]
        assign = {}
        while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):        # VAR=value [cmd]
            k, _, v = argv.pop(0).partition("=")
            assign[k] = v
        if not argv:
            self.env.update(assign)
        for fd, op, tgt in redirs:
            if op == "<" and tgt == "/dev/null":
                stdin = ""
            elif op == "<" and tgt:
                real, p = self._real(tgt.replace("~", self.home, 1))
                if p in self.vfs:
                    stdin = self.vfs[p]
                elif real and os.path.isfile(real):
                    stdin = open(real, "r", errors="replace").read()
                else:
                    return "", f"-bash: {tgt}: No such file or directory\n", 1
        for fd, op, tgt in redirs:                   # bash opens the targets before running the command
            p = posixpath.normpath(posixpath.join(self.cwd, tgt.replace("~", self.home, 1))) if tgt else ""
            if op in (">", ">>") and not (p.startswith(("/dev/", "/tmp/")) or p.startswith(self.home + "/")):
                return "", f"-bash: {tgt}: Permission denied\n", 1
        if not argv:
            return "", "", 0
        try:
            r = self._one(argv, stdin)
        except Exception:
            r = ("", "", 0)
        o, e, rc = r if isinstance(r, tuple) else (r, "", 0)
        dest = {"1": "out", "2": "err"}             # fd table, applied left to right like bash
        files = {}                                  # target path → (append?) for the session file store
        for fd, op, tgt in redirs:
            if op == ">&" and tgt in ("1", "2"):
                dest[fd] = dest[tgt]
            elif op in (">", ">>", ">&"):
                p = posixpath.normpath(posixpath.join(self.cwd, (tgt or "").replace("~", self.home, 1)))
                key = "null" if (op == ">&" or p.startswith("/dev/")) else "f:" + p
                if key != "null":
                    files[key] = op == ">>"
                for f in (("1", "2") if fd == "&" or op == ">&" else (fd,)):
                    dest[f] = key
        res = {"out": "", "err": "", "null": ""}
        res.update({k: "" for k in files})
        res[dest.get("1", "out")] += o
        res[dest.get("2", "err")] += e
        for k, app in files.items():                # `echo x > /tmp/f && cat /tmp/f` must work within the session
            p = k[2:]
            if p in self.vfs or (len(self.vfs) < 50 and sum(map(len, self.vfs.values())) < 65536):
                self.vfs[p] = ((self.vfs.get(p, "") if app else "") + res[k])[-65536:]
        return res["out"], res["err"], rc

    # ---------------------------------------------------------------------------------- commands
    def _one(self, argv, stdin=None):
        c, a = argv[0], argv[1:]
        os_ = self.ctx.os
        ubuntu = "Ubuntu" in os_
        if c in ("whoami",):
            return self.user + "\n"
        if c == "id":
            if a and a[0] in ("-u", "-g"):
                return "1001\n"
            if a and a[0] in ("-un", "-nu", "-gn", "-ng"):
                return self.user + "\n"
            return f"uid=1001({self.user}) gid=1001({self.user}) groups=1001({self.user}),33(www-data)\n"
        if c == "hostname":
            return self.host + "\n"
        if c == "pwd":
            return self.cwd + "\n"
        if c in ("true", ":"):
            return "", "", 0
        if c == "false":
            return "", "", 1
        if c == "uname":
            k = "5.15.0-126-generic" if ubuntu else "6.1.0-27-amd64"
            if "-a" in a:
                return f"Linux {self.host} {k} #136-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n" if ubuntu else \
                    f"Linux {self.host} {k} #1 SMP PREEMPT_DYNAMIC Debian 6.1.115-1 x86_64 GNU/Linux\n"
            if "-r" in a:
                return k + "\n"
            return "Linux\n"
        if c == "cat" and a and a[0] in ("/etc/os-release", "/etc/issue"):
            return f'PRETTY_NAME="{os_}"\nNAME="{os_.split()[0]}"\n'
        if c == "cd":
            target = a[0] if a else self.home
            if target == "-":
                target = self.env.get("OLDPWD", self.cwd)
            target = target.replace("~", self.home, 1)
            real, p = self._real(target)
            if real and os.path.isdir(real) or p in ("/", "/tmp", "/var", "/var/www", "/etc", "/home", "/srv"):
                self.env["OLDPWD"], self.cwd = self.cwd, p
                return ""
            return "", f"-bash: cd: {target}: No such file or directory\n", 1
        if c in ("ls", "ll", "dir"):
            targets = [x for x in a if not x.startswith("-")] or ["."]
            outs, errs, rc = [], [], 0
            for target in targets:
                o, e = self._ls(c, a, target, len(targets) > 1)
                outs.append(o)
                errs.append(e)
                rc = 2 if e else rc
            return "\n".join(x for x in outs if x), "".join(errs), rc
        if c in ("cat", "head", "tail", "less", "more"):
            outs, errs, n, files = [], [], 10, []
            it = iter(a)
            for x in it:                                   # head -2 / head -n 2 / tail -n2
                if x == "-n":
                    x = "-" + next(it, "10")
                if x.startswith("-n"):
                    x = "-" + x[2:]
                if x.startswith("-") and x[1:].isdigit():
                    n = int(x[1:])
                elif not x.startswith("-") or x == "-":
                    files.append(x)
            cut = lambda text: text if c not in ("head", "tail") else "".join(
                (lambda ls: ls[:n] if c == "head" else (ls[-n:] if n else []))(text.splitlines(True)))
            if not files:
                return cut(stdin or "")
            for f in files:
                if f == "-":
                    outs.append(cut(stdin or ""))
                    continue
                real, p = self._real(f.replace("~", self.home, 1))
                if p in self.vfs:                          # written earlier in this session
                    outs.append(cut(self.vfs[p]))
                elif real and os.path.isfile(real):
                    self.ctx.emit("file.read", self.addr, self.port, "ssh", self.session, path=p, username=self.user)
                    outs.append(cut(open(real, "r", errors="replace").read()))
                elif real and os.path.isdir(real):
                    errs.append(f"{c}: {f}: Is a directory\n")
                elif p == "/etc/passwd":
                    outs.append(cut("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                                    f"{self.user}:x:1001:1001::{self.home}:/bin/bash\n"))
                elif p == "/etc/hostname":
                    outs.append(self.host + "\n")
                elif p == "/etc/shadow":
                    errs.append(f"{c}: /etc/shadow: Permission denied\n")
                else:
                    errs.append(f"{c}: {f}: No such file or directory\n")
            return "".join(outs), "".join(errs), 1 if errs else 0
        if c == "grep":
            return self._grep(a, stdin)
        if c == "wc":
            return self._wc(a, stdin)
        if c in ("sort", "uniq"):
            lines = (stdin or "").splitlines()
            if c == "sort":
                lines = sorted(lines, reverse="-r" in a)
            else:
                lines = [x for i, x in enumerate(lines) if i == 0 or x != lines[i - 1]]
            return "".join(x + "\n" for x in lines)
        if c in ("env", "printenv"):
            if c == "printenv" and a:
                v = [self._var(x) for x in a if x in self.env or x == "PWD"]
                return "".join(x + "\n" for x in v), "", 0 if v else 1
            return "".join(f"{k}={self._var(k)}\n" for k in self.env)
        if c == "export":
            for x in a:
                k, eq, v = x.partition("=")
                if eq and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                    self.env[k] = v
            return ""
        if c == "unset":
            for x in a:
                if x not in ("HOME", "USER", "PATH"):
                    self.env.pop(x, None)
            return ""
        if c in ("ifconfig", "ip"):
            ip = self.ctx.em.sensor_ip
            return (f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
                    f"    inet {ip}/24 brd {'.'.join(ip.split('.')[:3])}.255 scope global eth0\n")
        if c == "ps":
            return self._ps(a)
        if c in ("w", "who", "uptime"):
            return self._uptime()
        if c in ("sudo",):
            return "", f"[sudo] password for {self.user}: \nSorry, user {self.user} may not run sudo on {self.host}.\n", 1
        if c in ("wget", "curl"):
            return self._fetch(c, a, argv)
        if c == "du":
            return self._du(a)
        if c in ("echo",):
            nl = "\n"
            while a and a[0] in ("-n", "-e", "-ne", "-en"):
                nl = "" if "n" in a[0] else nl
                a = a[1:]
            return " ".join(a) + nl
        if c in ("which", "type", "command"):
            known = {"ls", "cat", "id", "ps", "grep", "curl", "wget", "bash", "sh", "python3", "uname", "head", "tail", "wc"}
            names = [x for x in a if not x.startswith("-")]
            return "".join(f"/usr/bin/{x}\n" for x in names if x in known), "", 0 if all(x in known for x in names) else 1
        if c in ("exit", "logout"):
            return "\x04"
        if c in ("history", "clear", "unalias", "alias"):
            return ""
        return "", f"-bash: {c}: command not found\n", 127

    def _ls(self, c, a, target, header):
        real, p = self._real(target.replace("~", self.home, 1))
        head = f"{target}:\n" if header else ""
        if real and os.path.isdir(real):
            names = sorted(os.listdir(real))
            if not any(x.startswith("-") and "a" in x for x in a):
                names = [n for n in names if not n.startswith(".")]
            if c == "ll" or any(x.startswith("-") and "l" in x for x in a):
                lines = []
                for n in names:
                    st = os.stat(os.path.join(real, n))
                    d = os.path.isdir(os.path.join(real, n))
                    lines.append(f"{'drwxr-xr-x' if d else '-rw-r--r--'} 1 {self.user} {self.user} {st.st_size:>6} "
                                 f"{time.strftime('%b %d %H:%M', time.localtime(st.st_mtime))} {n}")
                return head + f"total {len(lines) * 4}\n" + "\n".join(lines) + ("\n" if lines else ""), ""
            return head + "  ".join(names) + ("\n" if names else ""), ""
        if real and os.path.isfile(real):
            return target + "\n", ""
        if p == "/":
            return head + "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n", ""
        if p == "/home":
            d = safe_join(self.home_root, "home")
            return (head + "  ".join(sorted(os.listdir(d))) + "\n" if d and os.path.isdir(d) else ""), ""
        if p == "/srv":
            return head + ("ftp\n" if os.path.isdir(os.path.join(self.home_root, "ftp")) else ""), ""
        if p in ("/tmp", "/var/www", "/var"):
            return head, ""
        return "", f"{'ls' if c != 'dir' else 'dir'}: cannot access '{target}': No such file or directory\n"

    def _grep(self, a, stdin):
        flags, pat, files, it = set(), None, [], iter(a)
        for x in it:
            if x in ("-e", "--regexp"):
                pat = next(it, "")
            elif x.startswith("-") and len(x) > 1 and pat is None:
                flags.update(x[1:])
            elif pat is None:
                pat = x
            else:
                files.append(x)
        if pat is None:
            return "", "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", 2
        try:
            rx = re.compile(pat[:200], re.I if "i" in flags else 0)
        except re.error:
            rx = re.compile(re.escape(pat[:200]), re.I if "i" in flags else 0)
        srcs, errs = [], ""
        if not files:
            srcs.append(("", stdin or ""))
        for f in files:
            real, p = self._real(f.replace("~", self.home, 1))
            if real and os.path.isfile(real):
                self.ctx.emit("file.read", self.addr, self.port, "ssh", self.session, path=p, username=self.user)
                srcs.append((f, open(real, "r", errors="replace").read()))
            else:
                errs += f"grep: {f}: No such file or directory\n"
        out, hits = [], 0
        for name, text in srcs:
            k = 0
            for i, line in enumerate(text.splitlines(), 1):
                if bool(rx.search(line)) != ("v" in flags):
                    k += 1
                    if "c" not in flags and "l" not in flags:
                        out.append((f"{name}:" if len(files) > 1 else "") + (f"{i}:" if "n" in flags else "") + line + "\n")
            if "c" in flags:
                out.append((f"{name}:" if len(files) > 1 else "") + f"{k}\n")
            elif "l" in flags and k:
                out.append(f"{name or '(standard input)'}\n")
            hits += k
        return "".join(out), errs, 0 if hits else (2 if errs else 1)

    def _wc(self, a, stdin):
        flags = "".join(x[1:] for x in a if x.startswith("-")) or "lwc"
        files = [x for x in a if not x.startswith("-")]
        srcs = [("", stdin or "")] if not files else []
        for f in files:
            real, _ = self._real(f.replace("~", self.home, 1))
            if real and os.path.isfile(real):
                srcs.append((f, open(real, "r", errors="replace").read()))
            else:
                return "", f"wc: {f}: No such file or directory\n", 1
        out = []
        for name, t in srcs:
            nums = [n for k, n in (("l", t.count("\n")), ("w", len(t.split())), ("c", len(t.encode()))) if k in flags]
            w = 1 if len(nums) == 1 and not name else 7
            out.append(" ".join(f"{n:>{w}}" for n in nums) + (f" {name}" if name else "") + "\n")
        return "".join(out)

    def _boot(self):
        bt = getattr(self.ctx, "boot_time", None)
        return bt() if callable(bt) else time.time() - 41 * 86400 - 3 * 3600

    def _uptime(self):
        up = int(time.time() - self._boot())
        d, h, m = up // 86400, up % 86400 // 3600, up % 3600 // 60
        return f" {time.strftime('%H:%M:%S')} up {d} days, {h:2d}:{m:02d},  1 user,  load average: 0.08, 0.05, 0.01\n"

    def _ps(self, a):
        role = str((getattr(self.ctx, "role", None) or {}).get("id", ""))
        boot = self._boot()
        start = time.strftime("%b%d", time.localtime(boot))
        procs = [("root", 1, "/sbin/init"), ("root", 412, "/lib/systemd/systemd-journald"),
                 ("systemd+", 598, "/lib/systemd/systemd-resolved"), ("root", 612, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
                 ("root", 640, "/usr/sbin/cron -f"), ("syslog", 655, "/usr/sbin/rsyslogd -n -iNONE")]
        if "web" in role:
            procs += [("root", 844, "/usr/sbin/apache2 -k start"), ("www-data", 851, "/usr/sbin/apache2 -k start"),
                      ("mysql", 902, "/usr/sbin/mysqld")]
        if "ftp" in role or "backup" in role:
            procs += [("root", 731, "/usr/sbin/vsftpd /etc/vsftpd.conf")]
        if "dns" in role:
            procs += [("bind", 760, "/usr/sbin/named -f -u bind")]
        procs += [("root", 1288, f"sshd: {self.user} [priv]"), (self.user, 1289, f"sshd: {self.user}@pts/0"),
                  (self.user, 1290, "-bash"), (self.user, 1342, "ps " + " ".join(a))]
        mine = lambda u: u == self.user
        if any("a" in x or "e" in x for x in a):
            if any("u" in x for x in a):
                out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
                for u, pid, cmd in procs:
                    tty = "pts/0" if mine(u) else "?"
                    st = time.strftime("%H:%M") if mine(u) else start
                    out.append(f"{u:<8} {pid:>7}  0.0  {0.1 if pid < 1000 else 0.0:.1f} {pid * 97 % 200000 + 5000:>6} "
                               f"{pid * 31 % 20000 + 1200:>5} {tty:<8} {'Ss' if pid < 1000 else 'S'}    {st:<5}   0:00 {cmd}")
                return "\n".join(out) + "\n"
            out = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
            for u, pid, cmd in procs:
                out.append(f"{u:<8} {pid:>8} {1 if pid > 1 else 0:>7}  0 {start if not mine(u) else time.strftime('%H:%M'):<5} "
                           f"{'pts/0' if mine(u) else '?':<12} 00:00:00 {cmd}")
            return "\n".join(out) + "\n"
        return ("    PID TTY          TIME CMD\n   1290 pts/0    00:00:00 bash\n"
                f"   1342 pts/0    00:00:00 ps\n")

    def _fetch(self, c, a, argv):
        """wget/curl: URL recorded (ssh.download), never fetched. A literal IP fails to connect after a short
        delay (egress filtered), a host name does not resolve (no DNS for the decoy) — as a locked-down server."""
        import ipaddress
        from urllib.parse import urlsplit
        cmd = " ".join(argv)
        urls = [x for x in a if re.match(r"(https?|ftp)://", x)] or [x for x in a if not x.startswith("-") and "." in x][:1]
        self.ctx.emit("ssh.download", self.addr, self.port, "ssh", self.session, urls=urls, cmd=cmd[:500])
        if not urls:
            return "", (f"{c}: missing URL\n" if c == "wget" else "curl: try 'curl --help' for more information\n"), 2
        u = urls[0] if "://" in urls[0] else "http://" + urls[0]
        sp = urlsplit(u)
        host = sp.hostname or ""
        port = sp.port or {"https": 443, "ftp": 21}.get(sp.scheme, 80)
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        silent = c == "curl" and any(x.startswith("-") and not x.startswith("--") and "s" in x and "S" not in x for x in a)
        if literal:
            time.sleep(self.NET_DELAY)
            ms = int(self.NET_DELAY * 1000) + 3
            if c == "curl":
                return "", "" if silent else f"curl: (7) Failed to connect to {host} port {port} after {ms} ms: Couldn't connect to server\n", 7
            return "", (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {u}\nConnecting to {host}:{port}... "
                        "failed: Connection timed out.\nRetrying.\n\n"), 4
        if c == "curl":
            return "", "" if silent else f"curl: (6) Could not resolve host: {host}\n", 6
        return "", (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {u}\nResolving {host} ({host})... failed: "
                    f"Temporary failure in name resolution.\nwget: unable to resolve host address ‘{host}’\n"), 4

    def _du(self, a):
        targets = [x for x in a if not x.startswith("-")] or ["."]
        h = any("h" in x for x in a if x.startswith("-"))
        out, err = [], ""
        for t in targets:
            real, p = self._real(t.replace("~", self.home, 1))
            if not real or not os.path.exists(real):
                err += f"du: cannot access '{t}': No such file or directory\n"
                continue
            size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(real) for f in fs) if os.path.isdir(real) \
                else os.path.getsize(real)
            kb = max(4, (size + 1023) // 1024)
            out.append(f"{(str(kb) + 'K') if h and kb < 1024 else (f'{kb / 1024:.1f}M' if h else kb)}\t{t}\n")
        return "".join(out), err, 1 if err else 0



ACCEPT_WAIT = 60   # seconds to wait for another channel; an open shell keeps the connection regardless

def _host_keys(ctx):
    """Persistent per-decoy host keys of every type a stock Ubuntu/Debian sshd has."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec
    keys = []
    rsa_f = os.path.join(ctx.data_dir, f"ssh_host_rsa_{ctx.name}")
    if not os.path.exists(rsa_f):
        paramiko.RSAKey.generate(3072).write_private_key_file(rsa_f)
    for kind, gen, cls in (("ed25519", ed25519.Ed25519PrivateKey.generate, paramiko.Ed25519Key),
                           ("ecdsa", lambda: ec.generate_private_key(ec.SECP256R1()), paramiko.ECDSAKey)):
        f = os.path.join(ctx.data_dir, f"ssh_host_{kind}_{ctx.name}")
        if not os.path.exists(f):
            pem = gen().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                      serialization.NoEncryption())
            with open(f, "wb") as fh:
                fh.write(pem)
            os.chmod(f, 0o600)
        try:
            keys.append(cls(filename=f))
        except Exception:
            pass
    keys.append(paramiko.RSAKey(filename=rsa_f))
    return keys


def start_ssh(ctx, svc):
    port = svc["port"]
    banner = svc.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
    hostkeys = _host_keys(ctx)

    def h(conn, addr, session):
        t = paramiko.Transport(conn)
        t.local_version = banner
        for k in hostkeys:            # like a real OpenSSH: ed25519 + ecdsa + rsa
            t.add_server_key(k)
        srv = _Server(ctx, addr, port, session)
        try:
            t.start_server(server=srv)
        except Exception:
            ctx.emit("proto.interaction", addr, port, "ssh", session, detail="handshake-failed")
            return
        ctx.emit("ssh.client", addr, port, "ssh", session, client_version=(t.remote_version or "")[:120])
        sh = None
        workers = []
        while t.is_active():
            chan = t.accept(ACCEPT_WAIT)
            if chan is None:
                workers = [x for x in workers if x.is_alive()]
                if workers:                            # an open shell/exec channel keeps the connection up
                    continue
                break
            if sh is None:
                sh = FakeShell(ctx, srv.user or "user", ctx.bait_dir, addr, port, session)
            w = threading.Thread(target=channel, args=(chan, srv, sh, addr, session), daemon=True)
            try:
                w.start()
            except RuntimeError:                       # out of threads: drop this channel, keep the connection
                srv.release(chan.get_id())
                chan.close()
                continue
            workers = [x for x in workers if x.is_alive()] + [w]
        for w in workers:
            w.join(1)
        t.close()
        srv.release_all()                              # channels paramiko opened that never reached accept()

    def channel(chan, srv, sh, addr, session):
        r = srv._r(chan)
        end = time.monotonic() + 10                    # shell / exec request; a closed channel frees its slot at once
        while not r["event"].wait(0.2) and time.monotonic() < end and not chan.closed and srv_active(chan):
            pass
        try:
            if r["exec"] is not None:
                ctx.emit("cmd.exec", addr, port, "ssh", session, cmd=r["exec"], username=srv.user)
                chan.sendall(sh.run(r["exec"]).replace("\x04", "").replace("\n", "\r\n"))
                chan.send_exit_status(0)
                return
            motd = f"{ctx.os} (GNU/Linux 5.15.0-126-generic x86_64)" if "Ubuntu" in ctx.os else ctx.os
            chan.sendall(f"Welcome to {motd}\r\n\r\nLast login: {time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(time.time() - 86400 * 3))} from 10.0.1.15\r\n")
            buf = ""
            chan.sendall(sh.prompt())
            chan.settimeout(300)
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                for ch in data.decode("utf-8", "replace"):
                    if ch in ("\r", "\n"):
                        chan.sendall("\r\n")
                        line = buf.strip()
                        buf = ""
                        if line:
                            ctx.emit("cmd.exec", addr, port, "ssh", session, cmd=line[:2000], username=srv.user)
                            out = sh.run(line)
                            if "\x04" in out:                 # `cmd1; cmd2; exit` → outputs, then logout
                                chan.sendall(out.split("\x04", 1)[0].replace("\n", "\r\n") + "logout\r\n")
                                return
                            chan.sendall(out.replace("\n", "\r\n"))
                        chan.sendall(sh.prompt())
                    elif ch in ("\x7f", "\x08"):
                        if buf:
                            buf = buf[:-1]
                            chan.sendall("\b \b")
                    elif ch == "\x03":
                        buf = ""
                        chan.sendall("^C\r\n" + sh.prompt())
                    elif ch == "\x04":
                        return
                    elif ch >= " " or ch == "\t":
                        buf += ch
                        chan.sendall(ch)
                        if len(buf) > 4096:
                            buf = buf[:4096]
        except Exception:
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass
            srv.release(chan.get_id())

    def srv_active(chan):
        t = chan.get_transport()
        return t is not None and t.is_active()

    serve_tcp(ctx, port, h, "ssh")
