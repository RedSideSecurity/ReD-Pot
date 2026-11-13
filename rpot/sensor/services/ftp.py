"""FTP emulator (vsftpd-like). Read-only bait tree, uploads stored inert for analysis.

Events: proto.interaction (2: client spoke FTP), auth.failed (3), honeytoken.used (5),
auth.success (4), ftp.list (3), file.read (4: RETR), file.write (4: STOR, stored 0400 + sha256;
dropped=<reason> when over the per-sensor upload quota shared with SMB — see base.UploadStore).
"""
import os
import random
import socket
import time

from rpot.sensor.base import UploadStore, serve_tcp, safe_join, bind_ip


def start_ftp(ctx, svc):
    port = svc["port"]
    banner = svc.get("banner", "220 (vsFTPd 3.0.3)")
    root = os.path.join(ctx.bait_dir, "ftp")
    pasv_lo, pasv_hi = svc.get("pasv_range", [30000, 30049])
    store = UploadStore.of(ctx.data_dir)

    def h(conn, addr, session):
        f = conn.makefile("rb")
        send = lambda s: conn.sendall((s + "\r\n").encode())
        send(banner)
        user, authed, cwd, pasv, spoke = None, False, "/", None, False
        tries = 0
        while True:
            line = f.readline(1024)
            if not line:
                break
            line = line.decode("latin-1", "replace").strip()
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if not spoke:
                spoke = True
                ctx.emit("proto.interaction", addr, port, "ftp", session, detail="ftp-command", first=cmd)
            if cmd == "USER":
                user = arg[:64]
                send("331 Please specify the password.")
            elif cmd == "PASS":
                if user and user.lower() in ("anonymous", "ftp"):
                    ctx.emit("auth.failed", addr, port, "ftp", session, username=user, anonymous=True)
                    time.sleep(1)
                    send("530 Login incorrect.")
                elif ctx.check_cred(user, arg, "ftp", addr, port, session):
                    authed = True
                    send("230 Login successful.")
                else:
                    tries += 1
                    time.sleep(1)
                    send("530 Login incorrect.")
                    if tries >= 3:
                        break
            elif cmd in ("QUIT", "BYE"):
                send("221 Goodbye.")
                break
            elif cmd == "SYST":
                send("215 UNIX Type: L8")
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            elif cmd in ("OPTS", "TYPE", "MODE", "STRU"):
                send("200 Switching to Binary mode." if cmd == "TYPE" else "200 OK.")
            elif cmd == "NOOP":
                send("200 NOOP ok.")
            elif not authed:
                send("530 Please login with USER and PASS.")
            elif cmd in ("PWD", "XPWD"):
                send(f'257 "{cwd}" is the current directory')
            elif cmd in ("CWD", "XCWD", "CDUP"):
                new = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/" if cmd == "CDUP" else _norm(cwd, arg)
                p = safe_join(root, new)
                if p and os.path.isdir(p):
                    cwd = new
                    send("250 Directory successfully changed.")
                else:
                    send("550 Failed to change directory.")
            elif cmd in ("PASV", "EPSV"):
                if pasv:
                    pasv.close()
                pasv = socket.socket()
                pasv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                pp = None
                for _ in range(20):
                    cand = random.randint(pasv_lo, pasv_hi)
                    try:
                        pasv.bind((bind_ip(), cand))
                        pp = cand
                        break
                    except OSError:
                        continue
                if pp is None:
                    pasv.close(); pasv = None
                    send("425 Can't open data connection.")
                    continue
                pasv.listen(1)
                pasv.settimeout(20)
                if cmd == "EPSV":
                    send(f"229 Entering Extended Passive Mode (|||{pp}|)")
                else:
                    ip = ctx.em.sensor_ip.replace(".", ",")
                    send(f"227 Entering Passive Mode ({ip},{pp >> 8},{pp & 255}).")
            elif cmd in ("LIST", "NLST", "MLSD"):
                target = _norm(cwd, next((x for x in arg.split() if not x.startswith("-")), "")) if arg else cwd
                p = safe_join(root, target)
                if not pasv:
                    send("425 Use PORT or PASV first.")
                    continue
                if not p or not os.path.isdir(p):
                    send("550 Failed to open directory.")
                    continue
                ctx.emit("ftp.list", addr, port, "ftp", session, path=target, username=user)
                send("150 Here comes the directory listing.")
                data = _listing(p, cmd).encode()
                _xfer_send(pasv, data, addr[0])
                pasv = None
                send("226 Directory send OK.")
            elif cmd == "SIZE":
                p = safe_join(root, _norm(cwd, arg))
                send(f"213 {os.path.getsize(p)}" if p and os.path.isfile(p) else "550 Could not get file size.")
            elif cmd == "RETR":
                target = _norm(cwd, arg)
                p = safe_join(root, target)
                if not p or not os.path.isfile(p) or not pasv:
                    send("550 Failed to open file.")
                    continue
                data = open(p, "rb").read()
                ctx.emit("file.read", addr, port, "ftp", session, path=target, bytes=len(data), username=user)
                send(f"150 Opening BINARY mode data connection for {os.path.basename(p)} ({len(data)} bytes).")
                _xfer_send(pasv, data, addr[0])
                pasv = None
                send("226 Transfer complete.")
            elif cmd in ("STOR", "APPE", "STOU"):
                if not pasv:
                    send("425 Use PORT or PASV first.")
                    continue
                send("150 Ok to send data.")
                blob = _xfer_recv(pasv, addr[0], store.max_file + 1)
                pasv = None
                res = store.put(blob)
                ctx.emit("file.write", addr, port, "ftp", session, path=_norm(cwd, arg), bytes=len(blob),
                         sha256=res["sha256"], stored=res["stored"], dropped=res["dropped"], username=user)
                send("226 Transfer complete." if res["stored"] else "451 Failure writing to local file.")
            elif cmd in ("DELE", "RMD", "MKD", "RNFR", "RNTO", "SITE", "CHMOD"):
                ctx.emit("file.write", addr, port, "ftp", session, path=_norm(cwd, arg), op=cmd, username=user)
                send("550 Permission denied.")
            elif cmd in ("PORT", "EPRT"):
                send("500 Illegal PORT command.")
            else:
                send("500 Unknown command.")
        if pasv:
            pasv.close()

    serve_tcp(ctx, port, h, "ftp")


def _norm(cwd, arg):
    import posixpath
    p = posixpath.normpath(posixpath.join(cwd, arg or "."))
    return "/" if p in (".", "") else p


def _listing(p, cmd):
    out = []
    for n in sorted(os.listdir(p)):
        fp = os.path.join(p, n)
        st = os.stat(fp)
        if cmd == "NLST":
            out.append(n)
        else:
            d = os.path.isdir(fp)
            out.append(f"{'drwxr-xr-x' if d else '-rw-r--r--'}    1 1001     1001     {st.st_size:>8} "
                       f"{time.strftime('%b %d %H:%M', time.localtime(st.st_mtime))} {n}")
    return "\r\n".join(out) + "\r\n"


def _accept_peer(pasv, peer):
    """Accept the data connection only from the client that opened the control connection."""
    while True:
        c, a = pasv.accept()
        if a[0] == peer:
            return c
        c.close()


def _xfer_send(pasv, data, peer):
    try:
        c = _accept_peer(pasv, peer)
        c.sendall(data)
        c.close()
    except Exception:
        pass
    finally:
        pasv.close()


def _xfer_recv(pasv, peer, limit):
    buf = b""
    try:
        c = _accept_peer(pasv, peer)
        c.settimeout(30)
        while len(buf) < limit:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        c.close()
    except Exception:
        pass
    finally:
        pasv.close()
    return buf
