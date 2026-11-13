# Changelog

## 1.0.0 — Community Edition — 2026-11-13

First release of **ReD-Pot Community Edition** (MIT), built from v0.4.0. It keeps every decoy role, the baits and
honeytokens, scoring, the dashboard and remote sensors, and sets the Community Edition limits: at most 3 decoys, one
decoy per network interface on that interface's own IP, a fixed persona and bait set, no outbound alerting and no
offline replay. See "Community Edition limits" in the README.

**Upgrading:** fresh installs only. Uninstall v0.3.x / v0.4.x (`sudo ./install.sh uninstall`), then install 1.0.0
(new persona, baits and admin token; remote sensors join again). Commands that change an existing install refuse a
configuration made by an older version.

### Added
- **Export:** *Incidents → Export JSON* downloads incidents and alert records for a date range (whole UTC days, *To*
  included, at most 366 days) as one JSON file with a `"complete": true` marker. Admin sessions only; one export at a
  time; larger than 200 MB is refused with the counts instead of being cut off.
  The same from the command line: `sudo ./install.sh export --from D --to D
  [-o FILE] [--force]` (file mode 0600, never follows symlinks, `--force` replaces only a regular file), and inside the
  console container `rpotctl export` (JSON on stdout) and `rpotctl slots` (decoy slot counts).
- **Decoy limit** (3 decoys: local decoys + remote sensors + pending joins), enforced by the installer, `rpotctl`,
  enrollment, the database and the sensor API. The dashboard shows "n of 3 decoys", disables *Add a sensor* when full
  and explains why; pending joins can be **cancelled**, which frees the slot at once. Revoking a remote sensor frees its
  slot; a local decoy frees its slot only with `install.sh remove-decoy`. A full manager answers a valid join with
  "decoy limit reached" and the token stays unused.
- Edition label in the dashboard header; `edition` in `/api/summary`, slot counts in `/api/fleet`.
- `sensor.gap` note: after an outage a remote sensor reports how many events it could not deliver (count and first/last
  timestamp only), shown on that decoy's incident.
- Alert records are stored in the database (`alert_records`) as the source for Export, whether or not `alerts.json`
  is enabled. They follow the event retention.
- `tests/lab_scenarios.sh setup|attack|all|down` builds a 3-decoy bridge lab (FS01, DC01, WEB01) and runs the simulated
  workstations; `DRY_RUN=1` prints the commands.
- **Release pipeline (GitHub Actions):** CI on every push and pull request (tests on Python 3.12/3.13, CE gate, shell
  syntax, dependency audit). A version tag builds the image for linux/amd64 and linux/arm64, publishes
  `ghcr.io/redsidesecurity/red-pot:<version>` with provenance and SBOM, checks the pushed image's source-hash label
  against the installer's `src_hash()`, then creates the GitHub Release from this changelog.

### Changed
- SSH decoy: an open interactive shell is no longer closed when no further channel is opened within 60 s.
- **Connection floods (pentest F-02):** one decoy-wide connection budget for every TCP service, SMB and HTTP included
  (250 concurrent, 20 per source IP, thread ceiling 320 under the container's 384); SMB sessions without a named logon
  idle out after 60 s. A listener no longer dies when the decoy runs out of threads: that client is dropped and the
  listener keeps serving. Sources that hit a cap raise a level-3 `conn.flood` event (once a minute per source).
- **SMB named-pipe flood (pentest N-3):** SMB named pipes (`\srvsvc`, `\wkssvc`) no longer start a thread each; RPC
  requests are answered in the SMB session's own thread. Every open pipe is charged to the decoy's connection budget:
  at most 8 per SMB session, 16 per source IP, 128 per decoy, and none once the decoy is within 32 threads of its
  thread ceiling (a pipe is refused before a new client is). A refused open gets `STATUS_INSUFFICIENT_RESOURCES`; the
  session keeps working. Idle pipes close after 60 s (null session) or 300 s (named logon), and all of a session's
  pipes close with the session. The SSH decoy allows 10 channels per connection (OpenSSH `MaxSessions`), charged the
  same way.
- **Resource-exhaustion detection:** a source that hits its own pipe cap raises `smb.pipe_flood` (level 4); its own
  SSH channel cap, or holding all its connection slots while the decoy is full, raises `resource.exhaustion` (level 4).
  When the decoy-wide thread or connection cap refuses a client, the manager opens or raises a level-4 decoy incident
  "Decoy NAME saturated - possible DoS". That incident names the top holders (source IPs and their counts), not the
  refused client, and always writes an alert record when it opens or rises (otherwise at most one per decoy per 5 min).
  Flood events now carry the total refused since the flood started (`refused`), the count since the last report
  (`new`) and `duration_s`. The first refusal is reported at once and a summary follows within 60 s.
- **Decoy service health:** every 30 s each decoy checks its listeners; a dead or unbound one is restarted and reported
  (`sensor.service_down` / `sensor.service_up`). The manager opens a level-4 "service down - possible DoS" incident on
  that decoy and `/api/sensors` shows `services_down` and per-service health; the dashboard marks a down service in red.
- **Persona:** the installer asks only the AD/DNS domain and the industry. Company name, NetBIOS name and mail domain
  are derived from the domain and shown on the review screen. Users come from a larger built-in name pool (70 first
  names × 72 last names), 14 picked per install by a random seed, which also picks the username format. Internationalised
  (`xn--`) domain labels are refused with a hint. `--domain` is required with `--yes` (no default domain).
  The NetBIOS name is the first domain label without hyphens (`corp.ararat-bank.am` → `ARARATBANK`); when that is
  longer than 15 characters, its first word (`northwind-traders-intl.com` → `NORTHWIND`). Before: `ARARAT-BANK`,
  or a 15-character cut such as `REDSIDE-SECURIT` (pentest F-04).
- **Fewer honeypot tells** (pentest F-04, F-05):
  - Bait files are dated per file at office-hours times with their own minutes and seconds (before, every file carried
    the install time's seconds). `.docx` baits have Word-like metadata: author and editor from the staff list, created
    and modified dates matching the file date, `app.xml`, and ZIP entries dated like Word's (no install time).
  - The DC's LDAP directory looks like a real Server 2019 domain: about 125 objects, including the default containers,
    `CN=Builtin` with the builtin groups, the default domain groups, the Default Domain (Controllers) Policy GPOs,
    a company OU tree with department OUs and groups, and one workstation per employee (also known to the KDC).
    Every `memberOf` points to an existing object, `member` matches it, and the primary group is not listed.
  - A null session can no longer list shares (Server 2019 default). Logged-on bait users still can.
  - The NetBIOS node-status reply carries the decoy interface's real MAC address instead of a made-up one.
- **One decoy per interface:** each decoy answers on its interface's own IP; the address question is gone. The
  installer offers each interface once and allows at most min(3, usable interfaces) decoys. A 1-NIC server holds one
  local decoy, which shares the management IP (host SSH moves to a random port). `--no-ssh-move` with a decoy on the
  management interface is an error. Interfaces with unusual names are listed as *Not usable*.
- `add-decoy` offers only interfaces without a decoy, checks the decoy count with the running manager first, and needs
  the manager to be running.
- Remote sensor install: no placement or address question; the decoy answers on the IP of the chosen decoy interface.
  On the manager-link interface host SSH moves (and the decoy follows DHCP there); on another interface the decoy binds
  that IP and host SSH is pinned to the manager-link IP. The decoy-interface firewall policy applies on sensors too.
- **Manager unreachable:** a sensor retries the batch in flight in memory for up to 60 s; after that, events go only to
  a write-only local log `undelivered-<NAME>.jsonl` on the sensor (mode 0600, `RPOT_UNDELIVERED_MAX_MB`, default 50) and
  are never sent later.
- Sensor timestamps older than 15 minutes (was 7 days) or more than 5 minutes in the future are replaced by the
  manager's time; the original is kept as `data.sensor_ts`, and the manager log warns once per sensor about clock skew.
- `rpot.json` format version 2. `alerts` keeps only `min_level` (the `alerts.json` threshold).
- `rpotctl init` takes `--domain` (required) and `--profile`; `--net-mode` is `host` (production,
  `--sensor NAME=role@IP%IFACE`) or `bridge` (isolated lab). At most 3 `--sensor` entries.
- The version (1.0.0) has a single source, `rpot/__init__.py`; the installer, `rpotctl` and the image tag read it.
- **DC DNS fingerprint:** the domain controller decoy's DNS now answers like a default Windows Server DNS: CHAOS
  queries (`version.bind`) get NOTIMP with no version, other answers have RA set (header bit only; the decoy still
  never recurses), and non-QUERY opcodes (DNS STATUS) get a 12-byte NOTIMP. `nmap -sV` reported it as
  "NLnet Labs NSD"; it now reports "Simple DNS Plus" (OS: Windows), as it does for most real domain controllers.
- **DNS zone apex:** the DC and Linux DNS decoys answered NXDOMAIN for the domain itself (SOA, NS, A) and for
  `_msdcs` / `_tcp` while names below them resolved, and negative answers had no SOA. The DC now serves the domain
  zone and an `_msdcs` zone with Windows defaults (SOA primary = the DC, `hostmaster.<domain>`, 900/600/86400/3600),
  NS and apex A = the DC, the Net Logon records (site, `pdc`/`gc`, DC and domain GUID records, `DomainDnsZones` /
  `ForestDnsZones`). The Linux DNS role gets a BIND-style SOA and NS. Empty names such as `_tcp` answer NOERROR with
  no data, NXDOMAIN/NODATA carry the SOA, zone transfers stay refused, and nothing is resolved outside the zone.
- **RDP fingerprint:** the RDP decoy now looks like Windows Server 2019 with Network Level Authentication required.
  TLS is capped at 1.2 (no TLS 1.3) with the Schannel cipher order and 2048-bit DHE. The certificate is a per-install
  self-signed one like the one Remote Desktop creates for itself: CN = host FQDN only, RSA 2048 / SHA-256, a 16-byte
  serial, 6-month validity (re-issued when it expires), EKU Server Authentication and Key Usage Key Encipherment +
  Data Encipherment, and no other extensions. A client that offers only Standard RDP Security or plain TLS gets an
  `RDP_NEG_FAILURE` with `HYBRID_REQUIRED_BY_SERVER` instead of a silent close. RDSTLS and CredSSP with Early User
  Authorization are accepted, and a bare TLS handshake on the RDP port shows the certificate, so `nmap -sC` reports
  `ssl-cert` on 3389 like on a Windows host.
- **LDAPS and HTTPS fingerprint:** the domain controller's LDAPS (636) and the new Global Catalog over SSL port
  (3269) present a certificate issued by a per-install fake enterprise CA named like the Active Directory Certificate
  Services default (`<domain>-<DC name>-CA`, its key stays in the sensor data directory, mode 0600). The certificate
  follows the "Domain Controller" template: CN and DNS name = the DC FQDN plus the DC object GUID, EKU Client +
  Server Authentication, template name `DomainController`, LDAP CRL and AIA locations, the DC account SID, an AD CS
  style 19-byte serial and a 1-year validity from a backdated issue date. TLS follows Windows Server 2019 (1.0 to 1.2,
  no 1.3, Schannel cipher order). The Linux web decoy's HTTPS now looks like Apache's default SSL site on Ubuntu
  22.04: the "snakeoil" self-signed certificate, TLS 1.2 and 1.3 only, `HIGH:!aNULL` with client cipher order.
- **Web decoy errors look like Apache (pentest N-4):** unusual or malformed requests no longer get Python
  `http.server` pages. Error responses use Apache 2.4.52's error documents, reason phrases and header order
  (`Date`, `Server`, ..., `Content-Type: text/html; charset=iso-8859-1` last) with the `Apache/2.4.52 (Ubuntu) Server
  at <host> Port <port>` footer, where host and port come from the request's Host header. Request handling follows
  Ubuntu's Apache defaults: `TRACE` is 405 (`TraceEnable Off`); an unknown method is 501; `PUT`/`DELETE`/`PROPFIND`
  on a static or missing path is 405; `OPTIONS` on a static or missing path is 200 with `Allow` and no PHP headers;
  PHP pages answer every method except `TRACE`, as mod_php does; a malformed request line, bare-LF line endings,
  HTTP/1.1 without Host, or an invalid Host is 400 and the bad input is not echoed; a request line over 8190
  bytes is 414; oversized or too many header fields are 400 with Apache's note; HTTP/0.9 `GET` gets the body only.
  Keep-alive works as on Ubuntu (5 s, at most 100 requests per connection, `Keep-Alive` only when the client asks).
  Static bait files are served without PHP headers and with `Last-Modified`, `ETag` and `Accept-Ranges`.
  Malformed requests and unusual methods raise `http.scanner`.
- **Port scan detection on small decoys:** a source touching every port of one decoy within 10 minutes (roles with at
  least 3 ports: the 4-port file server, the web role) raises `scan.detected`, besides the existing rule (5 distinct
  decoy ports in 10 minutes). A full scan of the file-server decoy was not detected before. SMB plus RDP from one
  client (3 of the file server's 4 ports) is not a scan.
- Docs: README "Community Edition limits" and ATT&CK coverage; INSTALL §6 is now "alerts.json, events.json and Export";
  the lab guide uses `tests/lab_scenarios.sh`.

### Removed
- Telegram and JSON webhook alerting, the hourly alert cap, the alert delivery log (`alerts` table) and `GET /api/alerts`.
  `rpot.json` keys `alerts.telegram`, `alerts.webhook` and `alerts.public_url`.
- Offline spool replay: events from a manager outage are no longer queued and replayed (`RPOT_SPOOL_MAX_MB` is gone).
- Decoys on extra addresses: macvlan networks, new free IPs, VLAN placement, vendor MAC addresses and the free-IP
  check. Installer flags `--placement`, `--decoy-ips`, `--company`, `--nics`; `rpotctl` flags `--company`, `--netbios`,
  `--email-domain`, `--user-format`, `--macvlan`, `--gateway`, `--host-network`, `--decoy-net`, `--own-ip` and
  `--net-mode macvlan`; `rpot.json` keys `decoy_nets` and `hostnet`.
- `rpotctl persona` and `rpotctl setup`: the persona and the baits cannot be changed after install.
- `--roles all` (5 roles never fit the limit).
- Upgrade code for v0.3 databases and configurations.

### Security
- **SMB `IPC$` is pipe-only** (pentest F-01, critical): before, an anonymous session could list and download the
  decoy's working directory (the ReD-Pot source) through `IPC$`. Now only the `srvsvc`/`wkssvc` pipes open there;
  any other name is "not found", the share root is "access denied" and a listing is refused. `IPC$` is backed by an
  empty directory, `ADMIN$`/`C$` are never mapped to a directory, the decoy process runs from an empty directory,
  and a share table that maps outside the bait tree stops the decoy. Every attempt to use `IPC$`, `ADMIN$` or `C$`
  as a disk is a new level-3 event `smb.admin_share` ("Tried to read admin share …").
- **Decoy interfaces show only the decoy:** on each decoy interface only that decoy's ports answer; every other port
  (IPv6 included) looks closed, and the interface answers ARP only for its own address. This also hides other host
  services on a decoy interface, including the management interface when a decoy shares it. Admin ports (web UI,
  sensor API, host SSH) are accepted only on the management interface.
- When a decoy shares the management interface, the web UI, sensor API and host SSH allow-lists default to the
  admin's own SSH client (`/32`), and `--yes` requires `--allow-ui`, `--allow-sensor` and `--allow-ssh`. An admin
  connected over IPv6 keeps SSH access through a `/128` rule.
- The same for remote sensors: when the decoy is on the interface that reaches the manager, the moved host SSH answers
  only the SSH allow-list (default: your own SSH client) and the current session; `--yes` requires `--allow-ssh`.
  Before, it was open to the whole decoy LAN and `--allow-ssh` was ignored on sensors.
- The sensor join string (a one-time token) is no longer put on any command line during the install: the enrollment
  container receives it in its environment. Give it to the installer by pasting it when asked, on standard input
  (`--join -`) or in a root-only file (`--join-file FILE`, mode 600). `--join 'redpot://…'` still works, but warns that
  local users can read it in the process list while the installer runs. The dashboard's *Add a sensor* now shows the
  command `sudo ./install.sh sensor` and, in its own copy box, the join string to paste; the API's `command` field no
  longer contains the join string.
- When a decoy shares the management interface, the installer first lists the host services that listen there and
  will become unreachable on that interface (for example a VPN server), and asks for confirmation. With `--yes` it stops
  unless `--close-other-services` is given.
- The server does not route for a decoy LAN. Forwarded traffic arriving on a decoy interface is refused, and traffic
  into a Docker network is accepted only for published ports, so a direct route to the console container's address
  (port 8740/8741) cannot bypass the allow-lists.
- The firewall fails closed: `firewall.sh apply` checks that every chain is hooked (iptables, ip6tables while IPv6 is on,
  `DOCKER-USER` or `FORWARD`). If a chain is missing, it exits with an error that names the chain and the rules are
  removed again. With Docker's nftables firewall backend the chain is hooked into `FORWARD` directly. The self-test
  reports whether the firewall is in effect.
  - Install: the installer first checks these prerequisites, before it stops services or moves SSH. If `apply` still
    fails, the installer stops and the decoys are not started. The check tests the egress guard's owner match in a
    temporary chain hooked from `OUTPUT` and the `FORWARD` hook with an empty chain (the kernel accepts the owner match
    only on the output path; mixing both made every install with a decoy fail), and removes its chains again.
  - `add-decoy` / `remove-decoy`: if the new rules fail, the previous rules are put back for the running console and
    decoys and the change is not started; if that fails too, the whole stack is stopped.
  - The `redpot` service first stops its containers, then applies the firewall, then starts them. After an unclean
    shutdown Docker restarts the containers on its own when it starts, so they run without the firewall until the
    service starts (after the network is online); if `apply` fails then, they are stopped and stay stopped.
- The NetBIOS name-service exception of the egress guard allows only small UDP answers from port 137, out of the decoy's
  own interface to a host in that interface's subnet, never to port 53.
- The installer refuses to install when uid 10001 (the containers' user) is used by a host account or host process.
- `add-decoy` next to a running domain controller decoy works: a socket bound to one interface (the DC's NetBIOS socket,
  `0.0.0.0%eth0` in `ss`) counts only for that interface's addresses when the installer checks for busy ports.
- Egress guard: decoy processes in the host network may only reply and report to the sensor API; the web UI,
  `127.0.0.1`, the LAN and the internet are refused.
- SMB share enumeration (`net view`, `smbclient -L`) works on host-mode decoys behind the egress guard: the
  `srvsvc`/`wkssvc` named pipes reach their RPC handlers inside the decoy process instead of over TCP `127.0.0.1`,
  so the guard keeps loopback closed and no RPC port listens on `127.0.0.1` any more.
- SMB `srvsvc` server info (NetrServerGetInfo) answers with the decoy's name, persona OS version and server type
  (domain controller bits on a DC); it used to fail and drop the pipe.
- The self-test lists host services that listen on all addresses.
- The console makes no outbound connections for alerting, so network monitoring sees no alert traffic from it.
- The undelivered log is opened write-only with `O_NOFOLLOW`, never read back, and capped.
- Enrollment validates the decoy IP; slot checks run inside the fleet lock, so concurrent join requests cannot exceed
  the limit. A sensor beyond the limit gets 403 on ingest and config.
- The export requires an admin session and the CSRF header, is sent with `Cache-Control: no-store`, and contains bait
  user names and attempted passwords: keep exported files private.
- The image has no setuid/setgid files. Local host-network decoys and the decoy of a remote sensor now also run with
  `no-new-privileges`:
  they start as root with only `NET_BIND_SERVICE`, `SETUID`, `SETGID` and `SETPCAP`, and the entrypoint drops at once
  to uid 10001 with `setpriv`, cutting the bounding set to `NET_BIND_SERVICE` and keeping only it (ambient) for ports
  22/445. The console, sensor and relay roles refuse to run as root without that drop.
- `sensor.gap` notes are rate-limited: at most one per decoy per 5 minutes (later reports in that window are merged
  into it, counts summed), and decoy-incident notes keep only their newest 20 lines / 4 KB. The first/last timestamps
  are the decoy's own clock and are dropped when older than 30 days or in the future.
- A remote sensor that follows its interface's address never listens on `0.0.0.0` when that interface has no IPv4
  address: it waits briefly, then exits and is restarted.

## v0.4.0 — 2026-11-11

A decoy must survive a careful attacker with real tools. This release fixes every finding of the 2026-11-11
live VM test (B1–B26, except B10) and the follow-up re-test (F1–F7), and adds `add-decoy` and a per-decoy world map.

**Upgrading:** Community Edition supports fresh installs only — uninstall v0.3.x, then install v0.4.0 (new persona,
baits and admin token; remote sensors enroll again). In-place upgrades are an Enterprise feature.

### New
- **`install.sh add-decoy` / `remove-decoy NAME`:** add a decoy on a new interface (its own IP) to a running
  install. Persona, admin token, existing decoys and every planted honeytoken stay valid; SSH is pinned/moved as
  needed; firewall, TTL, INSTALL-INFO and MOTD are updated; uninstall still restores everything.
- **World map per decoy:** each decoy is drawn at the GeoIP location of its own public IP (or `sensors[].public_ip`
  for NAT/VPS decoys); arcs go to the decoy that was attacked. No more fixed Armenia default — internal decoys use
  `rpotctl site`, else the manager's public IP, else "not placed".
- **Breadcrumb planner:** baits only reference deployed decoys by their real names; every decoy holds credentials
  for the others (a single decoy is self-contained); adding a decoy keeps existing tokens. Remote enrollment uses the
  same planner.
- **Real AD behaviour on the DC:** TGT/TGS for bait accounts (Kerberoast hashes crack to the bait password),
  Sicily + SASL GSS-SPNEGO NTLM LDAP binds (impacket GetUserSPNs/GetADUsers, BloodHound-style tools), real
  LDAP filter evaluation, CLDAP netlogon ping, NetBIOS name service and NTP.
- **Post-install self-test** (manager, sensor, add/remove-decoy): container, every TCP/UDP port, reachability.
- **TTL 128** for Windows decoys on host addresses (iptables mangle; xt_TTL or xt_HL).
- Join strings carry an optional `?role=` hint so the sensor installer plans SSH before enrolling.

### Fixed — the decoy could be unmasked
- Manager certificate is persona-styled (`CN=<host>.<domain>, O=<Company>`, issued by "<Company> Issuing CA");
  no "ReD-Pot", no lab `console_ip` in the SANs; UI/sensor `Server` header matches the host (B1).
- SMB: persona OS version (10.0.17763), stable per-install ServerGUID, SMB1 refused, no fake boot time,
  Windows-like share list (B2, B24).
- DC DNS answers like Microsoft DNS (REFUSED version.bind, SERVFAIL out of zone) (B6).
- Admin ports are rejected with a TCP reset (look closed, not filtered); the review warns when an allowlist
  includes a decoy's own LAN (B9).
- Fake shell: redirections, `$VAR`, pipes/filters, `ps aux` columns, realistic curl/wget failures, SSH and FTP
  views of the backup server match, session files readable (B8, F7). Real tar.gz backups, varied CSVs, aged
  folders, 404 for WordPress probes (B23). Per-install `pwdLastSet` (F4).

### Fixed — detection
- SMB/RDP accept only a correct bait password (NTLMv2/v1 verified); wrong passwords are logon failures and feed
  password-spraying detection; a bait name with a wrong secret is L4 `honeytoken.attempt`, never L5 (B3, B15).
- RDP captures user/domain/workstation via CredSSP/NLA (B12). SMB uploads are stored inert with an L4 event;
  uploads have a per-sensor quota (B13, B14).
- Tamper alerts (`sensor.offline`) are L4 incidents on Overview/Incidents/Events, noted when the decoy returns,
  also across a console restart; L5 and tamper alerts bypass the hourly alert cap (B11, F5, R1).
- KPI counts distinct baits used; per-token hits in `/api/tokens` (B16). Host labels use only trustworthy
  evidence; tried names and RDP cookies are listed separately (B17, B18).
- The dashboard keeps working (KPIs, incidents, error banner) if a script fails to load (B25); clock-skew banner
  and server-relative ages (B26).

### Fixed — installer
- `--yes` validates defaults (B7); `--roles all`, `--placement` for manager installs, no stray rpotctl hint (B19);
  sensor `--no-ssh-move` decided by role, correct dry-run role, friendly pin-mismatch message (B20); review
  ports stay fixed when jumping back (B22); TTL detection on new kernels (F1); UDP ports in the self-test (F2);
  `remove-decoy` reports removed tokens correctly (F3); world-map notice for public decoys (F6).

## v0.3.0 — 2026-11-10

A decoy must show **only** the ports the real server would have. This release closes every way the host itself could
give a decoy away.

### Fixed
- Bait descriptions on the Deception tab said "None deploy SSH password" when the manager had no local web/backup decoy.
- Remote sensor: the chosen "interface that reaches the manager" is now really used — with two NICs in one
  subnet the kernel could pick the other one (found on a Wi-Fi bridge where only one NIC reached the manager);
  a pinned /32 route is applied at every service start and removed by uninstall.
- Remote sensor enrollment retries for ~30 s on network errors and explains the problem instead of a traceback;
  the one-time join string stays valid.
- A sensor whose decoy uses the server's own address now reports its **current** address (follows DHCP changes);
  the manager's list, map and DNS view update by themselves.
- `uninstall` also removes a half-finished sensor install (enrollment never completed).

### New (sensors and addresses)
- **Delete a sensor:** a revoked remote sensor can be removed from the Deception list (its events stay).
- **DHCP warning:** if an address ReD-Pot binds to (management, a decoy's own address) is a DHCP lease, the
  review explains the risk (after a reboot the address may change and SSH may become unreachable) and asks to
  confirm; make it static or reserve it in the DHCP server.

### Changed
- **Address question: Enter = the interface's own address** (on the management interface: this server's address).
  No free-address scan any more; type an address to give the decoy its own extra IP (checked: in the subnet, not the
  gateway, nobody answers on it).
- **Host SSH moves whenever a decoy shares the management address** — for every role. OpenSSH on 22 at a
  "Windows Domain Controller" would reveal it. A decoy on another interface's own address makes SSH listen only on
  the management IP (also after a move), for every role.

### New
- **Other services on a decoy's address are found and removed.** Every listener on that address that the real
  server would not have (MySQL on a DC, Cockpit, nginx …) is listed with its service name; the installer offers to
  stop and disable them (default **yes**, shown on the review screen, turned back on by uninstall). Containers and
  hand-started programs are reported with a warning. DHCP client noise is ignored.
- **Three admin-port allowlists — web UI, sensor API, host SSH** — each its own list (`0.0.0.0/0` = anyone).
  Everyone else gets no answer: the firewall drops it (chains `REDPOT-IN` / `REDPOT-DOCKER`, applied by the
  `redpot` service at every start, removed by uninstall). Your current SSH client is always allowed. When a decoy
  shares the management address and a list is open, the review warns that a port scan shows that admin port.
  Unattended: `--allow-ui`, `--allow-sensor`, `--allow-ssh`.

## v0.2.2 — 2026-11-10

Found while testing v0.2.1 with all five decoy roles on one server (every bait exercised: 12 of 12).

### Fixed
- **SMB bait-account logons were not counted on the Deception tab.** NTLM never reveals the password, so the file
  server recognises a bait account by its name only; that alert (L5) fired, but it carried no token id, so the
  bait's hit counter stayed at 0 and the "planted at" text was a generic guess. It now names the real bait.
- When the prebuilt image cannot be downloaded the installer says why (not public / not published / offline).

## v0.2.1 — 2026-11-10

### Changed — clearer network questions
- **Management first, then each decoy decides.** The installer asks only *which interface is for management*.
  Every decoy then picks **any usable interface — the management one included** — and an address:
  the interface's / this server's **own address**, or a **new free address**. The old global
  "Where should the decoys live?" question and the one-NIC/two-NIC split are gone.
- **Host SSH moves only when it has to:** only if a decoy needing port 22 shares the management address
  (web, FTP, DNS roles). A file server or DC on the server's address leaves SSH on 22.
- Several decoys may share one address when their ports don't overlap; clashes are explained.
- Interfaces that are down, have no cable or no IPv4 address are listed as **Not usable** with the reason
  (they used to be silently hidden).
- Remote sensors: the address question uses the same plain words.

### New
- **Prebuilt Docker image** `ghcr.io/redsidesecurity/red-pot:<version>`: the installer downloads it instead of building
  (about a minute instead of several), and uses it **only if it was built from exactly your checkout** (SHA-256 of the
  source in the image label). Modified code, a newer commit or no internet → it builds locally as before.
  `--build` forces a local build.
- **World map notice:** when the attack map is empty the dashboard and the wall explain why — decoys only on
  internal addresses (internal attacks are on the Overview map), no GeoIP database, or simply no public attackers yet.
- `sudo ./install.sh geoip` downloads the GeoIP database later and restarts the console.
- Only **one installer at a time** (a second one, e.g. in another SSH session, is refused with the first one's pid).

### Fixed
- Wall header showed the company name twice; login page now points to `INSTALL-INFO.txt` / `reset-token`.

## v0.2.0 — 2026-11-10

Field-test release: everything below was found or verified on real Ubuntu 22.04 / 24.04 / 26.04 servers.

### New
- **Decoy on the interface's own IP.** With a dedicated decoy NIC the installer now offers that NIC's own address
  (press Enter). The decoy listens only on that IP; host SSH keeps port 22 but listens only on the management IP.
  Extra free IPs on the NIC still work as before.
- **Realistic web decoy.** The web server role shows a company **webmail** sign-in (default), an **IT service desk**
  with knowledge base, or the classic **intranet** — all in the client's name, with a per-company accent colour.
  A stolen bait password opens a believable inbox / ticket queue and raises an L5 honeytoken alert.
- **`sudo ./install.sh reset-token [--wall] [--wall-allow …]`** — new admin token (all admin browsers logged out),
  optionally a new wall link and a list of allowed wall screens.
- **Busy ports are handled.** If a decoy needs a port that a host service already uses (nginx, apache2, samba …),
  the installer names the service and offers to stop + disable it — shown on the review screen first, turned back
  on by `uninstall` (`--stop-conflicting` for unattended installs). Containers and hand-started programs are
  reported with a hint. VPS mode is checked too.
- **Wall screen security.** A wall session works only on the screen (IP) that opened the link, for 7 days
  (`console.wall_days`); a new wall link logs out every screen; optional screen allowlist (`console.wall_allow`);
  every use of the link is logged.
- **Damaged package database repair.** After a power cut `dpkg` file lists can be zero-filled, which blocks every
  `apt` install ("files list file … is missing final newline"). The installer detects this and rebuilds the lists.
- README: **choosing a setup** (one vs two interfaces), busy ports, going back in the wizard.
  New `docs/TEST-COMMANDS.md`: Ubuntu CLI commands to test every decoy role.

### Fixed
- **Host SSH did not move on Ubuntu 22.10+ (`ssh.socket`)**: `/run/sshd` did not exist yet, `sshd -t` failed and
  SSH stayed on 22. Also handled: `Port` lines in other `sshd_config.d` files (commented out, restored on
  uninstall), `ListenAddress` with a port (clear stop), systemd's restart rate limit (could leave SSH down after
  uninstall), Ubuntu 22.04's fixed-port `ssh.socket`; port 22 is now verified closed after the move.
- Management interface detected correctly when the installer runs under `sudo`.
- Pinning SSH never drops an address that carries a live SSH session (no lock-out).
- Docker is installed package by package and apt's real error is shown; a missing program is a clear error, not
  a traceback.
- Decoy interface list keeps the same numbers as the network step; the default avoids the internet-route NIC.

### Requirements
- Ubuntu **22.04+** (tested 22.04, 24.04, 26.04) or Debian 12+.

## v0.1.0 — 2026-11-09

First public release.
