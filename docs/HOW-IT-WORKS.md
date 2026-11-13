# How ReD-Pot works

- [The idea in one picture](#the-idea-in-one-picture)
- [Severity ladder L0–L5](#severity-ladder-l0l5)
- [Decoy roles and their baits](#decoy-roles-and-their-baits)
- [The breadcrumb chain](#the-breadcrumb-chain)
- [What an attacker sees, protocol by protocol](#what-an-attacker-sees-protocol-by-protocol)
- [Manager and sensors](#manager-and-sensors)
- [Security model](#security-model)
- [Dashboard](#dashboard)
- [Repository layout](#repository-layout)

## The idea in one picture

```
   your LAN                                   ReD-Pot trap zone (decoys nobody should touch)
 ┌──────────────┐   1 scan / touch          ┌────────────────────┐
 │ ACC-PC-07    │ ────────────────────────▶ │ RS-FS-01  file srv │  \\RS-FS-01\IT\passwords.txt
 │ (phished)    │   2 open share, steal     │ 135 139 445 3389   │──┐
 └──────────────┘ ────────────────────────▶ └────────────────────┘  │ credentials + SSH key
        │          3 reuse stolen password  ┌────────────────────┐  │
        └─────────────────────────────────▶ │ RS-WEB-01 web srv  │◀─┘   ⇒ L5 honeytoken alert:
                                            │ 22 80 443          │       "password planted on
                                            └────────────────────┘        RS-FS-01 used on RS-WEB-01
                                                      │                   by ACC-PC-07 (anna.k)"
                    ┌──────────────┐                  ▼
                    │ ReD-Pot      │ ◀── encrypted events from every decoy (scores, incidents,
                    │ manager      │      attack path, alerts.json for your SIEM)
                    └──────────────┘
```

A decoy is a fake server that behaves like a real one up to the point of a successful login, and then serves
believable but **fake** data. Nothing an attacker sends is executed. Every decoy has **bait** on it
(credentials, keys, documents). Each bait is a **honeytoken** with a unique id: when it is used anywhere, ReD-Pot knows exactly
where it was stolen from.

## Severity ladder L0–L5

Counting events is useless: a single `nmap` produces hundreds. ReD-Pot scores **how far** a source got instead:

| Level | Name | Meaning | Examples | Alert? |
|---|---|---|---|---|
| L1 | touch | TCP handshake only | someone typed a wrong IP | no (logged) |
| L2 | interaction | protocol data exchanged | HTTP GET, SMB negotiate, SSH banner, DNS lookup, LDAP rootDSE | no (logged) |
| L3 | intent | trying to get in or map things | login attempt, share enumeration, zone transfer, Kerberos pre-auth guess, port scan (≥5 ports, or every port of one decoy with ≥3 ports, / 10 min), password spraying (≥5 failures / 5 min), path brute force | **yes** |
| L4 | compromise | it worked | valid login, file read, command typed, sensitive file downloaded, directory modification attempt, **decoy offline (tampering)**, a bait account **name** used without its secret (`honeytoken.attempt`: AS-REP-roast user list, wrong password) | **yes** |
| L5 | honeytoken | stolen bait used | a planted password / SSH key / document used anywhere (the **correct** secret), a TGT for a bait account, a Kerberoast of a honey SPN | **yes, critical** |

Events from the same source are grouped into one **incident** that only ever goes **up** the ladder. Allowlisted sources
(your vulnerability scanner, IT admin hosts) are recorded but never raise incidents.

Generic usernames such as `admin`, `administrator`, `root` or `backup` are in every wordlist, so on their own they never count
as a honeytoken. A matching bait **password** always does.

## Decoy roles and their baits

Each role runs in its own container with only that role's ports. A decoy answers on the IP of its own network
interface (one decoy per interface, up to 3 decoys in Community Edition), with that interface's real MAC address, and the
host firewall lets only the decoy's ports answer there, so a scan sees one server with exactly the ports of that role.

| Role | Looks like | Ports | Baits planted |
|---|---|---|---|
| `windows-file-server` | Windows Server 2019 file server | 135, 139, 445, 3389 | departmental shares (`Finance`, `HR`, `IT`, `Public`); `IT\passwords.txt`; `IT\keys\*_deploy.key` (SSH key); `Salaries_2026.docx`, `Network_Overview.docx` that **call home when opened in Word** |
| `linux-web-hosting` | Ubuntu, Apache + PHP intranet | 22, 80, 443 | intranet with `/admin` login; `/.env` with the portal admin seed password, a DB password re-used on the backup FTP and (with a DC) an LDAP bind account; `robots.txt`; SSH with a fake shell and believable home directories |
| `ftp-backup-server` | Debian backup box, vsftpd | 21, 22 | `/backups/<web>_portal_db_<YYYY-MM>.sql` (admin MD5 hash + hint), a real `<web>_portal_site_<YYYY-MM>.tar.gz`; `configs/backup_job.ps1` (domain service account), `configs/*.sh` / `upload.netrc` with passwords for the other decoys |
| `windows-domain-controller` | Windows Server 2019 Active Directory DC | 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389 tcp; 53, 88, 123, 137, 389 udp | `SYSVOL\…\Groups.xml` with a **GPP `cpassword`** (decryptable with `gpp-decrypt`); `NETLOGON\logon.bat` with a service password + upload/deploy scripts with passwords for the backup, web and DNS decoys; LDAP directory with honey users, including Kerberoastable **`svc_sql`** (SPN + password in its description) |
| `linux-dns-server` | Ubuntu, BIND 9 | 22, 53 tcp+udp | authoritative zone that resolves the other decoys (`dc01`, `files`, `intranet`, `backup` … and `_ldap._tcp` SRV records); the `dnsadmin` SSH password is planted on the other decoys (FS `passwords.txt`, DC NETLOGON, backup configs); `~dnsadmin` holds notes with credentials for them |

The company identity comes from two installer answers: the AD/DNS domain and the industry (bank, hotel, government,
IT, generic). The company name, NetBIOS name and mail domain are derived from the domain (`corp.ararat-bank.am` →
"Ararat Bank", `ARARATBANK`, `ararat-bank.am`). The 14 users are picked from a built-in pool of first and last names
with a random per-install seed, and the seed also picks the username convention (`a.petrosyan`, `anna.petrosyan`,
`apetrosyan`, `anna_p`). The identity is used in banners, TLS certificates, SMB server names, user lists, file names and
passwords. The set of bait files is fixed, but every deployment gets **different** passwords, keys, users, dates and file
contents, so there are no shared fingerprints like T-Pot's default banners. Community Edition does not let you edit the
persona, the users or the baits.

## The breadcrumb chain

Baits point at other decoys, so an intruder who takes the bait walks deeper into the trap and leaves a trail.
The chain is **planned from the decoys that are really deployed** (local and enrolled remote ones): every crumb
names only those hosts, by their real names and FQDNs, and every decoy holds a credential for **each other**
decoy plus one that works on itself, so even 1–2 decoys give a complete path. Examples with all roles
(`<web>` = the web decoy's real name, e.g. `arb-web01`):

```
FS   \IT\passwords.txt ─────────▶ WEB  ssh deploy / …        ─▶ L5
     \IT\keys\<web>_deploy.key ─▶ WEB  ssh (public key)      ─▶ L5
     \IT\passwords.txt ─────────▶ BKP  ftp backup / …, DNS ssh dnsadmin, svc_scan (DC LDAP / FS SMB)
WEB  /.env ─────────────────────▶ WEB  /admin (seed password), BKP ftp (DB password re-use), DC LDAP (svc_web)
BKP  <web>_portal_db_*.sql ─────▶ WEB  /admin portal (MD5 + hint)
BKP  configs/backup_job.ps1 ────▶ DC LDAP / FS SMB (svc_backup); pull_<web>.sh ─▶ WEB ssh; upload.netrc ─▶ itself
DC   SYSVOL Groups.xml cpassword ─▶ local admin on FS / LDAP bind
DC   NETLOGON logon.bat, ftp_<bkp>.txt, deploy_<web>.cmd, dns_reload_<dns>.cmd ─▶ LDAP, BKP ftp, WEB ssh, DNS ssh
DC   LDAP svc_sql (SPN) ────────▶ Kerberoasting TGS-REQ
DNS  ~dnsadmin notes / nsupdate / .smbcredentials ─▶ WEB, BKP, DC, FS, itself
FS   *.docx opened in Word ─────▶ beacon to the web decoy    ─▶ L5 (who opened it, from where)
```

Each token's *planted* field (and so the incident text) names the decoy and path where the bait really lives.
Token ids, passwords and SSH keys are derived from a manager-only `bait_seed` (in `rpot.json`) + persona +
host names: `rpotctl.py baits` after **adding** a decoy keeps every existing token (stolen baits stay valid,
their `valid_on` only grows) and adds crumbs for the new one. The persona is fixed for the life of an install.
Remote enrollment uses the same planner; its new tokens are stored on the manager.

The dashboard draws this as an **attack path** (RS-FS-01 → RS-WEB-01 → RS-BKP-01 → bait doc) with timestamps.

## What an attacker sees, protocol by protocol

| Protocol | Behaviour | Logged as |
|---|---|---|
| SMB (impacket + persona) | SMB 2.0.2/2.1 only (SMB1 refused like a hardened Server 2019), persona OS version / names / stable ServerGUID, Windows-like share list (`ADMIN$`, `C$`, `IPC$`) for a logged-on bait user; like a Server 2019, a **null session** cannot list shares but can open the read-only bait shares by name. `IPC$` is pipe-only and `ADMIN$`/`C$` refuse access (any attempt to use them as a disk = `smb.admin_share`, L3); a **named** logon succeeds only with a bait password valid on this decoy (NTLMv2/v1 verified against its NT hash), anything else → `STATUS_LOGON_FAILURE`. Uploads to `Public` go to the inert upload store, other shares → access denied | user, domain, **workstation name**, shares, files read/written; failed logons feed spraying detection; bait name + wrong password = L4, correct bait password = L5 |
| SSH (paramiko) | Ed25519/ECDSA/RSA host keys, password + key auth, simulated bash with quoting, `$VAR`, `;` `&&` `||`, pipes (`grep`/`head`/`tail`/`wc`/`sort`), redirections (`2>/dev/null`, `2>&1`) — nothing is executed | every command; download URLs recorded, never fetched (IP → connect fails, name → does not resolve) |
| HTTP/HTTPS | intranet, `/admin` login, `.env`, scanner and exploit detection (Log4Shell, path traversal …) | path, user agent, scanner verdict |
| FTP | vsftpd banner, listing, download (root = `/srv/ftp`, also visible over SSH); uploads stored inert (`0400`, named by SHA-256), per-sensor quota shared with SMB (`RPOT_UPLOAD_MAX_MB`=200, `RPOT_UPLOAD_MAX_FILES`=500, `RPOT_UPLOAD_MAX_FILE_MB`=20; beyond → `file.write` with `dropped`) | logins, files |
| RDP | X.224 + TLS + CredSSP/NLA: persona NTLM challenge (what `rdp-ntlm-info` shows), the NTLM AUTHENTICATE gives user / domain / workstation; the logon never completes (correct bait password → "logon type not granted", else logon failure) | `rdp.auth` (L3) with username, domain, workstation; L5 for a correct bait password, L4 for a bait name with a wrong one |
| LDAP / LDAPS / GC | real rootDSE (Windows BER encoding: nmap says "Microsoft Windows Active Directory LDAP"), AD-accurate errors (`000004DC`, `data 52e`); simple, **Sicily NTLM** and **SASL GSS-SPNEGO NTLM** binds (sealed like Windows) verified against the bait accounts; real filter evaluation → the directory after a bait bind | binds (with workstation), searches (e.g. `servicePrincipalName=*`) |
| Kerberos | a real KDC for the bait accounts: correct password → **TGT** (per-install krbtgt key); TGS for a honey SPN is encrypted with that account's key, so the Kerberoast hash cracks to the bait password; `PREAUTH_REQUIRED` / `C_PRINCIPAL_UNKNOWN` / `PREAUTH_FAILED` for everyone else | user enumeration (kerbrute), password guesses (`auth.failed` → spraying), TGT issued, Kerberoasting |
| CLDAP / NetBIOS / NTP (DC, udp) | netlogon "LDAP ping" answered with a `NETLOGON_SAM_LOGON_RESPONSE_EX` from the persona (nltest, NetExec, `net ads`); NBNS name + node status (`DC01<20>`, `DOMAIN<1C>`, the decoy NIC's own MAC); NTP server (stratum 3) | DC locator pings, `nbtstat -A` / nbtscan, time queries |
| DNS | authoritative for your zone only (never an open resolver); out-of-zone: `REFUSED` (BIND on the DNS role) / `SERVFAIL` (Microsoft DNS on the DC); `version.bind` → BIND 9 on the DNS role, `NOTIMP` on the DC (Windows default; RA set on other answers, never recursion); UDP rate-limited, replies ≤4× request | lookups, zone-transfer (AXFR) attempts, `version.bind` fingerprinting |

## Manager and sensors

```
 decoy LAN / VLAN                 sensor host                     management network
┌───────────────┐ answers only ┌────────────────────────┐  HTTPS (pinned) ┌──────────────────────┐
│ attacker ───▶ │ ───────────▶ │ decoy ─unix socket─▶ relay ─────────────▶│ manager: sensor API   │
└───────────────┘              └────────────────────────┘ 1 kept-alive TLS │          web UI (admin)│
                                                            connection     └──────────────────────┘
```

| | |
|---|---|
| Transport | HTTPS (TLS 1.2/1.3 only) on its own random port. The web UI is HTTPS on a different random port. |
| Trust | The manager's certificate (persona-styled: `CN=<host>.<domain>, O=<Company>`, issued by "<Company> Issuing CA", SANs = real manager addresses only) is **pinned** by its SHA-256 fingerprint, which travels inside the join string. A different certificate is refused, so there is no CA to compromise and man-in-the-middle fails. |
| Enrollment | A one-time token (24 h) is exchanged for a **per-sensor key**. The manager stores only its hash. Replayed or guessed tokens get 403. *Revoke* disables a key immediately. |
| Least data | A sensor receives only its identity, the persona and a **hashed** honeytoken index (salted PBKDF2): no plaintext bait passwords, no bait locations, no admin secrets. The manager enriches events by token id. Exception by design: the DC decoy holds the **Kerberos keys** (AES256/AES128/RC4 = NT hash) of the bait accounts valid on it (`ldap/krb_keys.json`) so it can issue tickets and verify NTLM — password-equivalent for the fake domain only, never the plaintext; its krbtgt key is random per install. |
| Isolation | On a remote sensor the decoy hands events to a relay sidecar through a Unix socket, and only the relay talks to the manager. Local decoys run in the host network on their interface's IP; the host firewall lets their processes open new connections only to the manager's sensor API (not the web UI, not `127.0.0.1`, not the LAN or internet). Admin ports are published only on the management IP and accepted only on the management interface. |
| Anti-spoofing | Events are stamped with the authenticated sensor name, so a hijacked sensor cannot speak for another one. |
| Efficiency | One kept-alive TLS connection, heartbeats every 25–35 s with random jitter (no fixed beacon rhythm), batches gzip-compressed: about 0.6 kbit/s idle. |
| Resilience | If the manager is unreachable, the batch in flight is retried in memory for up to 60 s (a manager restart loses nothing). After that, the outage's events are written only to a local log on the decoy, `<data>/undelivered-<NAME>.jsonl` (mode 0600, capped by `RPOT_UNDELIVERED_MAX_MB`, default 50 MB, newest half kept). They are **never sent later**. On reconnect the sensor sends one `sensor.gap` note with the count and the first/last timestamp (decoy clock; no event content), shown on that decoy's incident. The manager keeps at most one such note per decoy per 5 minutes (later ones are merged into it) and caps decoy-incident notes at the newest 20 lines / 4 KB. Disk errors never stop the decoy. |
| Liveness | The manager checks every 30 s. More than 2 minutes of silence raises an **L4 "possible tampering"** alert, a red dashboard banner and an **incident** whose source is the decoy (`decoy FS01`), listed on Overview, Incidents and Events. Recovery and the `sensor.gap` count are added to that incident as notes. |
| Clocks | Sensor clocks are not trusted. A timestamp more than 15 minutes old or more than 5 minutes in the future is replaced by the manager's time; the sensor's value is kept as `sensor_ts` and the manager log warns once per sensor. |
| Decoy limit | At most 3 decoys: local decoys, remote sensors and pending join commands. It is checked by the installer, `rpotctl`, enrollment (a full manager answers a valid join with "decoy limit reached") and the database; a sensor beyond the limit gets 403 on ingest. Nothing phones home. |
| Live sync | Each heartbeat returns a config version. When it changes (a new sensor enrolled), sensors pull the new honeytoken index, so credentials stolen at one site are recognised at every site. |

## Security model

ReD-Pot is built to be attacked. The design goal is that a fully hijacked decoy gains **nothing**:

- **Containers:** run as uid 10001 with **zero capabilities** (`cap_drop: ALL`), `no-new-privileges`, the default seccomp profile,
  a **read-only root filesystem** (only tmpfs and data volumes writable), memory and process limits, log rotation and no Docker socket.
  The image has no setuid/setgid files. Decoys in the host network add only `NET_BIND_SERVICE`. Host-network decoys (local and
  remote) start as root with `NET_BIND_SERVICE`, `SETUID`, `SETGID` and `SETPCAP` under `no-new-privileges`, and the
  entrypoint drops at once to uid 10001 with `setpriv`, cutting the bounding set to `NET_BIND_SERVICE` and keeping it
  as an ambient capability; the other three are gone after the drop. A service role started as root without that drop
  refuses to run.
- **Host firewall** (`firewall.sh`): on each decoy interface only the decoy's ports answer; everything else, IPv6 included,
  looks like a closed port (TCP reset / ICMP port unreachable), and the interface answers ARP only for its own address.
  This hides every other host service on a decoy interface, including the management interface when a decoy shares it.
  Admin ports answer only on the management interface, to their allow-lists.
- **Hijacked decoy:** holds only its own key and a hashed honeytoken index. It cannot open the web UI (firewall egress guard for
  host-network decoys; the UI also refuses the management Docker subnet), cannot rewrite its configuration (read-only mounts) and
  cannot report as another sensor. In lab mode it has no internet access.
- **Untrusted input:** control characters are stripped and fields capped at the sensor. Every UI value is escaped, with a strict CSP.
  Every SQL query is parameterised. File paths are confined (realpath). Archive extraction refuses `..`, links and devices.
  Protocol parsers (BER, DNS) are bounded and fuzz-tested.
- **Floods:** one connection budget per decoy, shared by every TCP service (SMB and HTTP included): 250 concurrent connections,
  20 per source IP, and no new client while the decoy already runs 320 threads (its container allows 384). SMB sessions without
  a named logon are closed after 60 s idle. A source that hits a cap raises a level-3 "connection flood" event (once a minute).
  A failure to start a client thread drops that client only; the listener keeps running. Every 30 s the decoy checks that each
  listener is still bound and served; a dead one is restarted and reported, and the manager opens a level-4 "service down -
  possible DoS" incident for that decoy (`/api/sensors` lists `services_down` and per-service health). UDP is rate-limited per
  source and replies are capped (no amplification). Request bodies are capped, gzip bodies are inflated with a hard limit, repeated connects are de-duplicated,
  events expire after 90 days.
- **Privacy:** passwords that people *try* are stored masked (`S******* (len 9, h:1a2b3c4d)`), so an employee who mistypes a real
  password into a decoy does not end up in your SIEM in clear text.
- **Manager:** TLS 1.2+, HMAC-signed HttpOnly SameSite=Strict cookies, throttled login, CSRF header on state changes and on
  the export, a separate read-only cookie for wall screens, the server clock for liveness (sensor timestamps are clamped).
  No outbound connections for alerting: alerts stay in `alerts.json` and the database.
- **Residual risk:** on remote sensors, add a switch / firewall ACL so that the decoy IP may only **answer**, never
  **initiate** connections. In the Docker *lab* bridge mode, decoys can reach the Docker host's bridge IP.

## Dashboard

| Tab | What it is for |
|---|---|
| **Overview** | KPIs (*Honeytokens hit* = number of **different** baits really used in the range), the **internal network map** (your subnets on the left, the trap zone on the right, animated packets coloured by severity), live incidents |
| **Attack map** | world map of **public** source IPs (offline DB-IP GeoIP), top countries and ASNs, live external feed; dots fade with age. Each decoy is placed at the GeoIP location of its own public IP (city, or the country centre with the country database); decoys on private IPs at the site set with `rpotctl.py site`, else at the manager's `public_ip`, else "not placed". Arcs go from the attacker to the decoy it attacked |
| **Incidents** | every incident with level, source (workstation and logged-on user when known), what happened, sensors, status; **Export JSON** of incidents and alert records for a date range (UTC days, up to 366) |
| **Hosts** | every source seen: workstation name, logon user (only accounts a decoy accepted), users tried (every name typed, sprayed or sent), clients (the RDP `mstshash` cookie is shown here, it is not an identity); click for the attack path and full timeline |
| **Events** | raw events with filters |
| **Deception** | each decoy, its services, the baits planted on it, which stolen credentials unlock it and how often each was hit; decoy slots in use ("n of 3 decoys"); add, revoke and delete remote sensors, cancel pending joins |
| **Wall** | full-screen attack map for SOC screens, with a read-only kiosk link |

## Repository layout

```
install.sh                 interactive installer (manager, sensor, add-decoy/remove-decoy, uninstall)
installer/redpot_install.py  the installer itself (Python standard library only)
rpotctl.py                 deployment CLI: roles, init, baits, tls, compose, show, add-sensor, remove-sensor, wall-url, geoip, site
roles/*.json               role catalog (add a JSON file → a new role appears in the installer)
rpot/baits.py              persona + bait / honeytoken generator
rpot/common/               config, events transport (pinned TLS client, local undelivered log), TLS helpers
rpot/sensor/               sensor main, relay sidecar, protocol emulators in services/
rpot/common/edition.py     Community Edition constants: decoy limit, limit message
rpot/console/              manager: engine (SQLite, alert records), scoring, fleet, Flask app, static UI
tests/                     unit tests + attack simulators (attack_sim, dc_attack_sim, lab_scenarios, internet_sim)
docs/                      INSTALL, HOW-IT-WORKS, TEST-COMMANDS, COMPONENTS, brand, screenshots
```
