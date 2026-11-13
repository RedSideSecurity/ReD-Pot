#!/usr/bin/env bash
# ReD-Pot CE 3-decoy bridge lab: build it, then simulate internal workstations against it.
#   tests/lab_scenarios.sh setup    rpotctl init (3 decoys, --net-mode bridge) + compose + docker compose up
#   tests/lab_scenarios.sh attack   the workstation scenarios below
#   tests/lab_scenarios.sh all      setup, then attack
#   tests/lab_scenarios.sh down     docker compose down -v (keeps DIR)
#   DRY_RUN=1 tests/lab_scenarios.sh all    print every command instead of running it
# Settings (env): P=rpotlab IMG=rpot:1.0.0 DIR=./lab PRE=172.30.50 DOMAIN=corp.redsidesecurity.com PROFILE=it
#                 FS_NAME=FS01 DC_NAME=DC01 WEB_NAME=WEB01 (last octets FS=.21 DC=.10 WEB=.22, scanner SCAN=.6)
# Decoys (Community Edition: at most 3, one per IP on the isolated lab network ${P}_decoy):
#   FS01  windows-file-server        DC01  windows-domain-controller (also the domain's DNS)   WEB01 linux-web-hosting
# Workstations (containers on ${P}_decoy):
#   .6   IT-SCANNER           allowlisted vulnerability scanner (all 3 decoys)  → recorded, no incident
#   .91  SALES-PC-11          one stray TCP connect to WEB01                    → L1 touch
#   .77  HR-PC-02 (lilit.s)   opens \\FS01\Public by mistake                     → L3 (data share)
#   .66  DEV-PC-03            SSH password spraying on WEB01                    → L3 brute force / spraying
#   .50  ACC-PC-07 (anna.k)   breadcrumb chain FS01 → WEB01 → DC01 (attack_sim) → L5 honeytokens + bait document
#   .52  ACC-PC-07 (2nd NIC)  AD recon: DNS, SYSVOL GPP, LDAP bind + spraying, Kerberoasting (dc_attack_sim) → L4/L5
set -eu
ACT=${1:-all}
P=${P:-rpotlab}; IMG=${IMG:-rpot:1.0.0}; DIR=${DIR:-./lab}; NET=${P}_decoy
PRE=${PRE:-172.30.50}; DOMAIN=${DOMAIN:-corp.redsidesecurity.com}; PROFILE=${PROFILE:-it}
FS_NAME=${FS_NAME:-FS01}; DC_NAME=${DC_NAME:-DC01}; WEB_NAME=${WEB_NAME:-WEB01}
FS=$PRE${FS:-.21}; DC=$PRE${DC:-.10}; WEB=$PRE${WEB:-.22}; SCAN=$PRE${SCAN:-.6}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(dirname "$HERE")

x() {  # run, or print with DRY_RUN=1
  if [ -n "${DRY_RUN:-}" ]; then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}
run() { local ip=$1; shift; x docker run --rm --network "$NET" --ip "$ip" -e PYTHONPATH=/opt/rpot -v "$HERE:/t:ro" --entrypoint python "$IMG" "$@"; }

setup() {
  echo "== 3-decoy bridge lab in $DIR (project $P, network $NET)"
  x python3 "$ROOT/rpotctl.py" init -d "$DIR" --net-mode bridge --profile "$PROFILE" --domain "$DOMAIN" \
      --subnet "$PRE.0/24" --console-ip "$PRE.5" --allow "$SCAN/32" \
      --sensor "$FS_NAME=windows-file-server@$FS" \
      --sensor "$DC_NAME=windows-domain-controller@$DC" \
      --sensor "$WEB_NAME=linux-web-hosting@$WEB"
  x python3 "$ROOT/rpotctl.py" compose -d "$DIR" --image "$IMG" --ui-bind 127.0.0.1
  x docker compose -f "$DIR/docker-compose.yml" -p "$P" up -d
  echo "   UI: https://127.0.0.1:8740 (admin token: console.admin_token in $DIR/rpot.json)"
}

netbios() {  # derived by rpotctl from --domain; fall back to the first label when DIR does not exist yet
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["company"]["netbios"])' "$DIR/rpot.json" 2>/dev/null \
    || echo "${DOMAIN%%.*}" | tr 'a-z' 'A-Z'
}

attack() {
  NB=$(netbios)
  echo "== .6 allowlisted scanner"
  run "$SCAN" -c "
import socket
for h in ('$FS','$DC','$WEB'):
    for p in (21,22,53,80,88,135,139,389,443,445,3389):
        s=socket.socket(); s.settimeout(.5)
        try: s.connect((h,p))
        except OSError: pass
        s.close()
print('scan done')"

  echo "== .91 stray touch"
  run "$PRE.91" -c "
import socket; s=socket.create_connection(('$WEB',80),2); s.close(); print('touched')"

  echo "== .77 HR user browses Public share"
  run "$PRE.77" -c "
from impacket.smbconnection import SMBConnection
c=SMBConnection('HR-PC-02','$FS',myName='HR-PC-02')
try: c.login('lilit.s','x')
except Exception as e: print('named logon refused:', str(e)[:60]); c=SMBConnection('HR-PC-02','$FS',myName='HR-PC-02'); c.login('','')
print([f.get_longname() for f in c.listPath('Public','*')])"

  echo "== .66 SSH password spraying"
  run "$PRE.66" -c "
import paramiko
for u in ('root','admin','ubuntu','deploy','test','oracle'):
    c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try: c.connect('$WEB',22,username=u,password='Password1',timeout=5,allow_agent=False,look_for_keys=False)
    except Exception: pass
    c.close()
print('spray done')"

  echo "== .50 breadcrumb chain FS -> WEB -> DC"
  run "$PRE.50" /t/attack_sim.py --fs "$FS" --web "$WEB" --dc "$DC" --domain "$NB"

  echo "== .52 domain recon: DNS, SYSVOL GPP password, LDAP, spraying, Kerberoasting"
  run "$PRE.52" /t/dc_attack_sim.py --dc "$DC" --domain "$DOMAIN" --dc-name "$(echo "$DC_NAME" | tr 'A-Z' 'a-z')"
}

case "$ACT" in
  setup) setup ;;
  attack) attack ;;
  all) setup; attack ;;
  down) x docker compose -f "$DIR/docker-compose.yml" -p "$P" down -v ;;
  *) echo "usage: $0 setup|attack|all|down  (DRY_RUN=1 prints the commands)" >&2; exit 2 ;;
esac
