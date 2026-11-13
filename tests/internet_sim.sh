#!/usr/bin/env bash
# Simulate Internet attackers with REAL public source IPs against a running ReD-Pot CE bridge lab
# (tests/lab_scenarios.sh setup: FS01 + DC01 + WEB01). Each country gets a small internal docker network
# (/29 of a real public range, geolocated by DB-IP); the 3 decoys are temporarily attached and attacker
# containers connect to the decoys' address in that network, so the decoys see genuine public source
# addresses. The networks are --internal (no route out, no NAT) and are removed afterwards.
#   tests/internet_sim.sh [PROJECT=rpotlab] [IMAGE=rpot:1.0.0] [DEPLOY_DIR (for the leaked-cred demo)]
#   ONLY="br ke" tests/internet_sim.sh ...   → only those networks (e.g. to show fresh vs old activity)
#   FS_NAME=RS-FS-01 WEB_NAME=RS-WEB-01 DC_NAME=RS-DC-01 ...  → decoy host names if not FS01 / WEB01 / DC01
#   DC_NAME=- ...                                             → the lab has no DC decoy
#   DRY_RUN=1 tests/internet_sim.sh ...      → print the docker commands instead of running them
# Run it only on the lab host (vm1 or a laptop VM), never on the shared control box.
set -u -o pipefail
P=${1:-rpotlab}; IMG=${2:-rpot:1.0.0}; DEP=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
FS_NAME=${FS_NAME:-FS01}; WEB_NAME=${WEB_NAME:-WEB01}; DC_NAME=${DC_NAME:-DC01}
cname() { echo "${P}-$(echo "$1" | tr 'A-Z' 'a-z')-1"; }
FS=$(cname "$FS_NAME"); WEB=$(cname "$WEB_NAME"); DCC=""
[ "$DC_NAME" != "-" ] && DCC=$(cname "$DC_NAME")
# cc  subnet               profiles (one container each, attacker IPs .5 .6: a /29 has 6 hosts, at most 2 profiles)
NETS="cn1 218.92.0.0/29 ssh,scanner
cn2 36.110.0.0/29 scanner,ssh
ru 45.155.205.0/29 mix,LEAKED
de 185.220.101.0/29 web,smb
nl 193.32.162.0/29 scanner,web
lt 141.98.11.0/29 ssh,dc
us1 167.94.138.0/29 scanner,scanner
us2 104.248.50.0/29 web,ssh
br 177.54.144.0/29 rdp,smb
id 103.152.118.0/29 ssh
hu 80.94.95.0/29 web,dc
th 122.155.0.0/29 scanner
ke 197.232.17.0/29 rdp,dc
vn 14.161.0.0/29 ssh,web"

x() {  # run, or print with DRY_RUN=1
  if [ -n "${DRY_RUN:-}" ]; then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}

LEAK_U=""; LEAK_P=""
if [ -n "$DEP" ] && [ -f "$DEP/rpot.json" ]; then
  read -r LEAK_U LEAK_P < <(python3 -c 'import json,sys
c=json.load(open(sys.argv[1]))
t=[t for t in c["tokens"].values() if t.get("kind")=="credential" and sys.argv[2]+":ssh" in t.get("valid_on",[])][0]
print(t["username"],t["password"])' "$DEP/rpot.json" "$WEB_NAME")
fi

cleanup() {
  [ -n "${DRY_RUN:-}" ] && return
  while read -r cc net _; do
    for c in "$FS" "$WEB" $DCC; do docker network disconnect -f "rpot-inet-$cc" "$c" >/dev/null 2>&1; done
    docker network rm "rpot-inet-$cc" >/dev/null 2>&1
  done <<< "$NETS"
}
trap cleanup EXIT
cleanup

pids=()
while read -r cc net profs; do
  if [ -n "${ONLY:-}" ] && [[ " $ONLY " != *" $cc "* ]]; then continue; fi
  base=${net%/*}; pre=${base%.*}; first=${base##*.}
  # .1 gateway (unused: internal), .2 FS, .3 WEB, .4 DC, .5 .6 attackers (.7 = broadcast)
  x docker network create --internal --subnet "$net" --gateway "$pre.$((first+1))" "rpot-inet-$cc" | sed 's/^[0-9a-f]\{64\}$//;/^$/d' || continue
  x docker network connect --ip "$pre.$((first+2))" "rpot-inet-$cc" "$FS"
  x docker network connect --ip "$pre.$((first+3))" "rpot-inet-$cc" "$WEB"
  dcip=-
  if [ -n "$DCC" ]; then x docker network connect --ip "$pre.$((first+4))" "rpot-inet-$cc" "$DCC"; dcip=$pre.$((first+4)); fi
  i=5
  for pr in ${profs//,/ }; do
    args=("$pr" "$pre.$((first+2))" "$pre.$((first+3))" "$dcip")
    if [ "$pr" = LEAKED ]; then [ -n "$LEAK_U" ] || continue; args=(leaked "$pre.$((first+2))" "$pre.$((first+3))" "$dcip" "$LEAK_U" "$LEAK_P"); fi
    if [ "$pr" = dc ] && [ "$dcip" = - ]; then continue; fi
    if [ "$i" -gt 6 ]; then echo "[-] $cc: no free address for $pr (a /29 holds 2 attackers)" >&2; continue; fi
    x docker run --rm --network "rpot-inet-$cc" --ip "$pre.$((first+i))" -v "$HERE:/t:ro" --entrypoint python "$IMG" /t/inet_attacker.py "${args[@]}" &
    pids+=($!); i=$((i+1))
    if [ ${#pids[@]} -ge 6 ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
done <<< "$NETS"
wait
echo "[+] internet simulation finished"
