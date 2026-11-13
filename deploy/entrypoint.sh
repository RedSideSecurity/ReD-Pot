#!/bin/sh
# ReD-Pot container entrypoint: console | sensor | relay | ctl ARGS...
set -e
# VPS/host-network decoys bind :22/:445 on the host's IP. Only they use the capability-carrying
# interpreter copy (normal containers drop ALL capabilities; a file-cap binary would not exec there).
PY=python
[ "${RPOT_LOWPORTS:-0}" = "1" ] && PY=/usr/local/bin/python-lowports

# RPOT_PRIVDROP=1 (host-network decoys): the container starts as root with only NET_BIND_SERVICE, SETUID,
# SETGID and SETPCAP, under no-new-privileges, and drops here to uid/gid 10001 with no supplementary groups.
# The bounding set is cut to NET_BIND_SERVICE (needs SETPCAP, hence the check below); NET_BIND_SERVICE is kept as an
# ambient capability (survives execve under no-new-privileges). SETUID/SETGID/SETPCAP are gone from every set after
# the exec and cannot come back (NNP, no setuid files, bounding set). python-lowports (not python) keeps the
# process name the installer's listener checks know; its file capability grants nothing beyond the ambient set here.
# Fail closed: anything other than a root start of the sensor role refuses to run, and so does a root start of a
# service role WITHOUT RPOT_PRIVDROP=1 (it would run as uid 0).
if [ "${RPOT_PRIVDROP:-0}" = "1" ]; then
  if [ "$(id -u)" != "0" ]; then
    echo "[x] RPOT_PRIVDROP=1 needs the container to start as root (user: \"0:0\") to drop to uid 10001" >&2
    exit 78
  fi
  if [ "$1" != "sensor" ]; then
    echo "[x] RPOT_PRIVDROP=1 is only for the sensor role" >&2
    exit 78
  fi
  capeff=$(sed -n 's/^CapEff:[[:space:]]*\([0-9a-fA-F]\{1,16\}\)$/\1/p' /proc/self/status)
  if [ -z "$capeff" ] || [ $(( (0x$capeff >> 8) & 1 )) != 1 ]; then
    echo "[x] RPOT_PRIVDROP=1 needs CAP_SETPCAP to drop the bounding set (compose cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]) - regenerate the compose file" >&2
    exit 78
  fi
  shift
  exec setpriv --reuid 10001 --regid 10001 --clear-groups --bounding-set -all,+net_bind_service \
    --inh-caps -all,+net_bind_service --ambient-caps +net_bind_service --no-new-privs \
    -- /usr/local/bin/python-lowports -m rpot.sensor.main "$@"
fi

case "$1" in
  console|sensor|relay)
    if [ "$(id -u)" = "0" ]; then
      echo "[x] refusing to run the $1 role as root: set RPOT_PRIVDROP=1 (sensor) or a non-root user" >&2
      exit 78
    fi ;;
esac
case "$1" in
  console) shift; exec python -m rpot.console.app "$@" ;;
  sensor)  shift; exec $PY -m rpot.sensor.main "$@" ;;
  relay)   shift; exec python -m rpot.sensor.relay "$@" ;;
  ctl)     shift; exec python /opt/rpot/rpotctl.py "$@" ;;
  *)       exec "$@" ;;
esac
