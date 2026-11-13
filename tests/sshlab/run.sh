#!/usr/bin/env bash
# Real systemd + sshd in throw-away containers: move SSH to 50022 and back, on Ubuntu 24.04
# (ssh.socket + generator) and 22.04 (ssh.service), with and without an extra 'Port 22' drop-in.
#   sudo tests/sshlab/run.sh
set -u
R=$(cd "$(dirname "$0")/../.." && pwd); H=$R/tests/sshlab
docker build -q -f $H/Dockerfile.2404 -t sshlab:24.04 $H >/dev/null
docker build -q -f $H/Dockerfile.2204 -t sshlab:22.04 $H >/dev/null
for v in 24.04 22.04; do for extra in "" "Port 22"; do
  C=sshlab-${v/./}-$RANDOM
  docker run -d --name $C --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    -v $R:/src:ro -v $H/move_restore.py:/t.py:ro sshlab:$v >/dev/null
  for i in $(seq 1 30); do docker exec $C systemctl is-system-running 2>/dev/null | grep -qE "running|degraded" && break; sleep 1; done
  [ -n "$extra" ] && docker exec $C bash -c "echo '$extra' > /etc/ssh/sshd_config.d/50-cloud-init.conf"
  docker exec $C bash -c "systemctl restart ssh.socket 2>/dev/null; systemctl restart ssh" >/dev/null 2>&1
  out=$(docker exec $C python3 /t.py 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  ok=FAIL; echo "$out" | grep -q "moved  : 0.0.0.0:50022" && echo "$out" | grep -q "restore: 0.0.0.0:22" && ok=PASS
  echo "$ok  Ubuntu $v ${extra:+(+ extra '$extra' drop-in)}"
  [ $ok = FAIL ] && echo "$out"
  docker rm -f $C >/dev/null
done; done
