# ReD-Pot by RedSide Security — one image for console and every role sensor.
FROM python:3.13-slim
ARG SRC_SHA=unknown
ARG VERSION=dev
LABEL org.opencontainers.image.title="ReD-Pot" \
      org.opencontainers.image.description="ReD-Pot internal-network deception (console + decoy sensors) by RedSide Security" \
      org.opencontainers.image.source="https://github.com/RedSideSecurity/ReD-Pot" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="RedSide Security" \
      org.opencontainers.image.version="${VERSION}" \
      io.redside.src-sha256="${SRC_SHA}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/rpot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && cp "$(readlink -f /usr/local/bin/python3)" /usr/local/bin/python-lowports \
 && setcap cap_net_bind_service=+ep /usr/local/bin/python-lowports \
 && useradd -r -u 10001 -d /var/lib/rpot -s /usr/sbin/nologin rpot \
 && mkdir -p /var/lib/rpot /etc/rpot /srv/rpot/baits /run/rpot && chown rpot:rpot /var/lib/rpot /run/rpot
# pip (with its vendored urllib3/msgpack) and bundled setuptools wheels are not needed at runtime: remove
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null; \
    rm -rf /usr/local/lib/python3*/ensurepip /usr/local/lib/python3*/site-packages/setuptools* /usr/local/bin/pip* || true
COPY rpot ./rpot
COPY roles ./roles
COPY rpotctl.py ./
COPY deploy/entrypoint.sh /usr/local/bin/rpot
RUN chmod 755 /usr/local/bin/rpot
# F5: no setuid/setgid file may remain (a decoy RCE must not reach euid 0 through su/passwd/mount ...).
# Host-network decoys drop root with setpriv (util-linux) in the entrypoint: the build fails if it is missing.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && test -z "$(find / -xdev -perm /6000 -type f)" \
 && command -v setpriv >/dev/null
USER rpot
ENTRYPOINT ["rpot"]
CMD ["console"]
