# Guarded Apps: default Chromium container.
#
# One locked-down Chromium in kiosk mode on a TigerVNC display, with a
# persistent profile so the shared provider login survives restarts.
# My Bastion reaches it as a normal VNC connection; see ../README.md.

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        tigervnc-standalone-server \
        tigervnc-tools \
        fonts-liberation \
        fonts-noto-core \
        fonts-noto-cjk \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user that runs Xvnc and Chromium. Root only writes the
# managed policy at start-up, so the user cannot change it.
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin guarded \
    && mkdir -p /data /etc/chromium/policies/managed /opt/guarded \
    && chown guarded:guarded /data

COPY entrypoint.sh /opt/guarded/entrypoint.sh
COPY policies/ /opt/guarded/policies/
RUN chmod 0755 /opt/guarded/entrypoint.sh

# /data/profile holds the Chromium profile (the provider login).
VOLUME ["/data"]

EXPOSE 5901

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/guarded/entrypoint.sh"]
