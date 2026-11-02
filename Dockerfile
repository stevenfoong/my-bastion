# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# =============================================================================
# Multi-stage Dockerfile for mybastion
#
# Stages:
#   1. guacd-builder  — compile guacd from guacamole-server source
#   2. rust-builder   — compile mybastion binary
#   3. runtime        — minimal image with both binaries + runtime deps
#
# Build:
#   docker build -t mybastion .
#
# Run:
#   docker run -d -p 8089:8089 mybastion
#
# Run with VDI (Docker desktop containers):
#   docker run -d -p 8089:8089 \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     --group-add $(getent group docker | cut -d: -f3) \
#     mybastion
#
# The image runs both guacd and mybastion under a simple entrypoint script.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build guacd from source
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS guacd-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool pkg-config make gcc g++ git ca-certificates \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev \
    libssh2-1-dev libssl-dev libvncserver-dev \
    libpango1.0-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libcunit1-dev libtelnet-dev libwebsockets-dev \
    uuid-dev freerdp3-dev libspice-client-glib-2.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Pin to known-good commit to avoid upstream -Werror breakage
RUN git clone https://github.com/apache/guacamole-server.git \
    && cd guacamole-server && git checkout 6719b20d

# Apply patches for FreeRDP 3.x / Debian 13 compatibility
COPY patches/ /build/patches/
COPY scripts/check-guacd-plugins.sh /build/
WORKDIR /build/guacamole-server
RUN for patch in /build/patches/*.patch; do \
        [ -f "$patch" ] || continue; \
        echo "Applying patch: $(basename "$patch")"; \
        git apply "$patch"; \
    done

RUN autoreconf -fi

WORKDIR /build/guacd-build
RUN /build/guacamole-server/configure \
        --prefix=/opt/mybastion \
        --with-ssh \
        --with-vnc \
        --with-rdp \
        --with-spice \
        --without-telnet \
        --disable-kubernetes \
        --disable-guaclog \
        --disable-guacclip \
        --disable-static \
    && make -j"$(nproc)" \
    && make install \
    && bash /build/check-guacd-plugins.sh /opt/mybastion/lib \
    && mkdir -p /opt/mybastion/lib/freerdp3 \
    && cp /opt/mybastion/lib/libguac*.so* /opt/mybastion/lib/freerdp3/ \
    && { cp /usr/lib/x86_64-linux-gnu/freerdp3/libguac*.so* /opt/mybastion/lib/freerdp3/ 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Stage 2: Build mybastion
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS rust-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src/ src/
COPY docs/ docs/
COPY static/ static/

RUN cargo build --release

# ---------------------------------------------------------------------------
# Stage 3: Runtime image
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# Runtime libraries for guacd
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libjpeg62-turbo libpng16-16t64 libwebp7 \
    libssh2-1 libssl3t64 libvncclient1 \
    libpango-1.0-0 libpulse0 \
    libspice-client-glib-2.0-8 \
    libavcodec61 libavformat61 libavutil59 libswscale8 \
    libtelnet2 libwebsockets19t64 \
    libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 \
    # Xvnc + Chromium for web browser sessions
    tigervnc-standalone-server \
    chromium chromium-sandbox \
    x11-utils \
    # Minimal runtime utilities
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Install guacd
COPY --from=guacd-builder /opt/mybastion/sbin/ /opt/mybastion/sbin/
# guacenc converts recordings to video for MP4 downloads
COPY --from=guacd-builder /opt/mybastion/bin/guacenc /opt/mybastion/bin/guacenc
COPY --from=guacd-builder /opt/mybastion/lib/ /opt/mybastion/lib/

# Install mybastion binary
COPY --from=rust-builder /build/target/release/mybastion /opt/mybastion/bin/mybastion

# Install static web assets
COPY static/ /opt/mybastion/static/

# Seccomp profile that lets Chromium's sandbox start, for the host to pass to
# `docker run --security-opt seccomp=...` (see docs/web-sessions.md)
COPY contrib/docker/seccomp-chromium.json /opt/mybastion/seccomp-chromium.json

# Library path for guacd
RUN echo "/opt/mybastion/lib" > /etc/ld.so.conf.d/mybastion.conf && ldconfig

# FreeRDP plugin setup: guacd loads "guac-common-svc" by name, which FreeRDP
# resolves to "guac-common-svc.so" in its plugin path. The build installs it as
# "libguac-common-svc-client.so", so we create a symlink with the expected name.
# We also ensure the system FreeRDP plugin dir exists and contains the plugins.
RUN mkdir -p /usr/lib/x86_64-linux-gnu/freerdp3 && \
    if [ -d /opt/mybastion/lib/freerdp3 ]; then \
        cp /opt/mybastion/lib/freerdp3/*.so* /usr/lib/x86_64-linux-gnu/freerdp3/ 2>/dev/null; \
        ln -sf libguac-common-svc-client.so /opt/mybastion/lib/freerdp3/guac-common-svc.so; \
        ln -sf libguac-common-svc-client.so /usr/lib/x86_64-linux-gnu/freerdp3/guac-common-svc.so; \
        echo "FreeRDP plugins installed:"; \
        ls /usr/lib/x86_64-linux-gnu/freerdp3/guac* /opt/mybastion/lib/freerdp3/guac-common-svc.so 2>/dev/null; \
    fi

# Create writable runtime directories
RUN mkdir -p /var/lib/mybastion /var/lib/mybastion/recordings /etc/mybastion/tls \
    /opt/mybastion/certs /opt/mybastion/drives /opt/mybastion/scripts \
    /opt/mybastion/vdi-homes

# Chromium policy: web session hardening.
# DeveloperToolsAvailability=0: CDP needed for login scripts. Users can't reach DevTools
# through the UI anyway — chrome://* is in URLBlocklist.
RUN mkdir -p /etc/chromium/policies/managed && \
    echo '{"AllowFileSelectionDialogs": false, "PasswordManagerEnabled": true, "ImportSavedPasswords": false, "DeveloperToolsAvailability": 0, "DownloadRestrictions": 3, "PrintingEnabled": false, "EditBookmarksEnabled": false, "BrowserSignin": 0, "SyncDisabled": true, "ExtensionInstallBlocklist": ["*"], "URLBlocklist": ["file://*", "chrome://*", "chrome-extension://*", "view-source:*", "javascript:*"], "URLAllowlist": ["chrome://policy"]}' \
    > /etc/chromium/policies/managed/mybastion.json

# Create non-root user with a real home directory (Chromium crashpad needs it)
RUN groupadd -r mybastion && useradd -r -g mybastion -m -d /home/mybastion -s /bin/sh mybastion

# Generate self-signed cert for guacd TLS (internal loopback encryption)
RUN /opt/mybastion/bin/mybastion generate-cert --hostname localhost --out-dir /etc/mybastion/tls

# Default config template (copied to mybastion.toml on first run if not mounted)
RUN cat > /opt/mybastion/mybastion.toml.default <<'EOF'
listen_addr = "0.0.0.0:8089"
guacd_addr = "127.0.0.1:4822"
recording_path = "/var/lib/mybastion/recordings"
static_path = "/opt/mybastion/static"
db_path = "/var/lib/mybastion/mybastion.db"
session_pending_timeout_secs = 60
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199

[tls]
cert_path = "/etc/mybastion/tls/cert.pem"
key_path = "/etc/mybastion/tls/key.pem"
guacd_cert_path = "/etc/mybastion/tls/cert.pem"

# Inherited session types, off unless switched on here.
# [web]
# enabled = true    # headless-Chromium web sessions
# [spice]
# enabled = true    # SPICE and Proxmox VE consoles

# VDI Docker desktop containers (uncomment to enable)
# Requires: -v /var/run/docker.sock:/var/run/docker.sock
# [vdi]
# enabled = true
# idle_timeout_mins = 60
# home_base = "/opt/mybastion/vdi-homes"
EOF

# Set ownership so the non-root user can write to runtime dirs.
# /etc/mybastion is chowned (not recursive) so the entrypoint can create
# mybastion.toml there; subdirs are chowned recursively for data, certs, etc.
RUN chown mybastion:mybastion /opt/mybastion /etc/mybastion && \
    chown -R mybastion:mybastion /var/lib/mybastion /var/lib/mybastion/recordings \
    /etc/mybastion/tls /opt/mybastion/certs /opt/mybastion/drives \
    /opt/mybastion/scripts /opt/mybastion/vdi-homes /opt/mybastion/mybastion.toml.default

COPY entrypoint.sh /opt/mybastion/entrypoint.sh
COPY LICENSE NOTICE /opt/mybastion/
RUN chmod +x /opt/mybastion/entrypoint.sh

WORKDIR /opt/mybastion
EXPOSE 8089
VOLUME ["/var/lib/mybastion", "/var/lib/mybastion/recordings", "/opt/mybastion/drives", "/opt/mybastion/vdi-homes"]

ENV RUST_LOG=info
ENV GUACD_LOG_LEVEL=info
ENV HOME=/home/mybastion

USER mybastion
ENV TINI_KILL_PROCESS_GROUP=1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/mybastion/entrypoint.sh"]
