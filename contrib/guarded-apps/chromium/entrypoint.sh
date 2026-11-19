#!/bin/bash
# Guarded Apps: start one locked-down Chromium on a TigerVNC display.
#
# Environment (see ../README.md):
#   START_URL          required. Page Chromium opens, e.g. https://provider.example.com
#   ALLOWED_HOSTS      comma-separated hosts the browser may reach.
#                      Default: the host of START_URL (subdomains included)
#   VNC_PASSWORD       VNC password (max 8 characters, a VNC limit), or
#   VNC_PASSWORD_FILE  a file holding it (Docker secret)
#   GEOMETRY           screen size, default 1600x900
#   IDLE_TIMEOUT       seconds before an idle VNC connection is dropped
#                      (frees the one-user lock), default 900, 0 = never
#   ALLOW_UPLOADS      "true" to allow file-picker dialogs, default false
set -euo pipefail

: "${START_URL:?START_URL is required}"
GEOMETRY=${GEOMETRY:-1600x900}
IDLE_TIMEOUT=${IDLE_TIMEOUT:-900}
ALLOW_UPLOADS=${ALLOW_UPLOADS:-false}
DISPLAY_NUM=1
VNC_PORT=5901
USER_NAME=guarded
USER_HOME=/home/${USER_NAME}
PROFILE_DIR=/data/profile
POLICY_DIR=/etc/chromium/policies/managed

run_as() {
    setpriv --reuid="${USER_NAME}" --regid="${USER_NAME}" --init-groups \
        env HOME="${USER_HOME}" USER="${USER_NAME}" DISPLAY=":${DISPLAY_NUM}" "$@"
}

# ── VNC password ────────────────────────────────────────────────────────────
if [ -n "${VNC_PASSWORD_FILE:-}" ]; then
    VNC_PASSWORD=$(cat "${VNC_PASSWORD_FILE}")
fi
: "${VNC_PASSWORD:?set VNC_PASSWORD or VNC_PASSWORD_FILE}"
install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0700 "${USER_HOME}/.vnc"
printf '%s\n' "${VNC_PASSWORD}" | vncpasswd -f > "${USER_HOME}/.vnc/passwd"
chown "${USER_NAME}:${USER_NAME}" "${USER_HOME}/.vnc/passwd"
chmod 0600 "${USER_HOME}/.vnc/passwd"
unset VNC_PASSWORD

# ── Chromium managed policies (root-owned, the user cannot change them) ────
if [ -z "${ALLOWED_HOSTS:-}" ]; then
    ALLOWED_HOSTS=$(printf '%s' "${START_URL}" | sed -E 's#^[A-Za-z]+://##; s#[/:?\#].*$##')
fi

allow_list=""
IFS=',' read -ra hosts <<< "${ALLOWED_HOSTS}"
for h in "${hosts[@]}"; do
    h=$(printf '%s' "$h" | tr -d '[:space:]')
    [ -z "$h" ] && continue
    if ! [[ "$h" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "guarded-apps: invalid host in ALLOWED_HOSTS: $h" >&2
        exit 1
    fi
    allow_list+="${allow_list:+, }\"${h}\""
done
[ -n "${allow_list}" ] || { echo "guarded-apps: ALLOWED_HOSTS is empty" >&2; exit 1; }

uploads=false
[ "${ALLOW_UPLOADS}" = "true" ] && uploads=true

install -d -m 0755 "${POLICY_DIR}"
rm -f "${POLICY_DIR}"/*.json
cp /opt/guarded/policies/*.json "${POLICY_DIR}/"
cat > "${POLICY_DIR}/90-guarded-urls.json" <<EOF
{
  "URLBlocklist": ["*"],
  "URLAllowlist": [${allow_list}],
  "AllowFileSelectionDialogs": ${uploads}
}
EOF
chown -R root:root "${POLICY_DIR}"
chmod 0644 "${POLICY_DIR}"/*.json

# ── Xvnc: one viewer at a time ──────────────────────────────────────────────
# NeverShared + DisconnectClients=0: while someone is connected, a second
# connection is refused instead of kicking the first user out.
install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0700 "${PROFILE_DIR}"
install -d -m 1777 /tmp/.X11-unix
rm -f /tmp/.X${DISPLAY_NUM}-lock /tmp/.X11-unix/X${DISPLAY_NUM}

run_as Xvnc ":${DISPLAY_NUM}" \
    -geometry "${GEOMETRY}" \
    -depth 24 \
    -rfbport "${VNC_PORT}" \
    -rfbauth "${USER_HOME}/.vnc/passwd" \
    -SecurityTypes VncAuth \
    -NeverShared \
    -DisconnectClients=0 \
    -IdleTimeout="${IDLE_TIMEOUT}" \
    -nolisten tcp &
XVNC_PID=$!

for _ in $(seq 1 50); do
    [ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] && break
    sleep 0.2
done
[ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] || { echo "guarded-apps: Xvnc did not start" >&2; exit 1; }

# ── Chromium, restarted if the user closes it ───────────────────────────────
WINDOW_SIZE=${GEOMETRY/x/,}
while kill -0 "${XVNC_PID}" 2>/dev/null; do
    # A restarted container has a new hostname; Chromium would refuse the
    # profile while the old singleton lock is there.
    rm -f "${PROFILE_DIR}"/Singleton*
    run_as chromium \
        --kiosk \
        --user-data-dir="${PROFILE_DIR}" \
        --window-position=0,0 \
        --window-size="${WINDOW_SIZE}" \
        --no-first-run \
        --no-default-browser-check \
        --noerrdialogs \
        --disable-infobars \
        --disable-session-crashed-bubble \
        --disable-features=TranslateUI,VizDisplayCompositor,MediaRouter \
        --disable-gpu \
        --disable-gpu-compositing \
        --disable-software-rasterizer \
        --disable-dev-shm-usage \
        --use-gl=angle \
        --use-angle=swiftshader \
        --in-process-gpu \
        --disable-breakpad \
        --password-store=basic \
        "${START_URL}" || true
    sleep 2
done

echo "guarded-apps: Xvnc exited" >&2
exit 1
