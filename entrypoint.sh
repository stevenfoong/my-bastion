#!/bin/bash
# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# Entrypoint script: starts guacd and mybastion in the background. tini (PID 1)
# passes stop signals to both. If either one exits, the other is stopped and
# the container exits with that status, so a restart policy can bring it back
# rather than leaving mybastion running without guacd.
set -e

# Copy default config on first run (if no config file is mounted/present)
CONFIG_PATH="/etc/mybastion/mybastion.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No mybastion.toml found — copying default configuration."
    cp /opt/mybastion/mybastion.toml.default "$CONFIG_PATH"
fi

# Create an admin API key on first run. mybastion decides what "first run"
# means: it opens the database named by db_path in the config and creates
# the admin only if there is none yet. Checking for a database file at a fixed
# path here broke any config that moved db_path: every restart then tried to
# create the admin again and failed on the existing one (#240).
ADMIN_OUT=$(/opt/mybastion/bin/mybastion --config "$CONFIG_PATH" add-admin --name docker-admin --if-none)
echo "$ADMIN_OUT"
case "$ADMIN_OUT" in
    *"API Key:"*)
        echo ""
        echo "==> SAVE THE API KEY ABOVE — it is only shown once! <=="
        echo ""
        ;;
esac

# Start guacd in background
echo "Starting guacd..."
LD_LIBRARY_PATH=/opt/mybastion/lib FREERDP_ADDIN_PATH=/opt/mybastion/lib/freerdp3 \
    /opt/mybastion/sbin/guacd \
    -b 127.0.0.1 -l 4822 -L "${GUACD_LOG_LEVEL:-info}" -f \
    -C /etc/mybastion/tls/cert.pem -K /etc/mybastion/tls/key.pem &
GUACD_PID=$!

# Wait briefly to confirm guacd started
sleep 0.5
if ! kill -0 "$GUACD_PID" 2>/dev/null; then
    echo "ERROR: guacd failed to start"
    exit 1
fi
echo "guacd started (pid=$GUACD_PID)"


echo "Starting mybastion..."
/opt/mybastion/bin/mybastion --config "$CONFIG_PATH" serve &
MYBASTION_PID=$!

# Wait for whichever exits first, then stop the other.
set +e
wait -n "$GUACD_PID" "$MYBASTION_PID"
STATUS=$?
if ! kill -0 "$GUACD_PID" 2>/dev/null; then
    echo "guacd exited (status $STATUS), stopping mybastion"
else
    echo "mybastion exited (status $STATUS), stopping guacd"
fi
kill "$GUACD_PID" "$MYBASTION_PID" 2>/dev/null
wait
exit "$STATUS"
