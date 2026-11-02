#!/usr/bin/env bash
# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
#
# install-release.sh — Install mybastion from a release tarball.
#
# This script is shipped inside the release tarball and installs
# pre-built binaries to /opt/mybastion, config and TLS to /etc/mybastion and
# data to /var/lib/mybastion, with systemd services.
#
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --no-tls
#   sudo ./install.sh --hostname=myhost.example.com
#
set -euo pipefail

PREFIX="/opt/mybastion"
CONF_DIR="/etc/mybastion"
STATE_DIR="/var/lib/mybastion"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[install]${NC} $*"; }
error() { echo -e "${RED}[install]${NC} $*" >&2; }

NO_TLS=0
TLS_HOSTNAME=""
for arg in "$@"; do
    case "$arg" in
        --no-tls)      NO_TLS=1 ;;
        --hostname=*)  TLS_HOSTNAME="${arg#--hostname=}" ;;
        -h|--help)
            echo "Usage: sudo $0 [--no-tls] [--hostname=FQDN]"
            echo ""
            echo "Options:"
            echo "  --no-tls          Skip TLS certificate generation (plain HTTP only)"
            echo "  --hostname=FQDN   Hostname for the TLS certificate (default: system hostname)"
            exit 0
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create system user
# ---------------------------------------------------------------------------
if ! id -u mybastion >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /home/mybastion --shell /usr/sbin/nologin mybastion
    info "Created system user 'mybastion'"
else
    info "System user 'mybastion' already exists"
fi

# ---------------------------------------------------------------------------
# Step 2: Install files
# ---------------------------------------------------------------------------
info "Installing mybastion to $PREFIX..."

mkdir -p "$PREFIX"/{bin,sbin,lib,static} "$CONF_DIR/tls" "$STATE_DIR/recordings"

# Binaries
install -m 755 "$SCRIPT_DIR/bin/mybastion" "$PREFIX/bin/mybastion"
install -m 755 "$SCRIPT_DIR/sbin/guacd"   "$PREFIX/sbin/guacd"
# guacenc converts recordings to video for MP4 downloads (absent from
# tarballs built before 1.11.1)
[[ -f "$SCRIPT_DIR/bin/guacenc" ]] && install -m 755 "$SCRIPT_DIR/bin/guacenc" "$PREFIX/bin/guacenc"

# Libraries
cp -a "$SCRIPT_DIR/lib/"*.so* "$PREFIX/lib/"

# Static web assets
cp -r "$SCRIPT_DIR/static/"* "$PREFIX/static/"

# Licence and attribution (Apache-2.0 requires NOTICE to travel with the work)
install -m 644 "$SCRIPT_DIR/LICENSE" "$SCRIPT_DIR/NOTICE" "$PREFIX/"

# Drive setup script (if present)
if [[ -d "$SCRIPT_DIR/scripts" ]]; then
    cp -r "$SCRIPT_DIR/scripts/"* "$PREFIX/bin/"
    chmod +x "$PREFIX/bin/"*.sh 2>/dev/null || true
fi

# Default config (don't overwrite existing)
if [[ ! -f "$CONF_DIR/mybastion.toml" ]]; then
    cp "$SCRIPT_DIR/mybastion.toml.default" "$CONF_DIR/mybastion.toml"

    if [[ $NO_TLS -eq 0 ]]; then
        # mybastion.toml.default already has [tls] section
        info "Created config at $CONF_DIR/mybastion.toml (TLS enabled)"
    else
        # Remove TLS section for plain HTTP
        sed -i '/^\[tls\]/,$d' "$CONF_DIR/mybastion.toml"
        sed -i 's/listen_addr = .*/listen_addr = "0.0.0.0:8089"/' "$CONF_DIR/mybastion.toml"
        info "Created config at $CONF_DIR/mybastion.toml (plain HTTP)"
    fi
else
    info "Config already exists at $CONF_DIR/mybastion.toml (not overwritten)"
fi

chown -R mybastion:mybastion "$STATE_DIR"
chown root:mybastion "$CONF_DIR" "$CONF_DIR/mybastion.toml"
chmod 750 "$CONF_DIR"
chmod 640 "$CONF_DIR/mybastion.toml"

# ---------------------------------------------------------------------------
# Step 3: ldconfig
# ---------------------------------------------------------------------------
echo "$PREFIX/lib" > /etc/ld.so.conf.d/mybastion.conf
ldconfig
info "Library path configured"

# ---------------------------------------------------------------------------
# Step 4: systemd services
# ---------------------------------------------------------------------------
info "Installing systemd services..."
cp "$SCRIPT_DIR/systemd/mybastion.service"       /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/mybastion-guacd.service"  /etc/systemd/system/

systemctl daemon-reload
systemctl enable mybastion-guacd.service
systemctl enable mybastion.service

info "Systemd services installed and enabled"

# ---------------------------------------------------------------------------
# Step 5: TLS certificate
# ---------------------------------------------------------------------------
if [[ $NO_TLS -eq 0 ]]; then
    if [[ -f "$CONF_DIR/tls/cert.pem" && -f "$CONF_DIR/tls/key.pem" ]]; then
        info "TLS certificates already exist (not overwritten)"
    else
        CERT_HOSTNAME="${TLS_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
        info "Generating self-signed TLS certificate for: $CERT_HOSTNAME"
        "$PREFIX/bin/mybastion" generate-cert \
            --hostname "$CERT_HOSTNAME" \
            --out-dir "$CONF_DIR/tls"
        chown -R mybastion:mybastion "$CONF_DIR/tls"
        chmod 600 "$CONF_DIR/tls/key.pem"
        chmod 644 "$CONF_DIR/tls/cert.pem"
        info "TLS certificate generated at $CONF_DIR/tls/"
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "============================================"
info "  mybastion installed to $PREFIX"
info "============================================"
echo ""
info "Next steps:"
info "  1. Create an admin:"
info "     $PREFIX/bin/mybastion --config $CONF_DIR/mybastion.toml add-admin --name admin"
info ""
info "  2. (Optional) Set up encrypted file transfer:"
info "     sudo $PREFIX/bin/drive-setup.sh"
info ""
info "  3. Start the services:"
info "     sudo systemctl start mybastion"
echo ""
if [[ $NO_TLS -eq 0 ]]; then
    info "  4. Open in browser:"
    info "     https://$(hostname -f 2>/dev/null || hostname)"
    info ""
    warn "  Using self-signed cert — browser will show a warning."
    warn "  Replace $CONF_DIR/tls/cert.pem and key.pem with real certs for production."
else
    info "  4. Open in browser:"
    info "     http://localhost:8089"
fi
echo ""
