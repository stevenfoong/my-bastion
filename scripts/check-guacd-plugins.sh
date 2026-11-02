#!/bin/bash
# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# Fail unless every guacd protocol plugin mybastion uses, and guacenc (which
# converts recordings to video for MP4 downloads), was built.
#
# guacd's configure quietly leaves out a protocol whose library is missing,
# even when it is asked for with --with-<protocol>, so a build machine
# without libspice-client-glib-2.0-dev produced a guacd with no SPICE and
# nothing failed: SPICE and Proxmox consoles were missing from every .deb
# from v1.9.0 to v1.11.0. Run this after `make install` in every build path.
#
# guacenc is left out the same way when an ffmpeg library is missing.
#
# Usage: check-guacd-plugins.sh <dir holding libguac-client-*.so>
# (guacenc is looked for in the sibling bin/ directory, as `make install`
# lays them out)
set -euo pipefail

dir="${1:?usage: $0 <guacd lib dir>}"
missing=()
for protocol in rdp ssh vnc spice; do
    [[ -e "$dir/libguac-client-$protocol.so.0" ]] || missing+=("$protocol")
done
[[ -x "$dir/../bin/guacenc" ]] || missing+=("guacenc")
if (( ${#missing[@]} )); then
    echo "ERROR: guacd was built without: ${missing[*]} (looked in $dir)" >&2
    echo "Install the development library for each and rebuild; configure skips them silently." >&2
    exit 1
fi
echo "guacd plugins present: rdp ssh vnc spice; guacenc present"
