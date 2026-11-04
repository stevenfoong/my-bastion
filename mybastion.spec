# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# RPM spec for mybastion — lightweight Rust replacement for Apache Guacamole.
#
# This spec expects pre-built binaries (build-rpm.sh does compilation before
# rpmbuild runs). The _builddir macro is pointed at the repo checkout so
# install phase can find everything in place.
#
# Target: Rocky Linux 9 / RHEL 9 / AlmaLinux 9
# Requires EPEL for: ffmpeg-libs, libtelnet, libwebsockets, chromium

%global _prefix /opt/mybastion
%global confdir /etc/mybastion
%global statedir /var/lib/mybastion

Name:           mybastion
Version:        %{_version}
Release:        1%{?dist}
Summary:        Lightweight Rust replacement for Apache Guacamole client
License:        Apache-2.0
URL:            https://github.com/stevenfoong/my-bastion

BuildRequires:  systemd-rpm-macros

Requires:       cairo
Requires:       libjpeg-turbo
Requires:       libpng
Requires:       libwebp
Requires:       libssh2
Requires:       openssl-libs
Requires:       libvncserver
Requires:       pango
Requires:       pulseaudio-libs
Requires:       ffmpeg-libs
Requires:       libtelnet
Requires:       libwebsockets
Requires:       freerdp-libs
Requires:       ca-certificates

Recommends:     tigervnc-server
Recommends:     chromium
Recommends:     xorg-x11-utils
Recommends:     cryptsetup

%description
mybastion is a lightweight Rust replacement for the Apache Guacamole Java
webapp. It proxies the Guacamole protocol over WebSockets between web
browsers and guacd (the C daemon from guacamole-server). Supports SSH,
VNC, RDP, and web browser sessions (headless Chromium on Xvnc).

# Nothing to unpack or compile — build-rpm.sh handles everything.
%prep

%build

%install
rm -rf %{buildroot}

# Directory structure
install -d %{buildroot}%{_prefix}/bin
install -d %{buildroot}%{_prefix}/sbin
install -d %{buildroot}%{_prefix}/lib
install -d %{buildroot}%{_prefix}/static
install -d %{buildroot}%{_prefix}/static/guac
install -d %{buildroot}%{statedir}/recordings
install -d %{buildroot}%{confdir}/tls
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/ld.so.conf.d

# mybastion binary
install -m 755 target/release/mybastion %{buildroot}%{_prefix}/bin/mybastion

# Database proxy (built by build-rpm.sh: cd dbproxy && go build)
install -m 755 dbproxy/mybastion-dbproxy %{buildroot}%{_prefix}/bin/mybastion-dbproxy

# Drive setup helper script
install -m 755 scripts/drive-setup.sh %{buildroot}%{_prefix}/bin/drive-setup.sh

# guacd binary and libraries from staging
install -m 755 rpm/staging%{_prefix}/sbin/guacd %{buildroot}%{_prefix}/sbin/guacd
cp -a rpm/staging%{_prefix}/lib/*.so* %{buildroot}%{_prefix}/lib/

# FreeRDP plugin for RDPDR/RDPSND channels (drive redirection, audio, printing)
install -d %{buildroot}%{_libdir}/freerdp3
cp -a rpm/staging%{_libdir}/freerdp3/*.so* %{buildroot}%{_libdir}/freerdp3/ 2>/dev/null || true

# Static web assets
cp -r static/* %{buildroot}%{_prefix}/static/

# Default config — reuse the debian default (no duplication)
install -m 644 debian/mybastion.toml.default %{buildroot}%{confdir}/mybastion.toml

# Systemd units — reuse the debian service files (no duplication)
install -m 644 debian/mybastion.service %{buildroot}%{_unitdir}/mybastion.service
install -m 644 debian/mybastion-guacd.service %{buildroot}%{_unitdir}/mybastion-guacd.service
install -m 644 debian/mybastion-dbproxy.service %{buildroot}%{_unitdir}/mybastion-dbproxy.service

# ldconfig drop-in so guacd can find its libs
echo "%{_prefix}/lib" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/mybastion.conf

%pre
# Create mybastion system user with a real home directory (Chromium needs it)
if ! getent passwd mybastion >/dev/null 2>&1; then
    useradd -r -m -d /home/mybastion -s /sbin/nologin -c "mybastion service account" mybastion
fi

%post
chown -R mybastion:mybastion %{statedir}
# Key-encryption key for the SQLite secret store (created once, never overwritten)
if [ ! -f %{confdir}/kek ]; then
    (umask 277; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > %{confdir}/kek)
    chown mybastion:mybastion %{confdir}/kek
fi
# Shared secret between the core and the database proxy (created once)
if [ ! -f %{confdir}/dbproxy-secret ]; then
    (umask 227; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > %{confdir}/dbproxy-secret)
    chown root:mybastion %{confdir}/dbproxy-secret
fi
# Generate self-signed TLS certificate if none exists
if [ ! -f %{confdir}/tls/cert.pem ] || [ ! -f %{confdir}/tls/key.pem ]; then
    CERT_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    echo "Generating self-signed TLS certificate for ${CERT_HOSTNAME}..."
    %{_prefix}/bin/mybastion generate-cert \
        --hostname "$CERT_HOSTNAME" \
        --out-dir %{confdir}/tls
    chmod 600 %{confdir}/tls/key.pem
    chmod 644 %{confdir}/tls/cert.pem
fi
chown -R mybastion:mybastion %{confdir}/tls
/sbin/ldconfig
%systemd_post mybastion.service mybastion-guacd.service
echo ""
echo "  To set up encrypted file transfer (LUKS drive), run:"
echo "    sudo %{_prefix}/bin/drive-setup.sh"
echo ""

%preun
%systemd_preun mybastion.service mybastion-guacd.service mybastion-dbproxy.service

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then
    # Full uninstall — clean up
    rm -rf %{_prefix}
    userdel -r mybastion 2>/dev/null || true
fi
%systemd_postun_with_restart mybastion.service mybastion-guacd.service

%files
%license debian/copyright LICENSE NOTICE
%dir %{_prefix}
%{_prefix}/bin/mybastion
%{_prefix}/bin/mybastion-dbproxy
%{_prefix}/bin/drive-setup.sh
%{_prefix}/sbin/guacd
%{_prefix}/lib/*.so*
%{_libdir}/freerdp3/
%{_prefix}/static/
%dir %attr(0750,root,mybastion) %{confdir}
%config(noreplace) %attr(0640,root,mybastion) %{confdir}/mybastion.toml
%dir %attr(0750,mybastion,mybastion) %{confdir}/tls
%dir %attr(0750,mybastion,mybastion) %{statedir}
%dir %attr(0750,mybastion,mybastion) %{statedir}/recordings
%{_unitdir}/mybastion.service
%{_unitdir}/mybastion-guacd.service
%{_unitdir}/mybastion-dbproxy.service
%{_sysconfdir}/ld.so.conf.d/mybastion.conf
