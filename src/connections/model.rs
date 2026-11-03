// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Data types: connection entries, folder access config, and what users are shown.

use super::*;
use serde::{Deserialize, Serialize};

use crate::tunnel;

/// Folder access configuration stored at `<folder>/.config` in Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderConfig {
    pub allowed_groups: Vec<String>,
    /// Users granted access by login email, in addition to `allowed_groups`.
    /// Compared without regard to case. A user need not have logged in yet:
    /// access is decided from their identity at the time they ask. Omitted
    /// from the stored config when empty, so existing configs are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// Human-readable title shown instead of the folder key (e.g. the NetBox
    /// tenant name over its sanitised key). Omitted from the stored config
    /// when empty, so existing configs are unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// When true, if the folder's own `allowed_groups` doesn't grant access,
    /// the access check walks up the parent path and tries each ancestor's
    /// config. New folders default to `true` in the UI; legacy configs
    /// deserialise as `false` so existing deployments keep their
    /// per-folder-only semantics until an admin opts in.
    #[serde(default)]
    pub inherit_from_parent: bool,
}

/// Who is asking for access to a folder: their login email (absent for API
/// keys, which are admins and never get here) and their OIDC groups.
#[derive(Debug, Clone, Copy)]
pub struct FolderSubject<'a> {
    pub email: Option<&'a str>,
    pub groups: &'a [String],
}

impl FolderConfig {
    /// Whether exactly the parent's audience can open this folder: it
    /// inherits the parent's access and grants nobody of its own. Only then
    /// may the parent's `.defaults` flow into it; access is a union, so a
    /// folder that inherits and also has `allowed_groups` / `allowed_users`
    /// admits people the parent does not.
    pub fn shares_parent_audience(&self) -> bool {
        self.inherit_from_parent && self.allowed_groups.is_empty() && self.allowed_users.is_empty()
    }

    /// Whether this folder's own settings let `who` in: a shared group, or
    /// their email in `allowed_users`. Inheritance is the caller's concern.
    pub fn grants(&self, who: FolderSubject<'_>) -> bool {
        if self
            .allowed_groups
            .iter()
            .any(|g| who.groups.iter().any(|ug| ug == g))
        {
            return true;
        }
        match who.email.map(str::trim) {
            Some(email) if !email.is_empty() => self
                .allowed_users
                .iter()
                .any(|u| u.trim().eq_ignore_ascii_case(email)),
            _ => false,
        }
    }
}

/// A connection entry stored in Vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressBookEntry {
    #[serde(rename = "type")]
    pub session_type: String, // "ssh", "rdp", "vnc", "web"
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub url: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    /// RDP server keyboard layout (guacd `server-layout`, e.g. "en-gb-qwerty").
    /// None/empty lets guacd use its default (en-us-qwerty).
    pub server_layout: Option<String>,
    pub ignore_cert: Option<bool>,
    pub display_name: Option<String>,
    /// Override drive/file transfer setting for this entry.
    pub enable_drive: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Whether to prompt for credentials at connect time (even if stored creds exist).
    pub prompt_credentials: Option<bool>,
    /// VNC color depth (8, 16, 24, 32). Default: 24.
    pub color_depth: Option<u8>,
    /// Multi-hop SSH tunnel jump hosts (ordered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_hosts: Option<Vec<tunnel::JumpHost>>,
    /// Legacy: single SSH tunnel jump host (migrated to jump_hosts on read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_host: Option<String>,
    /// Legacy: SSH tunnel jump port (default: 22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_port: Option<u16>,
    /// Legacy: SSH tunnel jump username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_username: Option<String>,
    /// Legacy: SSH tunnel jump password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_password: Option<String>,
    /// Legacy: SSH tunnel jump private key (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_private_key: Option<String>,
    /// RDP RemoteApp program path (RAIL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app: Option<String>,
    /// RDP RemoteApp working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app_dir: Option<String>,
    /// RDP RemoteApp command-line arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app_args: Option<String>,
    /// Override recording enabled/disabled for this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_recording: Option<bool>,
    /// Maximum number of recordings to keep for this entry (0 = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recordings: Option<u32>,
    /// Enable SSH typescript recording for this entry (#159). Default off
    /// (per-connection opt-in). Only effective for SSH sessions and only
    /// when `[recording].typescript_path` is configured globally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_typescript: Option<bool>,
    /// Login script filename (relative to login_scripts_dir) to run after browser spawns.
    /// Only applicable to web sessions. The script receives CDP port and credentials
    /// via environment variables and stdin JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_script: Option<String>,
    /// Autofill credentials for web sessions. JSON array of objects:
    /// [{"url": "https://example.com", "username": "$USERNAME", "password": "$PASSWORD"}]
    /// $USERNAME and $PASSWORD are substituted from the entry's credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofill: Option<String>,
    /// Allowed domains for web sessions. When set, Chromium can only reach
    /// these domains (plus localhost). Uses --host-rules to block all others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// VNC: resize the server's screen to the browser window. Off unless set:
    /// only servers with a virtual screen (Xvnc, TigerVNC) can resize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vnc_resize: Option<bool>,
    /// VNC network preset: `auto`, `lan`, `wan` or `slow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vnc_network: Option<String>,
    /// Disable clipboard copy (server → client). Prevents copying from the remote session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server). Prevents pasting into the remote session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_paste: Option<bool>,
    /// Optional banner text shown before the session starts. User must click Continue to proceed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Enable RDP Graphics Pipeline Extension (GFX). Enables RemoteFX codec for better video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM). Improves video overlay rendering in RDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_desktop_composition: Option<bool>,
    /// Show the remote desktop wallpaper. Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (visual styles). Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging. Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_full_window_drag: Option<bool>,
    /// Force lossless encoding (PNG only). Better for text-heavy, low-bandwidth sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough. Passes raw H.264 from xrdp to browser WebCodecs decoder.
    /// Requires GFX enabled and xrdp with x264 on the target. Default: true when GFX enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_h264: Option<bool>,
    /// Docker image for VDI sessions (e.g. "myregistry/desktop:latest").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    /// CPU limit override for VDI container (fractional cores). Uses config default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_cpu_limit: Option<f64>,
    /// Memory limit override for VDI container in MB. Uses config default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_memory_limit: Option<u64>,
    /// Extra environment variables for VDI container (key=value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Override idle timeout for VDI container in minutes. Uses global default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_idle_timeout_mins: Option<u64>,
    /// Optional fixed username for the VDI container's RDP login. When set,
    /// mybastion uses this username for the RDP connect into the container
    /// instead of deriving one from the operator's identity. Useful when the
    /// container image has a baked-in user that doesn't honour the
    /// VDI_USERNAME env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_username: Option<String>,
    /// Optional fixed password matching `container_username`. When set,
    /// mybastion uses this password for the RDP connect instead of
    /// generating an ephemeral one. Stored in Vault alongside the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_password: Option<String>,
    /// Allow users to generate a Share URL for sessions from this entry.
    /// Default: false (admin must opt in per entry). Gates the Share
    /// button in the Connections Active Sessions card — when `false`,
    /// `SessionInfo.share_url` is serialised as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sharing: Option<bool>,
    /// GitHub #103: when true and this is the calling user's ONLY visible
    /// entry, the Connections page auto-connects to it on first load.
    /// Admin opt-in per entry. No effect for users with more than one
    /// visible entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_open_if_singleton: Option<bool>,
    /// GitHub #154: when true, the client enters fullscreen on first user
    /// gesture after connect and locks the Escape key (Chromium) so it
    /// reaches the remote session instead of exiting fullscreen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fullscreen_on_connect: Option<bool>,
    /// When true, the clipboard/files side tabs auto-hide when idle and
    /// reappear when the pointer nears the left edge of the display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autohide_side_tabs: Option<bool>,
    /// SPICE: connect using TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_tls: Option<bool>,
    /// SPICE: TLS port (if the encrypted port differs from `port`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_tls_port: Option<u16>,
    /// SPICE: PEM CA certificate for verifying the server TLS (e.g. a Proxmox cluster CA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_ca_cert: Option<String>,
    /// SPICE: expected TLS certificate subject (Proxmox "host-subject").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_cert_subject: Option<String>,
    /// SPICE: proxy URL, e.g. a Proxmox SPICE proxy "http://host:3128".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_proxy: Option<String>,
    /// Proxmox VE console: PVE API base URL, full URL incl. scheme + port
    /// (e.g. "https://pve.example.com:8006").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_url: Option<String>,
    /// Proxmox node name hosting the VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_node: Option<String>,
    /// Proxmox VM id (QEMU) whose console to open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_vmid: Option<u32>,
    /// Proxmox API token id ("user@realm!tokenname") — non-secret, shown in the
    /// UI (User column).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_token_id: Option<String>,
    /// Proxmox API token secret (UUID). Credential — never returned to the
    /// browser (see EntryInfo::has_proxmox_token_secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_token_secret: Option<String>,
    /// Verify the PVE API + SPICE-proxy TLS certificate (default false; PVE
    /// ships a self-signed cluster cert).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_verify_tls: Option<bool>,
    /// Total number of monitors to offer for SPICE/Proxmox multi-monitor
    /// (default 1 = single monitor). guacd is told `secondary-monitors =
    /// max_monitors - 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_monitors: Option<u32>,
    /// SSH terminal font size in points (default: 12). Only applies to SSH
    /// sessions. Lets operators tune readability independently of display DPI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_font_size: Option<u32>,
    /// Wake-on-LAN: send a magic packet to wake the target before connecting.
    /// Passed through to guacd's `wol-send-packet` param (SSH/RDP/VNC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_send_packet: Option<bool>,
    /// Wake-on-LAN: target MAC address (e.g. "00:11:22:33:44:55"). Required
    /// when `wol_send_packet` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_mac_addr: Option<String>,
    /// Wake-on-LAN: broadcast address to send the magic packet to
    /// (default guacd value: 255.255.255.255).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_broadcast_addr: Option<String>,
    /// Wake-on-LAN: UDP port for the magic packet (default guacd value: 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_udp_port: Option<u16>,
    /// Wake-on-LAN: seconds to wait after sending the packet before attempting
    /// to connect, giving the host time to boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_wait_time: Option<u32>,
    /// Stable id of the record this entry is synced from, set by the source
    /// (the NetBox webhook sends `netbox:device:<id>`). `PUT ...?move=true`
    /// matches an existing entry on this, never on its name, so a device
    /// that changes folder or name is moved rather than duplicated. Never
    /// used to connect. Preserved on update when the request omits it, as
    /// the edit form does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl AddressBookEntry {
    /// Migrate legacy flat jump_host fields into the jump_hosts array.
    /// If `jump_hosts` is already set, this is a no-op.
    pub fn normalize_jump_hosts(&mut self) {
        if self.jump_hosts.is_some() {
            return;
        }
        if let Some(ref host) = self.jump_host {
            if !host.is_empty() {
                self.jump_hosts = Some(vec![tunnel::JumpHost {
                    hostname: host.clone(),
                    port: self.jump_port.unwrap_or(22),
                    username: self.jump_username.clone().unwrap_or_default(),
                    password: self.jump_password.clone(),
                    private_key: self.jump_private_key.clone(),
                    host_key: None,
                }]);
            }
        }
        // Clear legacy fields so they don't get written back
        self.jump_host = None;
        self.jump_port = None;
        self.jump_username = None;
        self.jump_password = None;
        self.jump_private_key = None;
    }
}

/// Entry metadata returned to non-admin users (credentials stripped).
#[derive(Debug, Clone, Serialize)]
pub struct EntryInfo {
    pub name: String,
    pub session_type: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub display_name: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    pub ignore_cert: Option<bool>,
    pub enable_drive: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Whether to prompt for credentials at connect time.
    pub prompt_credentials: Option<bool>,
    /// Whether the entry can authenticate without prompting: a stored
    /// password or private key of its own, or folder defaults for its type.
    pub has_credentials: bool,
    /// True when `has_credentials` comes from folder defaults rather than
    /// the entry itself. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub inherited_credentials: bool,
    /// VNC color depth.
    pub color_depth: Option<u8>,
    /// SSH tunnel jump hosts (no credentials exposed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_hosts: Option<Vec<tunnel::JumpHostInfo>>,
    /// RDP RemoteApp program path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app: Option<String>,
    /// RDP RemoteApp working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app_dir: Option<String>,
    /// RDP RemoteApp command-line arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app_args: Option<String>,
    /// Override recording enabled/disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_recording: Option<bool>,
    /// Maximum recordings to keep for this entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_recordings: Option<u32>,
    /// Enable SSH typescript recording for this entry (#159).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_typescript: Option<bool>,
    /// Login script filename (web sessions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_script: Option<String>,
    /// Autofill credentials JSON (web sessions only). Contains $PASSWORD placeholders, not actual values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autofill: Option<String>,
    /// Allowed domains for web sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// VNC: resize the server's screen to the browser window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnc_resize: Option<bool>,
    /// VNC network preset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnc_network: Option<String>,
    /// Disable clipboard copy (server → client).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_paste: Option<bool>,
    /// Banner text shown before session starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Credential variable names referenced by this entry (e.g. ["corp_user", "corp_password"]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credential_variables: Vec<String>,
    /// Enable RDP Graphics Pipeline Extension (GFX).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_desktop_composition: Option<bool>,
    /// Show the remote desktop wallpaper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (visual styles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_full_window_drag: Option<bool>,
    /// Force lossless encoding (PNG only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_h264: Option<bool>,
    /// Docker image for VDI sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    /// CPU limit for VDI container (cores, e.g. 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_cpu_limit: Option<f64>,
    /// Memory limit for VDI container (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_memory_limit: Option<u64>,
    /// Environment variables to inject into the VDI container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Idle timeout for VDI container in minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_idle_timeout_mins: Option<u64>,
    /// Optional fixed VDI container username (for images with baked-in
    /// accounts that don't honour VDI_USERNAME).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_username: Option<String>,
    /// Whether a fixed VDI container password is stored on this entry.
    /// The actual value is never serialised back to clients.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_container_password: bool,
    /// Whether users can generate Share URLs for sessions of this entry.
    /// Defaults to false — admin must opt in per entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_sharing: Option<bool>,
    /// Auto-open on login when this is the user's only visible entry (#103).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_open_if_singleton: Option<bool>,
    /// Open the client in fullscreen on connect (#154).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fullscreen_on_connect: Option<bool>,
    /// Auto-hide the clipboard/files side tabs when idle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autohide_side_tabs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_tls_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_vmid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_verify_tls: Option<bool>,
    /// Proxmox token id (non-secret; shown in the User column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_token_id: Option<String>,
    /// Whether a Proxmox token secret is stored (the secret itself is never
    /// returned; the UI shows "leave blank to keep").
    pub has_proxmox_token_secret: bool,
    /// Total monitors offered (SPICE/Proxmox multi-monitor); 1 = single.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_monitors: Option<u32>,
    /// SSH terminal font size in points (SSH only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_font_size: Option<u32>,
    /// Wake-on-LAN: send a magic packet before connecting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_send_packet: Option<bool>,
    /// Wake-on-LAN: target MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_mac_addr: Option<String>,
    /// Wake-on-LAN: broadcast address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_broadcast_addr: Option<String>,
    /// Wake-on-LAN: UDP port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_udp_port: Option<u16>,
    /// Wake-on-LAN: wait time (seconds) after sending the packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_wait_time: Option<u32>,
    /// Stable id of the record this entry is synced from (see
    /// `AddressBookEntry::external_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl EntryInfo {
    /// Mark an entry as connectable through folder defaults when it has no
    /// secret of its own and the defaults cover its session type.
    pub fn apply_inherited(&mut self, e: &AddressBookEntry, defaults: Option<&FolderDefaults>) {
        // An entry with secrets of its own, or one set to prompt, never uses
        // the folder's, so it must not be labelled as if it did.
        if self.has_credentials || !entry_takes_folder_defaults(e) {
            return;
        }
        if let Some(d) = defaults.and_then(|d| d.get(&e.session_type)) {
            if d.has_secret() {
                self.has_credentials = true;
                self.inherited_credentials = true;
            }
        }
    }
}

impl From<(&str, &AddressBookEntry)> for EntryInfo {
    fn from((name, e): (&str, &AddressBookEntry)) -> Self {
        let jump_hosts = e.jump_hosts.as_ref().map(|hops| {
            hops.iter()
                .map(|h| tunnel::JumpHostInfo {
                    hostname: h.hostname.clone(),
                    port: h.port,
                    username: h.username.clone(),
                    host_key_fingerprint: h
                        .host_key
                        .as_ref()
                        .and_then(|k| tunnel::fingerprint_openssh_key(k).ok()),
                })
                .collect()
        });
        Self {
            name: name.to_string(),
            session_type: e.session_type.clone(),
            hostname: e.hostname.clone(),
            port: e.port,
            username: e.username.clone(),
            url: e.url.clone(),
            display_name: e.display_name.clone(),
            domain: e.domain.clone(),
            security: e.security.clone(),
            ignore_cert: e.ignore_cert,
            enable_drive: e.enable_drive,
            auth_pkg: e.auth_pkg.clone(),
            kdc_url: e.kdc_url.clone(),
            prompt_credentials: e.prompt_credentials,
            has_credentials: entry_has_own_credentials(e),
            inherited_credentials: false,
            color_depth: e.color_depth,
            jump_hosts,
            remote_app: e.remote_app.clone(),
            remote_app_dir: e.remote_app_dir.clone(),
            remote_app_args: e.remote_app_args.clone(),
            enable_recording: e.enable_recording,
            max_recordings: e.max_recordings,
            record_typescript: e.record_typescript,
            login_script: e.login_script.clone(),
            autofill: e.autofill.clone(),
            allowed_domains: e.allowed_domains.clone(),
            vnc_resize: e.vnc_resize,
            vnc_network: e.vnc_network.clone(),
            disable_copy: e.disable_copy,
            disable_paste: e.disable_paste,
            banner: e.banner.clone(),
            credential_variables: entry_credential_variables(e),
            enable_gfx: e.enable_gfx,
            enable_desktop_composition: e.enable_desktop_composition,
            enable_wallpaper: e.enable_wallpaper,
            enable_theming: e.enable_theming,
            enable_full_window_drag: e.enable_full_window_drag,
            force_lossless: e.force_lossless,
            enable_h264: e.enable_h264,
            container_image: e.container_image.clone(),
            container_cpu_limit: e.container_cpu_limit,
            container_memory_limit: e.container_memory_limit,
            container_env: e.container_env.clone(),
            container_idle_timeout_mins: e.container_idle_timeout_mins,
            container_username: e.container_username.clone(),
            has_container_password: e.container_password.as_ref().is_some_and(|p| !p.is_empty()),
            allow_sharing: e.allow_sharing,
            auto_open_if_singleton: e.auto_open_if_singleton,
            fullscreen_on_connect: e.fullscreen_on_connect,
            autohide_side_tabs: e.autohide_side_tabs,
            spice_tls: e.spice_tls,
            spice_tls_port: e.spice_tls_port,
            spice_ca_cert: e.spice_ca_cert.clone(),
            spice_cert_subject: e.spice_cert_subject.clone(),
            spice_proxy: e.spice_proxy.clone(),
            proxmox_url: e.proxmox_url.clone(),
            proxmox_node: e.proxmox_node.clone(),
            proxmox_vmid: e.proxmox_vmid,
            proxmox_verify_tls: e.proxmox_verify_tls,
            proxmox_token_id: e.proxmox_token_id.clone(),
            has_proxmox_token_secret: e
                .proxmox_token_secret
                .as_ref()
                .is_some_and(|t| !t.is_empty()),
            max_monitors: e.max_monitors,
            ssh_font_size: e.ssh_font_size,
            wol_send_packet: e.wol_send_packet,
            wol_mac_addr: e.wol_mac_addr.clone(),
            wol_broadcast_addr: e.wol_broadcast_addr.clone(),
            wol_udp_port: e.wol_udp_port,
            wol_wait_time: e.wol_wait_time,
            external_id: e.external_id.clone(),
        }
    }
}

/// Folder info returned to users.
#[derive(Debug, Clone, Serialize)]
pub struct FolderInfo {
    pub name: String,
    pub description: String,
    /// Title to show for the folder; empty when none is set (show the name).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// "shared" or "instance"
    pub scope: String,
    /// Full path from scope root (e.g. "Clients/Acme"). Same as name for top-level folders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Whether this folder has subfolders (for lazy tree loading).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_children: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_config_display_name_is_optional_in_storage() {
        // A config written before display names existed must still load, and
        // a folder without one must be stored exactly as before, so existing
        // Vault .config documents are untouched by the feature.
        let legacy: FolderConfig =
            serde_json::from_str(r#"{"allowed_groups":["ops"],"description":"Acme"}"#).unwrap();
        assert_eq!(legacy.display_name, "");
        let stored = serde_json::to_value(&legacy).unwrap();
        assert!(
            stored.get("display_name").is_none(),
            "an empty display name is omitted from the stored config"
        );

        let mut named = legacy.clone();
        named.display_name = "Dani & Fiori's Gourmet Pizzeria".to_string();
        let stored = serde_json::to_value(&named).unwrap();
        assert_eq!(
            stored["display_name"],
            serde_json::json!("Dani & Fiori's Gourmet Pizzeria")
        );
        let back: FolderConfig = serde_json::from_value(stored).unwrap();
        assert_eq!(back.display_name, named.display_name);
        assert_eq!(back.description, "Acme");
    }

    fn cfg(groups: &[&str], users: &[&str]) -> FolderConfig {
        FolderConfig {
            allowed_groups: groups.iter().map(|s| s.to_string()).collect(),
            allowed_users: users.iter().map(|s| s.to_string()).collect(),
            description: String::new(),
            display_name: String::new(),
            inherit_from_parent: false,
        }
    }

    fn who<'a>(email: Option<&'a str>, groups: &'a [String]) -> FolderSubject<'a> {
        FolderSubject { email, groups }
    }

    #[test]
    fn folder_grants_by_group_or_user() {
        let ops = vec!["ops".to_string()];
        let none: Vec<String> = vec![];
        let c = cfg(&["ops"], &["jsmith@example.com"]);
        assert!(c.grants(who(Some("someone@example.com"), &ops)), "group");
        assert!(c.grants(who(Some("jsmith@example.com"), &none)), "user");
        assert!(
            c.grants(who(Some("JSmith@Example.COM"), &none)),
            "case-insensitive"
        );
        assert!(!c.grants(who(Some("other@example.com"), &none)));
    }

    #[test]
    fn folder_user_grant_needs_a_real_email() {
        let none: Vec<String> = vec![];
        let c = cfg(&[], &["jsmith@example.com"]);
        assert!(!c.grants(who(None, &none)), "no identity email");
        assert!(!c.grants(who(Some(""), &none)), "empty email");
        // An empty or blank entry in the list must not match a blank email.
        let blank = cfg(&[], &["", "  "]);
        assert!(!blank.grants(who(Some(" "), &none)));
    }

    #[test]
    fn empty_folder_config_grants_nobody() {
        let ops = vec!["ops".to_string()];
        assert!(!cfg(&[], &[]).grants(who(Some("jsmith@example.com"), &ops)));
    }

    /// Configs written before allowed_users existed still load, and a config
    /// with no users is stored exactly as before.
    #[test]
    fn folder_config_allowed_users_is_backward_compatible() {
        let old: FolderConfig =
            serde_json::from_str(r#"{"allowed_groups":["ops"],"description":"x"}"#).unwrap();
        assert!(old.allowed_users.is_empty());
        let json = serde_json::to_value(cfg(&["ops"], &[])).unwrap();
        assert!(json.get("allowed_users").is_none(), "{json}");
        let json = serde_json::to_value(cfg(&[], &["a@b.c"])).unwrap();
        assert_eq!(json["allowed_users"][0], "a@b.c");
    }

    #[test]
    fn entry_info_marks_inherited_credentials() {
        let mut defaults = FolderDefaults::new();
        defaults.insert(
            "ssh".into(),
            DefaultCredentials {
                private_key: Some("k".into()),
                ..Default::default()
            },
        );
        let e = AddressBookEntry {
            session_type: "ssh".into(),
            ..Default::default()
        };
        let mut info = EntryInfo::from(("box", &e));
        assert!(!info.has_credentials);
        info.apply_inherited(&e, Some(&defaults));
        assert!(info.has_credentials && info.inherited_credentials);

        // own secret: has_credentials without the inherited flag
        let e = AddressBookEntry {
            session_type: "ssh".into(),
            password: Some("p".into()),
            ..Default::default()
        };
        let mut info = EntryInfo::from(("box", &e));
        info.apply_inherited(&e, Some(&defaults));
        assert!(info.has_credentials && !info.inherited_credentials);

        // set to prompt: connecting prompts, so it is not labelled as using
        // the folder's credentials
        let e = AddressBookEntry {
            session_type: "ssh".into(),
            prompt_credentials: Some(true),
            ..Default::default()
        };
        let mut info = EntryInfo::from(("box", &e));
        info.apply_inherited(&e, Some(&defaults));
        assert!(!info.has_credentials && !info.inherited_credentials);

        // the JSON omits the flag when false
        let v = serde_json::to_value(&info).unwrap();
        assert!(v.get("inherited_credentials").is_none());
    }

    #[test]
    fn test_enable_h264_serde_roundtrip() {
        // With enable_h264 set
        let json = r#"{"type":"rdp","hostname":"test","enable_gfx":true,"enable_h264":true}"#;
        let entry: AddressBookEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.enable_h264, Some(true));
        let out = serde_json::to_string(&entry).unwrap();
        assert!(out.contains("\"enable_h264\":true"));

        // Without enable_h264 (defaults to None)
        let json2 = r#"{"type":"rdp","hostname":"test","enable_gfx":true}"#;
        let entry2: AddressBookEntry = serde_json::from_str(json2).unwrap();
        assert_eq!(entry2.enable_h264, None);

        // Explicit false
        let json3 = r#"{"type":"rdp","hostname":"test","enable_h264":false}"#;
        let entry3: AddressBookEntry = serde_json::from_str(json3).unwrap();
        assert_eq!(entry3.enable_h264, Some(false));
    }

    // ── Path-traversal regression tests (v1.5.4 fix) ──────────────────────
    // Locks down the validate_name / validate_path invariants. Any future
    // relaxation of these rules (or a bug that re-opens `../` handling) must
    // fail these tests, not land silently.
}
