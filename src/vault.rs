// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! HashiVault / OpenBao KV v2 client with AppRole or workload JWT authentication.
//!
//! Stores address book entries (connection credentials) in Vault.
//! Path structure:
//!   <mount>/data/<base_path>/shared/<folder>/<entry>       — shared across instances
//!   <mount>/data/<base_path>/instance/<name>/<folder>/<entry> — instance-specific
//!
//! Each folder has a `.config` sentinel key containing `FolderConfig`
//! (allowed_groups, description) that controls OIDC group-based access.
//!
//! The mybastion logic lives here; reads and writes go through a
//! `store::SecretStore` (`store::vault` holds the HTTP, login and TLS code).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::VaultConfig;
use crate::store::vault::VaultStore;
use crate::store::{SecretStore, StoreError};
use crate::tunnel;

// ── Error type ──

#[derive(Debug)]
pub enum VaultError {
    Auth(String),
    NotFound,
    Forbidden,
    Http(reqwest::Error),
    Parse(String),
    BadName(String),
    /// The backend serving this scope is configured but not currently
    /// connected (initial connect pending or the Vault is down). Distinct from
    /// a Vault that returns an error: the request never left mybastion.
    Unavailable,
    /// A local secret store (SQLite) failed.
    Storage(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(msg) => write!(f, "vault auth error: {}", msg),
            Self::NotFound => write!(f, "not found in vault"),
            Self::Forbidden => write!(f, "vault access denied"),
            Self::Http(e) => write!(f, "vault HTTP error: {}", e),
            Self::Parse(msg) => write!(f, "vault response parse error: {}", msg),
            Self::BadName(msg) => write!(f, "invalid name: {}", msg),
            Self::Unavailable => write!(f, "vault backend not available"),
            Self::Storage(msg) => write!(f, "secret store error: {}", msg),
        }
    }
}

impl From<reqwest::Error> for VaultError {
    fn from(e: reqwest::Error) -> Self {
        VaultError::Http(e)
    }
}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Auth(msg) => VaultError::Auth(msg),
            StoreError::Http(e) => VaultError::Http(e),
            StoreError::Forbidden => VaultError::Forbidden,
            StoreError::NotFound => VaultError::NotFound,
            StoreError::CasConflict => VaultError::Parse("check-and-set conflict".into()),
            StoreError::Rejected { status, .. } => {
                VaultError::Parse(format!("unexpected status {}", status))
            }
            StoreError::Backend(msg) => VaultError::Storage(msg),
        }
    }
}

/// For `map_err`: a status the store rejected reads `"<op> failed (<status>)"`.
fn failed(op: &'static str) -> impl Fn(StoreError) -> VaultError {
    move |e| match e {
        StoreError::Rejected { status, .. } => {
            VaultError::Parse(format!("{} failed ({})", op, status))
        }
        e => e.into(),
    }
}

/// `failed`, with the store's response body after it, as writes report.
fn write_failed(op: &'static str) -> impl Fn(StoreError) -> VaultError {
    move |e| match e {
        StoreError::Rejected { status, body } => {
            VaultError::Parse(format!("{} failed ({}): {}", op, status, body))
        }
        e => e.into(),
    }
}

/// A typed value as the JSON document the store keeps.
fn to_doc<T: Serialize>(v: &T) -> Result<serde_json::Value, VaultError> {
    serde_json::to_value(v).map_err(|e| VaultError::Parse(e.to_string()))
}

// ── Data types ──

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

/// Credentials a folder lends to entries that have none of their own, keyed
/// by session type (`ssh`, `rdp`, `vnc`, `web`, ...). Stored at
/// `<folder>/.defaults` beside `.config`, so an entry created without secrets
/// (a NetBox webhook, a bulk import) is connectable the moment it exists,
/// with no second pass to fill it in. A subfolder without its own `.defaults`
/// inherits its nearest ancestor's, per type, as far up as
/// `inherit_from_parent` allows (see `resolve_effective_defaults`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DefaultCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl DefaultCredentials {
    /// Whether these defaults carry something that can authenticate (a
    /// username alone does not).
    pub fn has_secret(&self) -> bool {
        self.password.as_deref().is_some_and(|p| !p.is_empty())
            || self.private_key.as_deref().is_some_and(|k| !k.is_empty())
    }
}

/// Per-session-type default credentials of one folder.
pub type FolderDefaults = std::collections::BTreeMap<String, DefaultCredentials>;

/// Whether the entry carries a password or private key of its own.
pub fn entry_has_own_credentials(e: &AddressBookEntry) -> bool {
    e.password.as_deref().is_some_and(|p| !p.is_empty())
        || e.private_key.as_deref().is_some_and(|k| !k.is_empty())
}

/// Whether an entry is a candidate for folder defaults: it has no password
/// or private key of its own and is not set to prompt at connect time (a
/// prompting entry keeps prompting, defaults or not).
pub fn entry_takes_folder_defaults(e: &AddressBookEntry) -> bool {
    !entry_has_own_credentials(e) && e.prompt_credentials != Some(true)
}

/// Give an entry without credentials of its own the folder defaults for its
/// session type. The entry's own username and domain win when set; the
/// defaults' password and private key are taken as they are. Returns whether
/// anything was applied: false when the entry already has a secret or is set
/// to prompt, when the folder has no defaults for the type, or when those
/// defaults have no secret.
pub fn apply_folder_defaults(entry: &mut AddressBookEntry, defaults: &FolderDefaults) -> bool {
    if !entry_takes_folder_defaults(entry) {
        return false;
    }
    let Some(d) = defaults.get(&entry.session_type) else {
        return false;
    };
    if !d.has_secret() {
        return false;
    }
    if entry.username.as_deref().is_none_or(str::is_empty) && d.username.is_some() {
        entry.username = d.username.clone();
    }
    if entry.domain.as_deref().is_none_or(str::is_empty) && d.domain.is_some() {
        entry.domain = d.domain.clone();
    }
    entry.password = d.password.clone().filter(|p| !p.is_empty());
    entry.private_key = d.private_key.clone().filter(|k| !k.is_empty());
    true
}

/// What the defaults walk reads per folder: its own `.defaults`, and whether
/// its `.config` lets it inherit from the parent. A trait so the walk in
/// `resolve_effective_defaults` is unit-testable without a Vault; both
/// `VaultClient` and the multi-backend router implement it.
#[allow(async_fn_in_trait)]
pub trait DefaultsSource {
    /// The folder's own `.defaults`; `None` when it has none.
    async fn folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError>;

    /// Whether the folder's parent may lend it defaults: see
    /// `FolderConfig::shares_parent_audience`. A folder with no `.config`
    /// does not inherit, which is how `resolve_folder_access` treats it too.
    async fn takes_parent_defaults(&self, scope: &str, folder: &str) -> Result<bool, VaultError>;
}

/// The defaults that apply to entries in `folder`: its own `.defaults`, then
/// each ancestor's for any session type still unset, walking up only while
/// the folder just visited is seen by exactly its parent's audience
/// (`FolderConfig::shares_parent_audience`).
///
/// A secret set on a parent must reach only people who could already reach
/// the parent. A folder with `inherit_from_parent: false` is isolated, and
/// one that inherits but also grants groups or users of its own admits
/// people the parent doesn't, so the walk stops at either: otherwise a
/// subfolder shared with a contractor through `allowed_users` would hand
/// them the parent's key. That folder's own `.defaults` still apply to its
/// entries. `None` when no folder on the walk has any.
pub async fn resolve_effective_defaults<S: DefaultsSource>(
    src: &S,
    scope: &str,
    folder: &str,
) -> Result<Option<FolderDefaults>, VaultError> {
    let mut merged = FolderDefaults::new();
    let mut path = folder.to_string();
    loop {
        if let Some(d) = src.folder_defaults(scope, &path).await? {
            for (session_type, creds) in d {
                merged.entry(session_type).or_insert(creds);
            }
        }
        // Top-level folder: nothing above it to consult.
        let Some(i) = path.rfind('/') else { break };
        // Isolated folder: what its parent lends stops here.
        if !src.takes_parent_defaults(scope, &path).await? {
            break;
        }
        path.truncate(i);
    }
    Ok(if merged.is_empty() {
        None
    } else {
        Some(merged)
    })
}

impl DefaultsSource for VaultClient {
    async fn folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError> {
        match self.get_folder_defaults(scope, folder).await {
            Ok(d) => Ok(Some(d)),
            Err(VaultError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn takes_parent_defaults(&self, scope: &str, folder: &str) -> Result<bool, VaultError> {
        match self.get_folder_config(scope, folder).await {
            Ok(c) => Ok(c.shares_parent_audience()),
            Err(VaultError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }
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

// ── Vault client ──

pub struct VaultClient {
    store: Arc<dyn SecretStore>,
    base_path: String,
    instance_name: Option<String>,
}

impl VaultClient {
    /// Create a new Vault client and perform initial login.
    pub async fn new(config: &VaultConfig, secret_id: &str) -> Result<Self, VaultError> {
        let store = VaultStore::new(config, secret_id).await?;
        Ok(Self::with_store(
            Arc::new(store),
            config.base_path.clone(),
            config.instance_name.clone(),
        ))
    }

    /// A client over any store, e.g. SQLite. `base_path` prefixes the
    /// address-book paths as in `[vault]`; `instance_name` enables the
    /// instance scope.
    pub fn with_store(
        store: Arc<dyn SecretStore>,
        base_path: String,
        instance_name: Option<String>,
    ) -> Self {
        Self {
            store,
            base_path,
            instance_name,
        }
    }

    /// Spawn the store's background upkeep (for Vault, token renewal at 50%
    /// of TTL).
    pub fn spawn_renewal_task(self: &Arc<Self>) {
        Arc::clone(&self.store).spawn_maintenance();
    }

    // ── Path helpers ──

    /// Store path (relative to the KV mount) of `rest` under a scope.
    fn kv_path(&self, scope_prefix: &str, rest: &str) -> String {
        format!("{}/{}/{}", self.base_path, scope_prefix, rest)
    }

    /// The document at `path`, or `None` when there is none.
    async fn read_doc(&self, path: &str) -> Result<Option<serde_json::Value>, VaultError> {
        Ok(self.store.get(path).await?.map(|d| d.data))
    }

    // ── KV v2 operations ──

    /// List top-level folders for a single scope (`"shared"` or `"instance"`).
    ///
    /// Returns an empty vec (not an error) when the scope isn't applicable to
    /// this client — e.g. `"instance"` with no `instance_name` configured — so
    /// the multi-backend fan-out can call it unconditionally.
    pub async fn list_folders_in_scope(&self, scope: &str) -> Result<Vec<FolderInfo>, VaultError> {
        let prefix = match scope {
            "shared" => "shared".to_string(),
            "instance" => match &self.instance_name {
                Some(name) => format!("instance/{}", name),
                None => return Ok(Vec::new()),
            },
            _ => return Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        };

        let mut folders = Vec::new();
        let path = format!("{}/{}", self.base_path, prefix);
        match self.kv_list(&path).await {
            Ok(keys) => {
                for name in keys.iter().filter_map(|k| k.strip_suffix('/')) {
                    folders.push(FolderInfo {
                        name: name.to_string(),
                        description: String::new(),
                        display_name: String::new(),
                        scope: scope.to_string(),
                        path: Some(name.to_string()),
                        has_children: None, // enriched below
                    });
                }
            }
            Err(VaultError::NotFound) => {
                // No folders in this scope — that's fine
            }
            Err(e) => return Err(e),
        }

        // Enrich with descriptions and child detection
        for folder in &mut folders {
            if let Ok(config) = self.get_folder_config(&folder.scope, &folder.name).await {
                folder.description = config.description;
                folder.display_name = config.display_name;
            }
            // Check for subfolders by listing children
            if let Ok(children) = self.list_children(&folder.scope, &folder.name).await {
                folder.has_children = Some(children.iter().any(|c| c.strip_suffix('/').is_some()));
            }
        }

        Ok(folders)
    }

    /// List immediate children (subfolders and entries) at a given folder path.
    /// Subfolder names end with `/` in the returned list.
    pub async fn list_children(
        &self,
        scope: &str,
        folder_path: &str,
    ) -> Result<Vec<String>, VaultError> {
        validate_path(folder_path)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        self.kv_list(&self.kv_path(&scope_prefix, folder_path))
            .await
    }

    /// List subfolders at a given path within a scope.
    /// Returns FolderInfo for each subfolder, with has_children populated.
    pub async fn list_subfolders(
        &self,
        scope: &str,
        parent_path: &str,
    ) -> Result<Vec<FolderInfo>, VaultError> {
        let children = self.list_children(scope, parent_path).await?;
        let mut folders = Vec::new();

        for key in &children {
            if let Some(name) = key.strip_suffix('/') {
                let full_path = format!("{}/{}", parent_path, name);
                let mut info = FolderInfo {
                    name: name.to_string(),
                    description: String::new(),
                    display_name: String::new(),
                    scope: scope.to_string(),
                    path: Some(full_path.clone()),
                    has_children: None,
                };
                // Enrich with description
                if let Ok(config) = self.get_folder_config(scope, &full_path).await {
                    info.description = config.description;
                    info.display_name = config.display_name;
                }
                // Check for grandchildren
                if let Ok(grandchildren) = self.list_children(scope, &full_path).await {
                    info.has_children =
                        Some(grandchildren.iter().any(|c| c.strip_suffix('/').is_some()));
                }
                folders.push(info);
            }
        }

        Ok(folders)
    }

    /// Get the .config for a folder in a specific scope.
    pub async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderConfig, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid .config: {}", e)))
    }

    /// Resolve whether `who` may access `folder` under `scope`.
    ///
    /// Checks the folder's own `allowed_groups` and `allowed_users` first
    /// (see `FolderConfig::grants`). If neither matches and the
    /// folder's `inherit_from_parent` is true, walks up the slash-separated
    /// path and evaluates each ancestor's config the same way. Returns `false`
    /// once a folder denies and doesn't inherit, or once the walk reaches the
    /// top-level folder with no match. Missing (`NotFound`) folder configs
    /// are treated as deny; other Vault errors propagate so callers can log.
    pub async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        who: FolderSubject<'_>,
    ) -> Result<bool, VaultError> {
        let mut current = folder.to_string();
        loop {
            let config = match self.get_folder_config(scope, &current).await {
                Ok(c) => c,
                Err(VaultError::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            if config.grants(who) {
                return Ok(true);
            }
            if !config.inherit_from_parent {
                return Ok(false);
            }
            // Walk to parent segment; stop at the top-level folder.
            match current.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
                _ => return Ok(false),
            }
        }
    }

    /// List entry names in a folder (excludes the `.config` and `.defaults`
    /// sentinels).
    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let keys = self.kv_list(&self.kv_path(&scope_prefix, folder)).await?;
        Ok(keys
            .into_iter()
            .filter(|k| k != ".config" && k != ".defaults")
            .collect())
    }

    /// Get a full entry (with credentials).
    pub async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        let mut entry: AddressBookEntry = serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid entry: {}", e)))?;
        entry.normalize_jump_hosts();
        Ok(entry)
    }

    /// Write an entry to Vault.
    pub async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        self.write_entry(scope, folder, entry, data, false)
            .await
            .map(|_| ())
    }

    /// Write an entry only if none exists at that path, enforced by Vault
    /// itself (KV v2 check-and-set with `cas: 0`) rather than by a read
    /// beforehand, so two writers cannot both pass the check. Returns
    /// `Ok(false)` when an entry is already there.
    pub async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        self.write_entry(scope, folder, entry, data, true).await
    }

    async fn write_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
        only_if_absent: bool,
    ) -> Result<bool, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let cas = only_if_absent.then_some(0);
        match self.store.put(&path, &to_doc(data)?, cas).await {
            Ok(_) => Ok(true),
            Err(StoreError::CasConflict) => Ok(false),
            Err(e) => Err(write_failed("put entry")(e)),
        }
    }

    /// Delete an entry (all versions via metadata endpoint).
    pub async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), VaultError> {
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        self.store
            .delete(&path)
            .await
            .map_err(failed("delete entry"))
    }

    /// Write a folder's .config.
    pub async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        self.store
            .put(&path, &to_doc(config)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put folder config"))
    }

    /// Read a folder's `.defaults` (see `FolderDefaults`).
    pub async fn get_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderDefaults, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid .defaults: {}", e)))
    }

    /// Write a folder's `.defaults`. An empty map removes the key instead,
    /// so a folder with nothing to lend has no sentinel at all.
    pub async fn put_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
        defaults: &FolderDefaults,
    ) -> Result<(), VaultError> {
        if defaults.is_empty() {
            return self.delete_folder_defaults(scope, folder).await;
        }
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        self.store
            .put(&path, &to_doc(defaults)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put folder defaults"))
    }

    /// Remove a folder's `.defaults`. Absent is fine.
    pub async fn delete_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        match self.store.delete(&path).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(e) => Err(failed("delete folder defaults")(e)),
        }
    }

    /// The defaults that apply to entries in `folder`: see
    /// `resolve_effective_defaults` for the walk and where it stops.
    pub async fn effective_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError> {
        validate_path(folder)?;
        resolve_effective_defaults(self, scope, folder).await
    }

    /// Delete a folder and everything under it: entries, subfolders and the
    /// `.config` / `.defaults` sentinels at every level.
    ///
    /// Returns (subfolder_count, entry_count) for audit/UI feedback, counted
    /// before the delete. Subfolder count excludes the folder itself (0 for a
    /// leaf); sentinels are not entries.
    pub async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let root = self.kv_path(&scope_prefix, folder);

        let (mut subfolders, mut entries) = (0usize, 0usize);
        let mut dirs = vec![root.clone()];
        while let Some(dir) = dirs.pop() {
            let names = match self.store.list(&dir).await {
                Ok(names) => names,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(failed("list")(e)),
            };
            for name in names {
                match name.strip_suffix('/') {
                    Some(sub) => {
                        subfolders += 1;
                        dirs.push(format!("{}/{}", dir, sub));
                    }
                    None if name == ".config" || name == ".defaults" => {}
                    None => entries += 1,
                }
            }
        }

        self.store
            .delete_prefix(&root)
            .await
            .map_err(failed("delete folder"))?;
        Ok((subfolders, entries))
    }

    // ── Generic KV v2 read ──

    /// Read a single field from an arbitrary KV v2 path (relative to base_path).
    /// Used for reading non-address-book secrets like the LUKS encryption key.
    pub async fn read_kv_field(&self, kv_path: &str, field: &str) -> Result<String, VaultError> {
        let data = self.read_doc(kv_path).await?.ok_or(VaultError::NotFound)?;
        data[field]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::Parse(format!("field '{}' not found in secret", field)))
    }

    // ── Internal helpers ──

    /// Resolve "shared" or "instance" scope label to the actual Vault path prefix.
    fn resolve_scope_prefix(&self, scope: &str) -> Result<String, VaultError> {
        match scope {
            "shared" => Ok("shared".to_string()),
            "instance" => match &self.instance_name {
                Some(name) => Ok(format!("instance/{}", name)),
                None => Err(VaultError::BadName("no instance_name configured".into())),
            },
            _ => Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        }
    }

    /// The keys directly under `dir`; subfolder names end with `/`.
    async fn kv_list(&self, dir: &str) -> Result<Vec<String>, VaultError> {
        self.store.list(dir).await.map_err(failed("list"))
    }

    // ── User credential variables ──

    /// Read a user's stored credential variables from Vault.
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        self.get_user_credentials_by_key(&sanitize_email_key(email))
            .await
    }

    /// Write a user's credential variables to Vault (full replace).
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn put_user_credentials(
        &self,
        email: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), VaultError> {
        self.put_user_credentials_by_key(&sanitize_email_key(email), creds)
            .await
    }

    /// Read credential variables by the already-sanitised users key. Used by
    /// `vault-migrate` (which enumerates raw keys and must not re-sanitise).
    pub async fn get_user_credentials_by_key(
        &self,
        key: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        let path = format!("{}/users/{}", self.base_path, key);
        let doc = self
            .store
            .get(&path)
            .await
            .map_err(failed("get user credentials"))?;
        // No document: no credentials stored yet.
        let map = doc
            .and_then(|d| {
                d.data.as_object().map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
            })
            .unwrap_or_default();
        Ok(map)
    }

    /// Write credential variables by the already-sanitised users key (full
    /// replace). Companion to [`get_user_credentials_by_key`] for migration.
    pub async fn put_user_credentials_by_key(
        &self,
        key: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), VaultError> {
        let path = format!("{}/users/{}", self.base_path, key);
        self.store
            .put(&path, &to_doc(creds)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put user credentials"))
    }

    /// List the raw key names under `<base_path>/users/` (each a sanitised
    /// email). Empty when no credentials have been stored yet.
    pub async fn list_user_keys(&self) -> Result<Vec<String>, VaultError> {
        let path = format!("{}/users", self.base_path);
        match self.kv_list(&path).await {
            Ok(keys) => Ok(keys.into_iter().filter(|k| !k.ends_with('/')).collect()),
            Err(VaultError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Delete a user's credential variables from Vault.
    #[allow(dead_code)] // Will be used by admin endpoint
    pub async fn delete_user_credentials(&self, email: &str) -> Result<(), VaultError> {
        let key = sanitize_email_key(email);
        let path = format!("{}/users/{}", self.base_path, key);
        match self.store.delete(&path).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()), // Already gone
            Err(e) => Err(failed("delete user credentials")(e)),
        }
    }
}

/// Validate that a folder or entry name is safe (alphanumeric, hyphens, underscores, dots — no path traversal).
fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() || name.len() > 64 {
        return Err(VaultError::BadName("name must be 1-64 characters".into()));
    }
    if name == ".config" || name == ".defaults" || name == "." || name == ".." {
        return Err(VaultError::BadName("reserved name".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(VaultError::BadName(
            "name cannot contain path separators".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(VaultError::BadName(
            "name must be alphanumeric, hyphens, underscores, or dots".into(),
        ));
    }
    Ok(())
}

/// Validate a folder path that may contain subfolders (e.g. "Clients/Acme/Servers").
/// Each segment is validated with the same rules as `validate_name`.
/// Empty segments, trailing slashes, and leading slashes are rejected.
fn validate_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty() {
        return Err(VaultError::BadName("path cannot be empty".into()));
    }
    if path.len() > 256 {
        return Err(VaultError::BadName("path too long (max 256 chars)".into()));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(VaultError::BadName(
            "path cannot start or end with /".into(),
        ));
    }
    if path.contains("//") {
        return Err(VaultError::BadName(
            "path cannot contain empty segments".into(),
        ));
    }
    for segment in path.split('/') {
        validate_name(segment)?;
    }
    Ok(())
}

/// Sanitize an email address for use as a Vault path component.
/// Replaces `@` with `_at_` and strips any characters not in `[a-zA-Z0-9._-]`.
fn sanitize_email_key(email: &str) -> String {
    email
        .replace('@', "_at_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Check if a string is a credential variable reference (starts with `$`).
pub fn is_credential_variable(s: &str) -> bool {
    s.starts_with('$')
        && s.len() > 1
        && s[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Extract the variable name from a `$variable` reference.
fn variable_name(s: &str) -> Option<&str> {
    if is_credential_variable(s) {
        Some(&s[1..])
    } else {
        None
    }
}

/// Collect all credential variable names referenced by an address book entry.
pub fn entry_credential_variables(entry: &AddressBookEntry) -> Vec<String> {
    [
        &entry.username,
        &entry.password,
        &entry.domain,
        &entry.private_key,
        &entry.container_username,
        &entry.container_password,
    ]
    .iter()
    .filter_map(|field| field.as_deref())
    .filter_map(variable_name)
    .map(|s| s.to_string())
    .collect()
}

/// Resolve credential variable references in an address book entry.
/// Returns the entry with `$var` fields substituted from the user's credential map.
/// Fields that are not variable references are left unchanged.
/// Returns `Err(vec_of_missing_var_names)` if any referenced variables are missing.
pub fn resolve_credential_variables(
    entry: &AddressBookEntry,
    user_creds: &HashMap<String, String>,
) -> Result<AddressBookEntry, Vec<String>> {
    let mut resolved = entry.clone();
    let mut missing = Vec::new();

    fn resolve_field(
        field: &mut Option<String>,
        creds: &HashMap<String, String>,
        missing: &mut Vec<String>,
    ) {
        if let Some(ref val) = field {
            if let Some(name) = variable_name(val) {
                if let Some(resolved_val) = creds.get(name) {
                    *field = Some(resolved_val.clone());
                } else {
                    missing.push(name.to_string());
                }
            }
        }
    }

    resolve_field(&mut resolved.username, user_creds, &mut missing);
    resolve_field(&mut resolved.password, user_creds, &mut missing);
    resolve_field(&mut resolved.domain, user_creds, &mut missing);
    resolve_field(&mut resolved.private_key, user_creds, &mut missing);
    resolve_field(&mut resolved.container_username, user_creds, &mut missing);
    resolve_field(&mut resolved.container_password, user_creds, &mut missing);

    if missing.is_empty() {
        Ok(resolved)
    } else {
        Err(missing)
    }
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
    fn test_config_deserialize_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
            ca_cert = "/opt/mybastion/certs/ca.pem"
            client_cert = "/opt/mybastion/certs/client.pem"
            client_key = "/opt/mybastion/certs/client-key.pem"
            tls_skip_verify = true
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.ca_cert.as_deref(),
            Some("/opt/mybastion/certs/ca.pem")
        );
        assert_eq!(
            config.client_cert.as_deref(),
            Some("/opt/mybastion/certs/client.pem")
        );
        assert_eq!(
            config.client_key.as_deref(),
            Some("/opt/mybastion/certs/client-key.pem")
        );
        assert!(config.tls_skip_verify);
    }

    #[test]
    fn test_config_deserialize_no_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
        assert!(!config.tls_skip_verify);
    }

    #[test]
    fn test_validate_name_ok() {
        assert!(validate_name("my-entry.v2").is_ok());
        assert!(validate_name("a").is_ok());
    }

    #[test]
    fn test_validate_name_rejects_traversal() {
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn test_validate_name_rejects_empty_and_long() {
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_validate_path_ok() {
        assert!(validate_path("my-folder").is_ok());
        assert!(validate_path("Clients/Acme").is_ok());
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a/b/c/d").is_ok());
    }

    #[test]
    fn test_validate_path_rejects_bad_input() {
        assert!(validate_path("").is_err()); // empty
        assert!(validate_path("/leading").is_err()); // leading slash
        assert!(validate_path("trailing/").is_err()); // trailing slash
        assert!(validate_path("a//b").is_err()); // empty segment
        assert!(validate_path("a/../b").is_err()); // traversal
        assert!(validate_path("a/.config/b").is_err()); // reserved name
        assert!(validate_path(&format!("a/{}", "x".repeat(65))).is_err()); // segment too long
    }

    #[test]
    fn test_sanitize_email_key() {
        assert_eq!(
            sanitize_email_key("alice@example.com"),
            "alice_at_example.com"
        );
        assert_eq!(sanitize_email_key("bob+tag@foo.co"), "bobtag_at_foo.co");
        assert_eq!(sanitize_email_key("../../evil"), "....evil");
    }

    #[test]
    fn test_is_credential_variable() {
        assert!(is_credential_variable("$corp_user"));
        assert!(is_credential_variable("$lab_password"));
        assert!(is_credential_variable("$x"));
        assert!(!is_credential_variable("$"));
        assert!(!is_credential_variable("plain_text"));
        assert!(!is_credential_variable(""));
        assert!(!is_credential_variable("$has spaces"));
        assert!(is_credential_variable("$has-dashes")); // hyphens allowed since v0.8.0
    }

    #[test]
    fn folder_defaults_fill_only_entries_without_secrets() {
        let mut defaults = FolderDefaults::new();
        defaults.insert(
            "ssh".into(),
            DefaultCredentials {
                username: Some("root".into()),
                private_key: Some("-----BEGIN KEY-----".into()),
                ..Default::default()
            },
        );
        defaults.insert(
            "web".into(),
            DefaultCredentials {
                password: Some("router-pw".into()),
                ..Default::default()
            },
        );
        // username only: nothing to authenticate with
        defaults.insert(
            "rdp".into(),
            DefaultCredentials {
                username: Some("Administrator".into()),
                ..Default::default()
            },
        );

        // ssh entry without secrets: takes the key, keeps its own username
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            username: Some("admin".into()),
            ..Default::default()
        };
        assert!(apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.username.as_deref(), Some("admin"));
        assert_eq!(e.private_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert!(e.password.is_none());

        // no username at all: the default's username fills it
        let mut e = AddressBookEntry {
            session_type: "web".into(),
            ..Default::default()
        };
        assert!(apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.password.as_deref(), Some("router-pw"));
        assert!(e.username.is_none(), "web defaults carry no username");

        // an entry with its own secret is left alone
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            password: Some("own".into()),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.password.as_deref(), Some("own"));
        assert!(e.private_key.is_none());

        // defaults with no secret do nothing; a type without defaults too
        let mut e = AddressBookEntry {
            session_type: "rdp".into(),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert!(e.username.is_none());
        let mut e = AddressBookEntry {
            session_type: "vnc".into(),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));

        // an entry set to prompt keeps prompting: no defaults for it
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            prompt_credentials: Some(true),
            ..Default::default()
        };
        assert!(!entry_takes_folder_defaults(&e));
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert!(e.private_key.is_none());
    }

    /// In-memory stand-in for the two per-folder reads the defaults walk
    /// makes. `inherit` lists the folders whose `.config` has
    /// `inherit_from_parent: true`; everything else is treated as isolated,
    /// including folders with no `.config` at all.
    struct FakeDefaults {
        defaults: std::collections::HashMap<String, FolderDefaults>,
        inherit: std::collections::HashSet<String>,
    }

    impl DefaultsSource for FakeDefaults {
        async fn folder_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<Option<FolderDefaults>, VaultError> {
            Ok(self.defaults.get(folder).cloned())
        }
        async fn takes_parent_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<bool, VaultError> {
            Ok(self.inherit.contains(folder))
        }
    }

    fn ssh_key(key: &str) -> FolderDefaults {
        let mut d = FolderDefaults::new();
        d.insert(
            "ssh".into(),
            DefaultCredentials {
                private_key: Some(key.into()),
                ..Default::default()
            },
        );
        d
    }

    fn web_pw(pw: &str) -> FolderDefaults {
        let mut d = FolderDefaults::new();
        d.insert(
            "web".into(),
            DefaultCredentials {
                password: Some(pw.into()),
                ..Default::default()
            },
        );
        d
    }

    #[tokio::test]
    async fn effective_defaults_merge_nearest_first_through_inheriting_folders() {
        // corp/.defaults: ssh key + web pw; corp/linux/.defaults: ssh key only;
        // corp/linux/web has none. Every subfolder inherits.
        let mut defaults = std::collections::HashMap::new();
        let mut corp = ssh_key("corp-key");
        corp.extend(web_pw("corp-web"));
        defaults.insert("corp".to_string(), corp);
        defaults.insert("corp/linux".to_string(), ssh_key("linux-key"));
        let src = FakeDefaults {
            defaults,
            inherit: ["corp/linux", "corp/linux/web"]
                .into_iter()
                .map(String::from)
                .collect(),
        };

        let d = resolve_effective_defaults(&src, "shared", "corp/linux/web")
            .await
            .unwrap()
            .expect("defaults found on the path");
        // nearest folder wins per type; a type it lacks comes from higher up
        assert_eq!(d["ssh"].private_key.as_deref(), Some("linux-key"));
        assert_eq!(d["web"].password.as_deref(), Some("corp-web"));

        // nothing anywhere on the path: None, not an empty map
        let bare = FakeDefaults {
            defaults: Default::default(),
            inherit: ["a/b"].into_iter().map(String::from).collect(),
        };
        assert!(resolve_effective_defaults(&bare, "shared", "a/b")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn effective_defaults_stop_at_a_folder_that_does_not_inherit() {
        // corp lends an ssh key. corp/guests is isolated for access
        // (inherit_from_parent: false, shared with an outside user through
        // allowed_users); corp/guests/lab inherits from corp/guests. The
        // corp key must reach neither of them.
        let mut defaults = std::collections::HashMap::new();
        defaults.insert("corp".to_string(), ssh_key("corp-key"));
        let src = FakeDefaults {
            defaults: defaults.clone(),
            inherit: ["corp/guests/lab"].into_iter().map(String::from).collect(),
        };
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/guests")
                .await
                .unwrap()
                .is_none(),
            "an isolated folder must not receive its parent's defaults"
        );
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/guests/lab")
                .await
                .unwrap()
                .is_none(),
            "the walk must not cross the isolated folder on its way up"
        );

        // the isolated folder's own .defaults still apply to its entries and
        // to subfolders that inherit from it, but corp's key stays out
        defaults.insert("corp/guests".to_string(), web_pw("guest-web"));
        let src = FakeDefaults {
            defaults,
            inherit: ["corp/guests/lab"].into_iter().map(String::from).collect(),
        };
        for folder in ["corp/guests", "corp/guests/lab"] {
            let d = resolve_effective_defaults(&src, "shared", folder)
                .await
                .unwrap()
                .expect("the isolated folder's own defaults apply");
            assert_eq!(d["web"].password.as_deref(), Some("guest-web"));
            assert!(
                !d.contains_key("ssh"),
                "{folder}: corp's key crossed the boundary"
            );
        }

        // a folder with no .config is treated as isolated, as access does
        let src = FakeDefaults {
            defaults: [("corp".to_string(), ssh_key("corp-key"))]
                .into_iter()
                .collect(),
            inherit: Default::default(),
        };
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/unconfigured")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn effective_defaults_propagate_read_errors() {
        struct Failing;
        impl DefaultsSource for Failing {
            async fn folder_defaults(
                &self,
                _s: &str,
                _f: &str,
            ) -> Result<Option<FolderDefaults>, VaultError> {
                Ok(Some(ssh_key("k")))
            }
            async fn takes_parent_defaults(&self, _s: &str, _f: &str) -> Result<bool, VaultError> {
                Err(VaultError::Forbidden)
            }
        }
        // a .config that cannot be read must not be mistaken for "inherits"
        assert!(resolve_effective_defaults(&Failing, "shared", "a/b")
            .await
            .is_err());
        // but a top-level folder never needs its config
        let d = resolve_effective_defaults(&Failing, "shared", "a")
            .await
            .unwrap();
        assert!(d.is_some());
    }

    #[test]
    fn parent_defaults_reach_only_the_parents_audience() {
        // Folder access is a union: a subfolder that inherits and also grants
        // someone of its own admits people the parent doesn't. corp/partner
        // inherits from corp but adds a contractor, so corp's default key
        // must not flow into it, or the contractor connects with it.
        let cfg = |inherit: bool, groups: &[&str], users: &[&str]| -> FolderConfig {
            serde_json::from_value(serde_json::json!({
                "allowed_groups": groups,
                "allowed_users": users,
                "inherit_from_parent": inherit,
            }))
            .unwrap()
        };
        assert!(cfg(true, &[], &[]).shares_parent_audience());
        assert!(
            !cfg(true, &[], &["contractor@ext.example"]).shares_parent_audience(),
            "an extra user is an extra audience"
        );
        assert!(
            !cfg(true, &["partners"], &[]).shares_parent_audience(),
            "an extra group is an extra audience"
        );
        assert!(
            !cfg(false, &[], &[]).shares_parent_audience(),
            "an isolated folder takes nothing from its parent"
        );
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
    fn test_entry_credential_variables() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()), // literal, not a variable
            ..AddressBookEntry::default()
        };
        let vars = entry_credential_variables(&entry);
        assert_eq!(vars, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_success() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()),
            hostname: Some("rdp.example.com".into()),
            ..AddressBookEntry::default()
        };

        let mut creds = HashMap::new();
        creds.insert("corp_user".into(), "alice".into());
        creds.insert("corp_password".into(), "s3cret".into());

        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("s3cret"));
        assert_eq!(resolved.domain.as_deref(), Some("CORP")); // unchanged
        assert_eq!(resolved.hostname.as_deref(), Some("rdp.example.com")); // unchanged
    }

    #[test]
    fn test_resolve_credential_variables_missing() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new(); // empty
        let err = resolve_credential_variables(&entry, &creds).unwrap_err();
        assert_eq!(err, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_no_variables() {
        let entry = AddressBookEntry {
            username: Some("alice".into()),
            password: Some("literal_pass".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new();
        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("literal_pass"));
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

    #[test]
    fn validate_name_accepts_plain_names() {
        assert!(validate_name("acme").is_ok());
        assert!(validate_name("acme-prod").is_ok());
        assert!(validate_name("acme_prod").is_ok());
        assert!(validate_name("host.example").is_ok());
        assert!(validate_name("A1b2C3").is_ok());
    }

    #[test]
    fn validate_name_rejects_traversal() {
        assert!(validate_name("..").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_name_rejects_reserved() {
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn validate_name_rejects_encoded_traversal() {
        // Encoded forms should fail because `%` is not in the whitelist.
        assert!(validate_name("%2e%2e").is_err());
        assert!(validate_name("%2E%2E%2F").is_err());
        assert!(validate_name("..%2F..").is_err());
    }

    #[test]
    fn validate_name_rejects_nul_and_control() {
        assert!(validate_name("foo\0bar").is_err());
        assert!(validate_name("foo\nbar").is_err());
        assert!(validate_name("foo\tbar").is_err());
    }

    #[test]
    fn validate_name_rejects_unicode() {
        // Unicode letters/digits shouldn't sneak past the ascii-alphanumeric
        // whitelist (blocks homoglyph and normalization tricks).
        assert!(validate_name("café").is_err());
        assert!(validate_name("Ⅰ").is_err()); // Roman numeral 1
        assert!(validate_name("а").is_err()); // Cyrillic 'a'
    }

    #[test]
    fn validate_name_rejects_empty_and_overlong() {
        assert!(validate_name("").is_err());
        let overlong = "a".repeat(65);
        assert!(validate_name(&overlong).is_err());
        let at_limit = "a".repeat(64);
        assert!(validate_name(&at_limit).is_ok());
    }

    #[test]
    fn validate_name_rejects_spaces_and_special() {
        assert!(validate_name("foo bar").is_err());
        assert!(validate_name("foo;rm -rf").is_err());
        assert!(validate_name("foo$bar").is_err());
        assert!(validate_name("foo@bar").is_err());
    }

    #[test]
    fn validate_path_accepts_nested() {
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a").is_ok());
        assert!(validate_path("a/b").is_ok());
    }

    #[test]
    fn validate_path_rejects_leading_or_trailing_slash() {
        assert!(validate_path("/foo").is_err());
        assert!(validate_path("foo/").is_err());
        assert!(validate_path("/").is_err());
    }

    #[test]
    fn validate_path_rejects_empty_segments() {
        assert!(validate_path("").is_err());
        assert!(validate_path("a//b").is_err());
        assert!(validate_path("a///b").is_err());
    }

    #[test]
    fn validate_path_rejects_traversal_in_any_segment() {
        assert!(validate_path("../etc").is_err());
        assert!(validate_path("foo/../etc").is_err());
        assert!(validate_path("foo/..").is_err());
        assert!(validate_path("foo/./bar").is_err());
    }

    #[test]
    fn validate_path_rejects_overlong() {
        let overlong = "a".repeat(257);
        assert!(validate_path(&overlong).is_err());
    }
}
