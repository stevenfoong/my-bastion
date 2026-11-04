//! Policy and approval engine (Phase 2 of `docs/fork-design.md`).
//!
//! A policy rule matches a subject (who), a target (what) and an action, and
//! has an effect: allow, deny, require approval, or allow and alert.
//! Evaluation:
//!
//! - an explicit deny on any matching rule always wins;
//! - otherwise the most specific matching rule decides: the target first
//!   (entry > folder, deeper folder > shallower > any), then the subject
//!   (user or API key > group > role > anyone); on a tie the stricter effect
//!   wins;
//! - no matching rule allows, so an install with no policies behaves as
//!   before.
//!
//! An approved request grants the requester that action on that target for
//! the rule's `grant_minutes`, so a dropped connection needs no new approval.
//! For `ssh_command` a grant covers that exact command only.
//!
//! `clipboard` and `file_transfer` rules (optionally for one direction: `in`
//! to the target, `out` from it) are evaluated once when a session starts;
//! the result (`SessionControls`) switches guacd's own clipboard and transfer
//! options off and drives the filter on the WebSocket bridge (`filter.rs`).
//! In interactive SSH sessions, typed lines are logged and checked against
//! the `ssh_command` rules for alerts only (`keylog.rs`).
//!
//! **Break-glass:** an admin can override policy for themself on one target
//! with a mandatory reason. It is granted at once for `BREAK_GLASS_MINUTES`,
//! overrides a deny too, and is always audited and sent to Telegram.
//!
//! An `ssh_command` rule may list `commands`: regular expressions matched
//! against the whole command line (unanchored, so `rm\s+-rf` matches anywhere
//! in it). With none, the rule matches every command. Patterns are a guard on
//! what reaches the target, not a sandbox: an allowlist (deny anything, allow
//! known commands) is far stronger than a denylist.

pub mod api;
pub mod filter;
pub mod keylog;
pub mod store;

use serde::{Deserialize, Serialize};

use crate::auth::{role_level, AuthIdentity};

/// What is being done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Connect,
    /// One command run through the bastion (`run_ssh`).
    SshCommand,
    /// Copy (out) and paste (in) in a session.
    Clipboard,
    /// Download (out) and upload (in): RDP drive and SFTP.
    FileTransfer,
    /// An AI agent's input to a session over MCP: click, type, keys, scroll.
    Input,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Connect => "connect",
            Action::SshCommand => "ssh_command",
            Action::Clipboard => "clipboard",
            Action::FileTransfer => "file_transfer",
            Action::Input => "input",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "connect" => Some(Action::Connect),
            "ssh_command" => Some(Action::SshCommand),
            "clipboard" => Some(Action::Clipboard),
            "file_transfer" => Some(Action::FileTransfer),
            "input" => Some(Action::Input),
            _ => None,
        }
    }

    /// Clipboard and file transfer: decided per session, with a direction.
    fn is_transfer(self) -> bool {
        matches!(self, Action::Clipboard | Action::FileTransfer)
    }
}

/// Which way data moves, for clipboard and file transfer rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// To the target: paste, upload.
    In,
    /// From the target: copy, download.
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in" => Some(Direction::In),
            "out" => Some(Direction::Out),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    AllowAndAlert,
    RequireApproval,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::AllowAndAlert => "allow_and_alert",
            Effect::RequireApproval => "require_approval",
            Effect::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Effect::Allow),
            "allow_and_alert" => Some(Effect::AllowAndAlert),
            "require_approval" => Some(Effect::RequireApproval),
            "deny" => Some(Effect::Deny),
            _ => None,
        }
    }

    /// Ranking among rules that are equally specific: the stricter wins.
    fn strictness(self) -> u8 {
        match self {
            Effect::Allow => 0,
            Effect::AllowAndAlert => 1,
            Effect::RequireApproval => 2,
            Effect::Deny => 3,
        }
    }
}

/// Who a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Subject {
    Any,
    /// A login email, compared without regard to case.
    User(String),
    /// An OIDC group.
    Group(String),
    /// Exactly this role.
    Role(String),
    /// An admin API key, by name.
    ApiKey(String),
    /// An AI agent key on `/mcp`, by name; `*` for every agent.
    AiAgent(String),
}

impl Subject {
    fn rank(&self) -> u8 {
        match self {
            Subject::AiAgent(a) if a == "*" => 2,
            Subject::User(_) | Subject::ApiKey(_) | Subject::AiAgent(_) => 4,
            Subject::Group(_) => 3,
            Subject::Role(_) => 2,
            Subject::Any => 1,
        }
    }

    fn matches(&self, who: &Requester) -> bool {
        match self {
            Subject::Any => true,
            Subject::User(e) => who
                .email
                .as_deref()
                .is_some_and(|w| !w.is_empty() && w.eq_ignore_ascii_case(e.trim())),
            Subject::Group(g) => who.groups.iter().any(|x| x == g),
            Subject::Role(r) => who.email.is_some() && who.role == *r,
            Subject::ApiKey(k) => who.api_key.as_deref() == Some(k.as_str()),
            Subject::AiAgent(a) => who
                .ai_agent
                .as_deref()
                .is_some_and(|name| a.trim() == "*" || name.strip_prefix("ai:") == Some(a.trim())),
        }
    }
}

/// What a rule covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// Everything, including ad-hoc connections.
    Any,
    /// A folder and everything under it.
    Folder { scope: String, path: String },
    /// One connection entry.
    Entry {
        scope: String,
        folder: String,
        entry: String,
    },
}

impl Target {
    /// (kind rank, folder depth): entry > folder (deeper first) > any.
    fn rank(&self) -> (u8, usize) {
        match self {
            Target::Entry { folder, .. } => (3, folder.split('/').count()),
            Target::Folder { path, .. } => (2, path.split('/').count()),
            Target::Any => (1, 0),
        }
    }

    fn matches(&self, res: &Resource) -> bool {
        match (self, res) {
            (Target::Any, _) => true,
            (
                Target::Folder { scope, path },
                Resource::Entry {
                    scope: s,
                    folder: f,
                    ..
                },
            ) => scope == s && (f == path || f.starts_with(&format!("{}/", path))),
            (
                Target::Entry {
                    scope,
                    folder,
                    entry,
                },
                Resource::Entry {
                    scope: s,
                    folder: f,
                    entry: e,
                },
            ) => scope == s && folder == f && entry == e,
            _ => false,
        }
    }
}

/// Who may decide a request: everyone with at least this role, or in this
/// group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Approver {
    Role(String),
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// Set by the store; ignored in a create or update body.
    #[serde(default)]
    pub id: i64,
    pub name: String,
    pub subject: Subject,
    pub target: Target,
    pub action: Action,
    pub effect: Effect,
    /// For `require_approval`; at least one.
    #[serde(default)]
    pub approvers: Vec<Approver>,
    /// How long an approval lets the requester in.
    #[serde(default = "default_grant_minutes")]
    pub grant_minutes: u32,
    /// How long a request waits for a decision before it expires.
    #[serde(default = "default_timeout_minutes")]
    pub timeout_minutes: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// For `ssh_command`: regular expressions; the rule matches a command
    /// that any of them matches. Empty: every command.
    #[serde(default)]
    pub commands: Vec<String>,
    /// For `require_approval` on high-risk targets: Telegram only notifies,
    /// and the decision needs a fresh sign-in on the web UI.
    #[serde(default)]
    pub web_only: bool,
    /// For `clipboard` and `file_transfer`: only this direction. None: both.
    #[serde(default)]
    pub direction: Option<Direction>,
}

const MAX_COMMAND_PATTERNS: usize = 50;
const MAX_PATTERN_LEN: usize = 500;

fn default_grant_minutes() -> u32 {
    60
}

fn default_timeout_minutes() -> u32 {
    30
}

fn default_enabled() -> bool {
    true
}

impl Rule {
    fn specificity(&self) -> (u8, usize, u8, u8, u8) {
        let (t, depth) = self.target.rank();
        // A rule narrowed to some commands, or to one direction, beats one
        // that is not.
        let commands = u8::from(!self.commands.is_empty() || self.direction.is_some());
        (
            t,
            depth,
            self.subject.rank(),
            commands,
            self.effect.strictness(),
        )
    }

    /// Whether the rule's command patterns admit `command`. A rule without
    /// patterns matches any command; a pattern that does not compile (only
    /// possible for a rule written outside `validate`) matches nothing.
    fn matches_command(&self, command: Option<&str>) -> bool {
        if self.commands.is_empty() {
            return true;
        }
        let Some(cmd) = command else { return false };
        self.commands
            .iter()
            .any(|p| regex::Regex::new(p).is_ok_and(|re| re.is_match(cmd)))
    }

    /// Check the parts a caller can get wrong. Errors are for the admin UI.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is required".into());
        }
        let blank = |s: &str| s.trim().is_empty();
        match &self.subject {
            Subject::User(v)
            | Subject::Group(v)
            | Subject::Role(v)
            | Subject::ApiKey(v)
            | Subject::AiAgent(v)
                if blank(v) =>
            {
                return Err("subject value is required".into())
            }
            Subject::Role(r) if role_level(r) == 0 => {
                return Err(format!("unknown role '{}'", r));
            }
            _ => {}
        }
        match &self.target {
            Target::Folder { scope, path } if blank(path) || !valid_scope(scope) => {
                return Err("folder target needs scope shared|instance and a path".into())
            }
            Target::Entry {
                scope,
                folder,
                entry,
            } if blank(folder) || blank(entry) || !valid_scope(scope) => {
                return Err("entry target needs scope shared|instance, folder and entry".into())
            }
            _ => {}
        }
        if self.effect == Effect::RequireApproval {
            if self.approvers.is_empty() {
                return Err("require_approval needs at least one approver".into());
            }
            for a in &self.approvers {
                match a {
                    Approver::Role(r) if role_level(r) == 0 => {
                        return Err(format!("unknown approver role '{}'", r))
                    }
                    Approver::Role(v) | Approver::Group(v) if blank(v) => {
                        return Err("approver value is required".into())
                    }
                    _ => {}
                }
            }
            if self.grant_minutes == 0 || self.timeout_minutes == 0 {
                return Err("grant_minutes and timeout_minutes must be at least 1".into());
            }
        }
        if self.web_only && self.effect != Effect::RequireApproval {
            return Err("web only applies to require_approval rules".into());
        }
        if self.action.is_transfer() && self.effect == Effect::RequireApproval {
            return Err(
                "clipboard and file transfer rules allow, alert or deny; they cannot wait for approval"
                    .into(),
            );
        }
        if self.direction.is_some() && !self.action.is_transfer() {
            return Err("a direction only applies to clipboard and file_transfer rules".into());
        }
        if !self.commands.is_empty() && self.action != Action::SshCommand {
            return Err("command patterns only apply to ssh_command rules".into());
        }
        if self.commands.len() > MAX_COMMAND_PATTERNS {
            return Err(format!("at most {} command patterns", MAX_COMMAND_PATTERNS));
        }
        for p in &self.commands {
            if p.trim().is_empty() || p.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "command patterns must be 1-{} characters",
                    MAX_PATTERN_LEN
                ));
            }
            regex::Regex::new(p).map_err(|e| format!("bad command pattern '{}': {}", p, e))?;
        }
        Ok(())
    }
}

fn valid_scope(s: &str) -> bool {
    s == "shared" || s == "instance"
}

/// What a request is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    /// A saved connection entry.
    Entry {
        scope: String,
        folder: String,
        entry: String,
    },
    /// An ad-hoc connection to a host (only `Target::Any` rules match it).
    AdHoc { host: String },
}

impl Resource {
    /// Stable key for grants and pending requests.
    pub fn key(&self) -> String {
        match self {
            Resource::Entry {
                scope,
                folder,
                entry,
            } => format!("entry:{}/{}/{}", scope, folder, entry),
            Resource::AdHoc { host } => format!("adhoc:{}", host),
        }
    }

    /// The key with the command folded in, so a grant or a waiting request
    /// for one command never covers another.
    pub fn key_for(&self, command: Option<&str>) -> String {
        match command {
            None => self.key(),
            Some(cmd) => {
                use sha2::{Digest, Sha256};
                let h = hex::encode(Sha256::digest(cmd.as_bytes()));
                format!("{}#cmd:{}", self.key(), &h[..32])
            }
        }
    }

    /// For people: "shared/Prod/web01", or "ad hoc: 10.0.0.5".
    pub fn label(&self) -> String {
        match self {
            Resource::Entry {
                scope,
                folder,
                entry,
            } => format!("{}/{}/{}", scope, folder, entry),
            Resource::AdHoc { host } => format!("ad hoc: {}", host),
        }
    }
}

/// The caller, as policies see them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    /// Login email; `None` for API keys.
    pub email: Option<String>,
    /// API key name; `None` for users.
    pub api_key: Option<String>,
    /// An AI agent, as `ai:<key-name>`.
    pub ai_agent: Option<String>,
    pub role: String,
    pub groups: Vec<String>,
}

impl Requester {
    pub fn from_identity(id: &AuthIdentity) -> Self {
        match id {
            AuthIdentity::ApiKey(name) => Requester {
                email: None,
                api_key: Some(name.clone()),
                ai_agent: None,
                role: "admin".into(),
                groups: Vec::new(),
            },
            AuthIdentity::User {
                email,
                role,
                groups,
            } => Requester {
                email: Some(email.clone()),
                api_key: None,
                ai_agent: None,
                role: role.clone(),
                groups: groups.clone(),
            },
            AuthIdentity::AiAgent(name) => Requester {
                email: None,
                api_key: None,
                ai_agent: Some(name.clone()),
                role: "ai_agent".into(),
                groups: Vec::new(),
            },
            // The person's rules and the AI client's both apply.
            AuthIdentity::AiUser {
                email,
                role,
                groups,
                client,
                ..
            } => Requester {
                email: Some(email.clone()),
                api_key: None,
                ai_agent: Some(format!("ai:{}", client)),
                role: role.clone(),
                groups: groups.clone(),
            },
        }
    }

    /// The identity a request and its grant belong to. A person acting
    /// through an AI client is `user:<email> via ai:<client>`, so their own
    /// approvals never cover what their AI does, nor the other way round.
    pub fn id(&self) -> String {
        match (&self.email, &self.api_key, &self.ai_agent) {
            (Some(e), _, Some(a)) => format!("user:{} via {}", e.to_ascii_lowercase(), a),
            (Some(e), _, _) => e.to_ascii_lowercase(),
            (None, Some(k), _) => format!("api-key:{}", k),
            (None, None, Some(a)) => a.clone(),
            (None, None, None) => "unknown".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision<'a> {
    /// `rule` is `None` when no rule matched.
    Allow {
        rule: Option<&'a Rule>,
        alert: bool,
    },
    RequireApproval {
        rule: &'a Rule,
    },
    Deny {
        rule: &'a Rule,
    },
}

/// Decide `action` on `res` for `who` under `rules`.
pub fn evaluate<'a>(
    rules: &'a [Rule],
    who: &Requester,
    action: Action,
    res: &Resource,
    command: Option<&str>,
) -> Decision<'a> {
    evaluate_in(rules, who, action, res, command, None)
}

/// `evaluate`, for one direction of a clipboard or file transfer.
fn evaluate_in<'a>(
    rules: &'a [Rule],
    who: &Requester,
    action: Action,
    res: &Resource,
    command: Option<&str>,
    direction: Option<Direction>,
) -> Decision<'a> {
    let matching: Vec<&Rule> = rules
        .iter()
        .filter(|r| {
            r.enabled
                && r.action == action
                && r.subject.matches(who)
                && r.target.matches(res)
                && r.matches_command(command)
                && (r.direction.is_none() || r.direction == direction)
        })
        .collect();
    if let Some(rule) = matching
        .iter()
        .filter(|r| r.effect == Effect::Deny)
        .max_by_key(|r| r.specificity())
    {
        return Decision::Deny { rule };
    }
    match matching.into_iter().max_by_key(|r| r.specificity()) {
        None => Decision::Allow {
            rule: None,
            alert: false,
        },
        Some(rule) => match rule.effect {
            Effect::Allow => Decision::Allow {
                rule: Some(rule),
                alert: false,
            },
            Effect::AllowAndAlert => Decision::Allow {
                rule: Some(rule),
                alert: true,
            },
            Effect::RequireApproval => Decision::RequireApproval { rule },
            Effect::Deny => Decision::Deny { rule },
        },
    }
}

/// Whether `who` may decide a request made by `requester_id` that names
/// `approvers`. People only: an API key is not someone who can vouch for a
/// request. Nobody decides their own request.
pub fn may_decide(
    approvers: &[Approver],
    who: &Requester,
    requester_id: &str,
) -> Result<(), String> {
    if who.email.is_none() {
        return Err("an API key cannot decide approval requests".into());
    }
    // Nor what their own AI client asks for.
    if who.id() == requester_id || requester_id.starts_with(&format!("user:{} via ", who.id())) {
        return Err("you cannot approve or deny your own request".into());
    }
    let eligible = approvers.iter().any(|a| match a {
        Approver::Role(r) => role_level(&who.role) >= role_level(r),
        Approver::Group(g) => who.groups.iter().any(|x| x == g),
    });
    if eligible {
        Ok(())
    } else {
        Err("you are not an approver for this request".into())
    }
}

/// What a session may do with the clipboard and file transfer, one value
/// per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transfer {
    #[default]
    Allow,
    /// Allowed, and each one goes to the audit log.
    Alert,
    Deny,
}

/// The clipboard and file transfer decisions for one session, and who and
/// what they were made for (for the audit rows the bridge writes).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct SessionControls {
    /// Clipboard out of the target.
    pub copy: Transfer,
    /// Clipboard into the target.
    pub paste: Transfer,
    pub upload: Transfer,
    pub download: Transfer,
    #[serde(skip)]
    pub actor: String,
    #[serde(skip)]
    pub requester: String,
    #[serde(skip)]
    pub target: String,
    /// Who and what the session is for, to check typed SSH lines against
    /// the command rules (`keylog.rs`).
    #[serde(skip)]
    pub who: Option<Requester>,
    #[serde(skip)]
    pub resource: Option<Resource>,
}

impl SessionControls {
    /// Evaluate the clipboard and file transfer rules for a session.
    pub fn decide(rules: &[Rule], who: &Requester, res: &Resource) -> Self {
        let one = |action, dir| match evaluate_in(rules, who, action, res, None, Some(dir)) {
            Decision::Allow { alert: false, .. } => Transfer::Allow,
            Decision::Allow { alert: true, .. } => Transfer::Alert,
            // `validate` refuses approval for these; treat one as a deny.
            Decision::RequireApproval { .. } | Decision::Deny { .. } => Transfer::Deny,
        };
        SessionControls {
            copy: one(Action::Clipboard, Direction::Out),
            paste: one(Action::Clipboard, Direction::In),
            upload: one(Action::FileTransfer, Direction::In),
            download: one(Action::FileTransfer, Direction::Out),
            actor: String::new(),
            requester: who.id(),
            target: res.label(),
            who: Some(who.clone()),
            resource: Some(res.clone()),
        }
    }
}

/// The clipboard and file transfer controls for `id` starting a session
/// on `res`.
pub async fn session_controls(
    db: &crate::db::Db,
    id: &AuthIdentity,
    res: Resource,
) -> Result<SessionControls, String> {
    let db = db.clone();
    let who = Requester::from_identity(id);
    let actor = id.display_name().to_string();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        let rules = store::list_rules(&conn).map_err(|e| e.to_string())?;
        Ok(SessionControls {
            actor,
            ..SessionControls::decide(&rules, &who, &res)
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// How long a break-glass override lasts.
pub const BREAK_GLASS_MINUTES: u32 = 60;
/// The shortest reason a break-glass override takes.
pub const MIN_BREAK_GLASS_REASON: usize = 10;

/// An admin overrides policy for themself: `action` on `res` (and for
/// `ssh_command`, that command) for `BREAK_GLASS_MINUTES`, deny included.
/// Withdraws their requests still waiting for the same thing. The caller
/// checks the role and a fresh sign-in.
#[allow(clippy::too_many_arguments)]
pub fn break_glass(
    conn: &rusqlite::Connection,
    who: &Requester,
    display: &str,
    action: Action,
    res: &Resource,
    command: Option<String>,
    reason: &str,
    ip: &str,
    now: i64,
) -> Result<store::ApprovalRequest, String> {
    let rid = who.id();
    let key = res.key_for(command.as_deref());
    let withdrawn = store::cancel_open(conn, &rid, action, &key, now).map_err(|e| e.to_string())?;
    let req = store::ApprovalRequest {
        id: uuid::Uuid::new_v4().to_string(),
        requester: rid.clone(),
        requester_display: display.to_string(),
        action: action.as_str().into(),
        resource: res.clone(),
        target_label: res.label(),
        command,
        policy_id: 0,
        policy_name: "break-glass".into(),
        approvers: Vec::new(),
        grant_minutes: BREAK_GLASS_MINUTES,
        reason: reason.to_string(),
        status: "approved".into(),
        created_at: now,
        expires_at: now,
        decided_at: Some(now),
        decided_by: Some(display.to_string()),
        comment: Some(reason.to_string()),
        grant_until: Some(now + i64::from(BREAK_GLASS_MINUTES) * 60),
        client_ip: Some(ip.to_string()),
        web_only: false,
        break_glass: true,
    };
    store::create_request(conn, &req).map_err(|e| e.to_string())?;
    store::audit(
        conn,
        &store::AuditEvent {
            event: "break_glass",
            actor: display,
            requester: &rid,
            action: action.as_str(),
            target: &req.target_label,
            policy: Some("break-glass"),
            approval_id: Some(&req.id),
            detail: Some(reason),
            ip: Some(ip),
            ..Default::default()
        },
        now,
    )
    .map_err(|e| e.to_string())?;
    let admin = display;
    tracing::warn!(
        admin,
        target = %req.target_label,
        action = action.as_str(),
        reason = reason,
        "Break-glass override"
    );
    for id in withdrawn {
        crate::telegram::notify(&id);
    }
    crate::telegram::notify(&req.id);
    Ok(req)
}

/// How recent a web sign-in must be to decide a web-only request.
pub const FRESH_SIGNIN_SECS: i64 = 15 * 60;

/// Where a decision comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The web UI or API; `fresh` when the caller signed in on the web UI
    /// within `FRESH_SIGNIN_SECS`.
    Web {
        fresh: bool,
    },
    Telegram,
}

#[derive(Debug, PartialEq)]
pub enum DecideError {
    NotFound,
    /// Not an approver, their own request, or web only from Telegram.
    Forbidden(String),
    /// A web-only request, and the caller's sign-in is not fresh.
    NeedsFreshSignIn,
    /// Already decided, or expired.
    Conflict(String),
    Db(String),
}

/// Approve or deny request `req_id` as `who`, with an audit row, and update
/// the Telegram messages for it. `by` is who the audit log names.
#[allow(clippy::too_many_arguments)]
pub fn decide_request(
    conn: &rusqlite::Connection,
    req_id: &str,
    who: &Requester,
    by: &str,
    comment: &str,
    approve: bool,
    via: Via,
    now: i64,
) -> Result<store::ApprovalRequest, DecideError> {
    let req = store::get_request(conn, req_id)
        .map_err(|e| DecideError::Db(e.to_string()))?
        .ok_or(DecideError::NotFound)?;
    may_decide(&req.approvers, who, &req.requester).map_err(DecideError::Forbidden)?;
    if req.web_only {
        match via {
            Via::Telegram => {
                return Err(DecideError::Forbidden(
                    "this request can only be decided on the web UI".into(),
                ))
            }
            Via::Web { fresh: false } => return Err(DecideError::NeedsFreshSignIn),
            Via::Web { fresh: true } => {}
        }
    }
    let done =
        store::decide(conn, req_id, approve, by, comment, now).map_err(DecideError::Conflict)?;
    let detail = match (via, comment.is_empty()) {
        (Via::Telegram, true) => Some("via Telegram".to_string()),
        (Via::Telegram, false) => Some(format!("via Telegram: {}", comment)),
        (Via::Web { .. }, false) => Some(comment.to_string()),
        (Via::Web { .. }, true) => None,
    };
    store::audit(
        conn,
        &store::AuditEvent {
            event: if approve {
                "approved"
            } else {
                "approval_denied"
            },
            actor: by,
            requester: &done.requester,
            action: &done.action,
            target: &done.target_label,
            policy: Some(&done.policy_name),
            approval_id: Some(&done.id),
            detail: detail.as_deref(),
            ..Default::default()
        },
        now,
    )
    .map_err(|e| DecideError::Db(e.to_string()))?;
    crate::telegram::notify(&done.id);
    Ok(done)
}

/// The outcome of a policy check for a request, after grants and pending
/// requests are taken into account.
pub enum Gate {
    Allowed,
    Denied {
        policy: String,
    },
    /// Waiting for an approver; the request was just created or already open.
    Pending(Box<store::ApprovalRequest>),
}

/// Check `action` on `res` for `id`, recording what the audit log needs:
/// denials, alerts, new requests and use of a grant. A required approval
/// becomes a request, or reuses the one already waiting.
pub async fn gate(
    db: &crate::db::Db,
    id: &AuthIdentity,
    action: Action,
    res: Resource,
    command: Option<String>,
    ip: String,
) -> Result<Gate, String> {
    gate_forced(db, id, action, res, command, ip, None).await
}

/// `gate`, where what the rules allow still needs approval under `forced`
/// (the folder's AI mode `approve`). A deny or a rule's own approval is
/// unchanged.
pub async fn gate_forced(
    db: &crate::db::Db,
    id: &AuthIdentity,
    action: Action,
    res: Resource,
    command: Option<String>,
    ip: String,
    forced: Option<Rule>,
) -> Result<Gate, String> {
    let db = db.clone();
    let who = Requester::from_identity(id);
    let display = id.display_name().to_string();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        let now = store::now_secs();
        let rules = store::list_rules(&conn).map_err(|e| e.to_string())?;
        let rid = who.id();
        let target = res.label();
        let audit = |e: store::AuditEvent| store::audit(&conn, &e, now).map_err(|e| e.to_string());
        let decision = match (
            evaluate(&rules, &who, action, &res, command.as_deref()),
            &forced,
        ) {
            (Decision::Allow { .. }, Some(rule)) => Decision::RequireApproval { rule },
            (d, _) => d,
        };
        match decision {
            Decision::Allow { rule, alert } => {
                if let (true, Some(rule)) = (alert, rule) {
                    audit(decision_event(
                        "alert", &display, &rid, action, &target, rule, &ip,
                    ))?;
                }
                Ok(Gate::Allowed)
            }
            Decision::Deny { rule } => {
                let key = res.key_for(command.as_deref());
                if let Some(grant) = store::active_break_glass(&conn, &rid, action, &key, now)
                    .map_err(|e| e.to_string())?
                {
                    audit(store::AuditEvent {
                        approval_id: Some(&grant.id),
                        ..decision_event(
                            "allowed_by_break_glass",
                            &display,
                            &rid,
                            action,
                            &target,
                            rule,
                            &ip,
                        )
                    })?;
                    return Ok(Gate::Allowed);
                }
                audit(decision_event(
                    "denied", &display, &rid, action, &target, rule, &ip,
                ))?;
                Ok(Gate::Denied {
                    policy: rule.name.clone(),
                })
            }
            Decision::RequireApproval { rule } => {
                let key = res.key_for(command.as_deref());
                if let Some(grant) = store::active_grant(&conn, &rid, action, &key, now)
                    .map_err(|e| e.to_string())?
                {
                    audit(store::AuditEvent {
                        approval_id: Some(&grant.id),
                        ..decision_event(
                            if grant.break_glass {
                                "allowed_by_break_glass"
                            } else {
                                "allowed_by_grant"
                            },
                            &display,
                            &rid,
                            action,
                            &target,
                            rule,
                            &ip,
                        )
                    })?;
                    return Ok(Gate::Allowed);
                }
                if let Some(open) = store::open_request(&conn, &rid, action, &key, now)
                    .map_err(|e| e.to_string())?
                {
                    return Ok(Gate::Pending(Box::new(open)));
                }
                let req = store::ApprovalRequest {
                    id: uuid::Uuid::new_v4().to_string(),
                    requester: rid.clone(),
                    requester_display: display.clone(),
                    action: action.as_str().into(),
                    resource: res.clone(),
                    target_label: target.clone(),
                    command: command.clone(),
                    policy_id: rule.id,
                    policy_name: rule.name.clone(),
                    approvers: rule.approvers.clone(),
                    grant_minutes: rule.grant_minutes,
                    reason: String::new(),
                    status: "pending".into(),
                    created_at: now,
                    expires_at: now + i64::from(rule.timeout_minutes) * 60,
                    decided_at: None,
                    decided_by: None,
                    comment: None,
                    grant_until: None,
                    client_ip: Some(ip.clone()),
                    web_only: rule.web_only,
                    break_glass: false,
                };
                store::create_request(&conn, &req).map_err(|e| e.to_string())?;
                crate::telegram::notify(&req.id);
                audit(store::AuditEvent {
                    approval_id: Some(&req.id),
                    ..decision_event("requested", &display, &rid, action, &target, rule, &ip)
                })?;
                Ok(Gate::Pending(Box::new(req)))
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Record a command run through the bastion in the policy audit log: who,
/// where, the command and how it ended. Its output is never kept.
pub async fn record_command(
    db: &crate::db::Db,
    id: &AuthIdentity,
    res: &Resource,
    command: &str,
    outcome: &Result<crate::ssh_exec::ExecOutput, String>,
    ip: String,
) {
    let (event, detail) = match outcome {
        Ok(o) => (
            "command_run",
            serde_json::json!({
                "command": command,
                "exit_status": o.exit_status,
                "signal": o.signal,
                "timed_out": o.timed_out,
                "duration_ms": o.duration_ms,
            }),
        ),
        Err(e) => (
            "command_failed",
            serde_json::json!({ "command": command, "error": e }),
        ),
    };
    let db = db.clone();
    let actor = id.display_name().to_string();
    let requester = Requester::from_identity(id).id();
    let target = res.label();
    let detail = detail.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        store::audit(
            &conn,
            &store::AuditEvent {
                event,
                actor: &actor,
                requester: &requester,
                action: Action::SshCommand.as_str(),
                target: &target,
                detail: Some(&detail),
                ip: Some(&ip),
                ..Default::default()
            },
            store::now_secs(),
        )
        .map_err(|e| e.to_string())
    })
    .await;
    if let Ok(Err(e)) | Err(e) = result.map_err(|e| e.to_string()) {
        tracing::error!(error = %e, "Failed to audit a command run");
    }
}

/// The audit row for a policy decision.
fn decision_event<'a>(
    event: &'a str,
    actor: &'a str,
    requester: &'a str,
    action: Action,
    target: &'a str,
    rule: &'a Rule,
    ip: &'a str,
) -> store::AuditEvent<'a> {
    store::AuditEvent {
        event,
        actor,
        requester,
        action: action.as_str(),
        target,
        policy: Some(&rule.name),
        effect: Some(rule.effect.as_str()),
        ip: Some(ip),
        ..Default::default()
    }
}

/// Expire requests nobody decided in time, every 30 seconds, with an audit
/// row for each.
pub fn spawn_expiry(db: crate::db::Db) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            let db = db.clone();
            let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<usize> {
                let conn = db.lock().unwrap();
                let now = store::now_secs();
                let due = store::expire_due(&conn, now)?;
                for r in &due {
                    crate::telegram::notify(&r.id);
                    store::audit(
                        &conn,
                        &store::AuditEvent {
                            event: "expired",
                            actor: "system",
                            requester: &r.requester,
                            action: &r.action,
                            target: &r.target_label,
                            policy: Some(&r.policy_name),
                            approval_id: Some(&r.id),
                            ..Default::default()
                        },
                        now,
                    )?;
                }
                Ok(due.len())
            })
            .await;
            match result {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => tracing::info!(count = n, "Approval requests expired"),
                Ok(Err(e)) => tracing::warn!(error = %e, "Expiring approval requests failed"),
                Err(e) => tracing::warn!(error = %e, "Approval expiry task failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(email: &str, role: &str, groups: &[&str]) -> Requester {
        Requester {
            email: Some(email.into()),
            api_key: None,
            ai_agent: None,
            role: role.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    fn rule(id: i64, subject: Subject, target: Target, effect: Effect) -> Rule {
        Rule {
            id,
            name: format!("r{id}"),
            subject,
            target,
            action: Action::Connect,
            effect,
            approvers: vec![Approver::Role("admin".into())],
            grant_minutes: 60,
            timeout_minutes: 30,
            enabled: true,
            commands: vec![],
            web_only: false,
            direction: None,
        }
    }

    fn folder(path: &str) -> Target {
        Target::Folder {
            scope: "shared".into(),
            path: path.into(),
        }
    }

    fn entry_in(folder: &str) -> Resource {
        Resource::Entry {
            scope: "shared".into(),
            folder: folder.into(),
            entry: "web01".into(),
        }
    }

    fn effect_of(d: &Decision) -> &'static str {
        match d {
            Decision::Allow { alert: false, .. } => "allow",
            Decision::Allow { alert: true, .. } => "alert",
            Decision::RequireApproval { .. } => "approval",
            Decision::Deny { .. } => "deny",
        }
    }

    #[test]
    fn no_rule_allows() {
        let who = user("a@x", "operator", &[]);
        assert_eq!(
            evaluate(&[], &who, Action::Connect, &entry_in("prod"), None),
            Decision::Allow {
                rule: None,
                alert: false
            }
        );
    }

    #[test]
    fn contractors_need_approval_for_prod_and_below() {
        let rules = [rule(
            1,
            Subject::Group("contractors".into()),
            folder("prod"),
            Effect::RequireApproval,
        )];
        let c = user("c@x", "operator", &["contractors"]);
        let staff = user("s@x", "operator", &["staff"]);
        for f in ["prod", "prod/web"] {
            assert_eq!(
                effect_of(&evaluate(&rules, &c, Action::Connect, &entry_in(f), None)),
                "approval"
            );
        }
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &c,
                Action::Connect,
                &entry_in("production"),
                None
            )),
            "allow"
        );
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &staff,
                Action::Connect,
                &entry_in("prod"),
                None
            )),
            "allow"
        );
        let other_scope = Resource::Entry {
            scope: "instance".into(),
            folder: "prod".into(),
            entry: "web01".into(),
        };
        assert_eq!(
            effect_of(&evaluate(&rules, &c, Action::Connect, &other_scope, None)),
            "allow"
        );
    }

    #[test]
    fn explicit_deny_always_wins() {
        let rules = [
            rule(
                1,
                Subject::User("c@x".into()),
                Target::Entry {
                    scope: "shared".into(),
                    folder: "prod".into(),
                    entry: "web01".into(),
                },
                Effect::Allow,
            ),
            rule(2, Subject::Any, Target::Any, Effect::Deny),
        ];
        let d = evaluate(
            &rules,
            &user("c@x", "admin", &[]),
            Action::Connect,
            &entry_in("prod"),
            None,
        );
        assert!(matches!(d, Decision::Deny { rule } if rule.id == 2));
    }

    #[test]
    fn most_specific_target_then_subject_wins() {
        let rules = [
            rule(
                1,
                Subject::User("c@x".into()),
                Target::Any,
                Effect::RequireApproval,
            ),
            rule(2, Subject::Any, folder("prod"), Effect::Allow),
            rule(3, Subject::Any, folder("prod/web"), Effect::AllowAndAlert),
            rule(
                4,
                Subject::Group("g".into()),
                folder("prod/web"),
                Effect::RequireApproval,
            ),
        ];
        let c = user("c@x", "operator", &[]);
        // Folder beats Any even though rule 1 names the user.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &c,
                Action::Connect,
                &entry_in("prod"),
                None
            )),
            "allow"
        );
        // The deeper folder wins.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &c,
                Action::Connect,
                &entry_in("prod/web"),
                None
            )),
            "alert"
        );
        // Same folder: the group subject beats Any.
        let g = user("g@x", "operator", &["g"]);
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &g,
                Action::Connect,
                &entry_in("prod/web"),
                None
            )),
            "approval"
        );
        // Elsewhere only rule 1 matches.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &c,
                Action::Connect,
                &entry_in("lab"),
                None
            )),
            "approval"
        );
    }

    #[test]
    fn equally_specific_rules_take_the_stricter_effect() {
        let rules = [
            rule(1, Subject::Group("a".into()), folder("prod"), Effect::Allow),
            rule(
                2,
                Subject::Group("b".into()),
                folder("prod"),
                Effect::RequireApproval,
            ),
        ];
        let who = user("x@x", "operator", &["a", "b"]);
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &who,
                Action::Connect,
                &entry_in("prod"),
                None
            )),
            "approval"
        );
    }

    #[test]
    fn disabled_rules_and_ad_hoc_targets() {
        let mut off = rule(1, Subject::Any, Target::Any, Effect::Deny);
        off.enabled = false;
        let rules = [off, rule(2, Subject::Any, folder("prod"), Effect::Deny)];
        let who = user("a@x", "poweruser", &[]);
        let adhoc = Resource::AdHoc {
            host: "10.0.0.5".into(),
        };
        // Folder rules never match an ad-hoc connection; the Any rule is off.
        assert_eq!(
            effect_of(&evaluate(&rules, &who, Action::Connect, &adhoc, None)),
            "allow"
        );
    }

    #[test]
    fn subjects_match_users_roles_and_api_keys() {
        let key = Requester {
            email: None,
            api_key: Some("ci".into()),
            ai_agent: None,
            role: "admin".into(),
            groups: vec![],
        };
        let rules = [
            rule(1, Subject::ApiKey("ci".into()), Target::Any, Effect::Deny),
            rule(
                2,
                Subject::Role("operator".into()),
                Target::Any,
                Effect::RequireApproval,
            ),
            rule(
                3,
                Subject::User("Pat@Example.com".into()),
                Target::Any,
                Effect::AllowAndAlert,
            ),
        ];
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &key,
                Action::Connect,
                &entry_in("x"),
                None
            )),
            "deny"
        );
        // A role rule is exact, and never matches an API key.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &user("o@x", "operator", &[]),
                Action::Connect,
                &entry_in("x"),
                None
            )),
            "approval"
        );
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &user("p@x", "poweruser", &[]),
                Action::Connect,
                &entry_in("x"),
                None
            )),
            "allow"
        );
        // Emails compare without case.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &user("pat@example.COM", "viewer", &[]),
                Action::Connect,
                &entry_in("x"),
                None
            )),
            "alert"
        );
    }

    #[test]
    fn deciding_requests() {
        let approvers = [
            Approver::Role("admin".into()),
            Approver::Group("secops".into()),
        ];
        let admin = user("boss@x", "admin", &[]);
        let sec = user("sec@x", "operator", &["secops"]);
        let op = user("op@x", "operator", &[]);
        assert!(may_decide(&approvers, &admin, "c@x").is_ok());
        assert!(may_decide(&approvers, &sec, "c@x").is_ok());
        assert!(may_decide(&approvers, &op, "c@x").is_err());
        // Never your own, whatever your role or case.
        let e = may_decide(&approvers, &admin, "boss@x").unwrap_err();
        assert!(e.contains("own"), "{e}");
        let key = Requester {
            email: None,
            api_key: Some("k".into()),
            ai_agent: None,
            role: "admin".into(),
            groups: vec![],
        };
        assert!(may_decide(&approvers, &key, "c@x").is_err());
    }

    fn cmd_rule(id: i64, patterns: &[&str], effect: Effect) -> Rule {
        let mut r = rule(id, Subject::Any, folder("prod"), effect);
        r.action = Action::SshCommand;
        r.commands = patterns.iter().map(|p| p.to_string()).collect();
        r
    }

    #[test]
    fn command_rules_match_on_the_command_line() {
        let rules = [
            cmd_rule(1, &[], Effect::Allow),
            cmd_rule(2, &[r"rm\s+-rf\s+/(\s|$)", r"^\s*shutdown\b"], Effect::Deny),
            cmd_rule(3, &[r"^systemctl\s+restart\b"], Effect::RequireApproval),
        ];
        let who = user("o@x", "operator", &[]);
        let run = |cmd: &str| {
            effect_of(&evaluate(
                &rules,
                &who,
                Action::SshCommand,
                &entry_in("prod"),
                Some(cmd),
            ))
        };
        assert_eq!(run("uptime"), "allow");
        assert_eq!(run("rm -rf /"), "deny");
        assert_eq!(run("sudo rm  -rf / --no-preserve-root"), "deny");
        assert_eq!(run("rm -rf /tmp/build"), "allow");
        assert_eq!(run("shutdown -h now"), "deny");
        assert_eq!(run("systemctl restart nginx"), "approval");
        // Connect rules are separate from command rules.
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &who,
                Action::Connect,
                &entry_in("prod"),
                None
            )),
            "allow"
        );
    }

    #[test]
    fn a_rule_with_patterns_beats_one_without() {
        let rules = [
            cmd_rule(1, &[], Effect::RequireApproval),
            cmd_rule(2, &[r"^(uptime|df -h)$"], Effect::Allow),
        ];
        let who = user("o@x", "operator", &[]);
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &who,
                Action::SshCommand,
                &entry_in("prod"),
                Some("uptime")
            )),
            "allow"
        );
        assert_eq!(
            effect_of(&evaluate(
                &rules,
                &who,
                Action::SshCommand,
                &entry_in("prod"),
                Some("reboot")
            )),
            "approval"
        );
    }

    #[test]
    fn grants_are_per_command() {
        let res = entry_in("prod");
        assert_eq!(res.key_for(None), res.key());
        assert_ne!(res.key_for(Some("uptime")), res.key_for(Some("reboot")));
        assert_eq!(res.key_for(Some("uptime")), res.key_for(Some("uptime")));
    }

    #[test]
    fn validation_catches_unusable_rules() {
        let mut r = rule(1, Subject::Group("".into()), folder("prod"), Effect::Allow);
        assert!(r.validate().is_err());
        r.subject = Subject::Role("superuser".into());
        assert!(r.validate().is_err());
        r.subject = Subject::Any;
        r.target = Target::Folder {
            scope: "global".into(),
            path: "prod".into(),
        };
        assert!(r.validate().is_err());
        r.target = folder("prod");
        r.effect = Effect::RequireApproval;
        r.approvers.clear();
        assert!(r.validate().is_err());
        r.approvers = vec![Approver::Group("ops".into())];
        assert!(r.validate().is_ok());
        // Patterns only on command rules, and they must compile.
        r.commands = vec!["^uptime$".into()];
        assert!(r.validate().is_err());
        r.action = Action::SshCommand;
        assert!(r.validate().is_ok());
        r.commands = vec!["(unclosed".into()];
        assert!(r.validate().unwrap_err().contains("bad command pattern"));
    }

    fn transfer_rule(id: i64, action: Action, dir: Option<Direction>, effect: Effect) -> Rule {
        let mut r = rule(id, Subject::Any, folder("prod"), effect);
        r.action = action;
        r.direction = dir;
        r
    }

    #[test]
    fn session_controls_follow_transfer_rules_per_direction() {
        let who = user("c@x", "operator", &["contractors"]);
        // No rules: everything allowed, as before.
        let open = SessionControls::decide(&[], &who, &entry_in("prod"));
        assert_eq!(
            (open.copy, open.paste, open.upload, open.download),
            (
                Transfer::Allow,
                Transfer::Allow,
                Transfer::Allow,
                Transfer::Allow
            )
        );
        let rules = [
            // Copying out of prod is denied, pasting in is fine.
            transfer_rule(1, Action::Clipboard, Some(Direction::Out), Effect::Deny),
            // File transfer is audited both ways, and a direction-specific
            // rule beats the general one: uploads are allowed quietly.
            transfer_rule(2, Action::FileTransfer, None, Effect::AllowAndAlert),
            transfer_rule(3, Action::FileTransfer, Some(Direction::In), Effect::Allow),
        ];
        let c = SessionControls::decide(&rules, &who, &entry_in("prod"));
        assert_eq!(
            (c.copy, c.paste, c.upload, c.download),
            (
                Transfer::Deny,
                Transfer::Allow,
                Transfer::Allow,
                Transfer::Alert
            )
        );
        assert_eq!(
            (c.requester.as_str(), c.target.as_str()),
            ("c@x", "shared/prod/web01")
        );
        // Outside prod, none apply; connect rules never do.
        let lab = SessionControls::decide(&rules, &who, &entry_in("lab"));
        assert_eq!(lab.copy, Transfer::Allow);
        let connect_only = [rule(4, Subject::Any, folder("prod"), Effect::Deny)];
        assert_eq!(
            SessionControls::decide(&connect_only, &who, &entry_in("prod")).copy,
            Transfer::Allow
        );
        // A direction rule never matches a connect.
        assert!(matches!(
            evaluate(&rules, &who, Action::Connect, &entry_in("prod"), None),
            Decision::Allow { rule: None, .. }
        ));
    }

    #[test]
    fn transfer_rules_validate() {
        let mut r = transfer_rule(1, Action::Clipboard, Some(Direction::Out), Effect::Deny);
        assert!(r.validate().is_ok());
        r.effect = Effect::RequireApproval;
        assert!(r
            .validate()
            .unwrap_err()
            .contains("cannot wait for approval"));
        let mut c = rule(2, Subject::Any, folder("prod"), Effect::Deny);
        c.direction = Some(Direction::In);
        assert!(c.validate().unwrap_err().contains("direction"));
    }

    fn db_with(rules: &[Rule]) -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        store::migrate(&c).unwrap();
        for r in rules {
            store::insert_rule(&c, r, "admin@x").unwrap();
        }
        c
    }

    #[test]
    fn break_glass_overrides_a_deny_for_that_admin_only() {
        let c = db_with(&[rule(0, Subject::Any, folder("prod"), Effect::Deny)]);
        let boss = user("boss@x", "admin", &[]);
        let res = entry_in("prod");
        let now = 1_000_000;
        let g = break_glass(
            &c,
            &boss,
            "boss@x",
            Action::Connect,
            &res,
            None,
            "database outage",
            "192.0.2.9",
            now,
        )
        .unwrap();
        assert!(g.break_glass && g.status == "approved");
        assert_eq!(
            g.grant_until,
            Some(now + i64::from(BREAK_GLASS_MINUTES) * 60)
        );
        let key = res.key();
        assert!(
            store::active_break_glass(&c, "boss@x", Action::Connect, &key, now + 60)
                .unwrap()
                .is_some()
        );
        // Not for anyone else, not after the window, not for another action.
        assert!(
            store::active_break_glass(&c, "other@x", Action::Connect, &key, now + 60)
                .unwrap()
                .is_none()
        );
        assert!(store::active_break_glass(
            &c,
            "boss@x",
            Action::Connect,
            &key,
            now + i64::from(BREAK_GLASS_MINUTES) * 60
        )
        .unwrap()
        .is_none());
        assert!(
            store::active_break_glass(&c, "boss@x", Action::SshCommand, &key, now + 60)
                .unwrap()
                .is_none()
        );
        // An ordinary grant is not a break-glass one.
        let audit = store::list_audit(&c, 10).unwrap();
        assert!(audit.iter().any(|r| r.event == "break_glass"
            && r.actor == "boss@x"
            && r.detail.as_deref() == Some("database outage")));
    }

    #[test]
    fn break_glass_withdraws_the_waiting_request() {
        let c = db_with(&[]);
        let boss = user("boss@x", "admin", &[]);
        let res = entry_in("prod");
        let now = 1_000_000;
        let waiting = store::ApprovalRequest {
            id: "w1".into(),
            requester: "boss@x".into(),
            requester_display: "boss@x".into(),
            action: "connect".into(),
            resource: res.clone(),
            target_label: res.label(),
            policy_id: 1,
            policy_name: "p".into(),
            approvers: vec![Approver::Role("admin".into())],
            grant_minutes: 60,
            reason: String::new(),
            status: "pending".into(),
            created_at: now,
            expires_at: now + 1800,
            decided_at: None,
            decided_by: None,
            comment: None,
            grant_until: None,
            client_ip: None,
            command: None,
            web_only: false,
            break_glass: false,
        };
        store::create_request(&c, &waiting).unwrap();
        break_glass(
            &c,
            &boss,
            "boss@x",
            Action::Connect,
            &res,
            None,
            "approver is asleep",
            "192.0.2.9",
            now + 5,
        )
        .unwrap();
        assert_eq!(
            store::get_request(&c, "w1").unwrap().unwrap().status,
            "cancelled"
        );
    }
}
