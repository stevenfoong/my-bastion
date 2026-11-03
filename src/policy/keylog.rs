//! Interactive SSH command log: the lines a user types into an SSH session,
//! rebuilt from the keystrokes the browser sends on the WebSocket bridge.
//!
//! guacd draws the terminal as images, so the bridge never sees what the
//! shell echoes, only what is typed. The log is therefore **best-effort**,
//! good for review and alerting, never for blocking:
//!
//! - Line editing is followed (backspace, delete, cursor keys, Home/End,
//!   Ctrl+A/E/U/K/W/H, Ctrl+C), and so is a paste (Ctrl+Shift+V, or the right
//!   or middle mouse button, of the clipboard the browser last sent).
//! - Tab completion, history (Up/Down, Ctrl+R), Alt and Escape sequences
//!   change the line in ways only the shell knows: such a line is logged as
//!   `uncertain`. Editors and pagers (vi, less) are logged as typed.
//! - What a user types at a password prompt has no echo, and the bridge
//!   cannot tell a prompt from a shell. The line right after a command that
//!   usually asks for a password (`sudo`, `su`, `ssh`, …) is not stored when
//!   it is one word typed within a minute: it is logged as `redacted`.
//!
//! Each line is checked against the `ssh_command` rules as if it were run
//! through `run_ssh`; one that would be denied, held by a rule with command
//! patterns, or allowed with an alert is alerted (policy audit log, server
//! log and the Telegram `chat_ids`).

use std::sync::OnceLock;

use base64::Engine;
use rusqlite::{params, Connection};
use serde::Serialize;

use super::filter::read_instruction;
use super::{evaluate, Action, Decision, Effect, SessionControls};
use crate::protocol::last_instruction_boundary;

/// The longest line kept; the rest is cut and the line marked uncertain.
const MAX_LINE: usize = 4096;
/// The longest clipboard text remembered for a paste.
const MAX_CLIPBOARD: usize = 64 * 1024;
/// How long after a password-prompting command the next word is redacted.
const REDACT_SECS: u64 = 60;
/// The most a partial instruction may hold. Key and mouse instructions are
/// tiny; clipboard blobs are a few KiB.
const MAX_CARRY: usize = 1024 * 1024;

/// Commands after which the next one-word line is probably a password.
const PROMPTING: &str = r"^\s*(sudo|su|passwd|ssh|scp|sftp|rsync|mysql|mariadb|psql|kinit|htpasswd|gpg|openssl|ftp|telnet|(docker|podman|helm|vault|bao)\s+login)\b";

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Set once at startup from `[ssh_log] enabled`.
pub fn configure(enabled: bool) {
    let _ = ENABLED.set(enabled);
}

pub fn enabled() -> bool {
    *ENABLED.get().unwrap_or(&true)
}

// ── Keysyms ──

const BACKSPACE: u32 = 0xff08;
const TAB: u32 = 0xff09;
const RETURN: u32 = 0xff0d;
const ESCAPE: u32 = 0xff1b;
const HOME: u32 = 0xff50;
const LEFT: u32 = 0xff51;
const UP: u32 = 0xff52;
const RIGHT: u32 = 0xff53;
const DOWN: u32 = 0xff54;
const PAGE_UP: u32 = 0xff55;
const PAGE_DOWN: u32 = 0xff56;
const END: u32 = 0xff57;
const KP_ENTER: u32 = 0xff8d;
const DELETE: u32 = 0xffff;
const SHIFT_L: u32 = 0xffe1;
const SHIFT_R: u32 = 0xffe2;
const CONTROL_L: u32 = 0xffe3;
const CONTROL_R: u32 = 0xffe4;
const META_L: u32 = 0xffe7;
const ALT_R: u32 = 0xffea;

/// The character a keysym types, if it types one.
fn keysym_char(k: u32) -> Option<char> {
    match k {
        0x20..=0x7e | 0xa0..=0xff => char::from_u32(k),
        0x0100_0100..=0x0110_ffff => char::from_u32(k - 0x0100_0000),
        _ => None,
    }
}

/// A line the user entered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Line {
    pub text: String,
    /// Tab completion, history or the like changed it: the shell may have
    /// run something else.
    pub uncertain: bool,
    /// Some of it was pasted.
    pub pasted: bool,
    /// Probably a password: `text` is empty.
    pub redacted: bool,
}

/// Rebuilds typed lines from key events.
#[derive(Debug, Default)]
pub struct LineReader {
    buf: Vec<char>,
    cursor: usize,
    uncertain: bool,
    pasted: bool,
    ctrl: bool,
    alt: bool,
}

impl LineReader {
    /// One key event; the lines it completed.
    pub fn key(&mut self, keysym: u32, pressed: bool) -> Option<Line> {
        match keysym {
            CONTROL_L | CONTROL_R => {
                self.ctrl = pressed;
                return None;
            }
            META_L..=ALT_R => {
                self.alt = pressed;
                return None;
            }
            SHIFT_L | SHIFT_R => return None,
            _ if !pressed => return None,
            _ => {}
        }
        if self.alt {
            // Meta sequences: word moves, history, readline commands.
            self.uncertain = true;
            return None;
        }
        if self.ctrl {
            return match keysym_char(keysym).map(|c| c.to_ascii_lowercase()) {
                Some('c') => {
                    self.clear();
                    None
                }
                Some('j') | Some('m') => self.enter(),
                Some('a') => {
                    self.cursor = 0;
                    None
                }
                Some('e') => {
                    self.cursor = self.buf.len();
                    None
                }
                Some('u') => {
                    self.buf.drain(..self.cursor);
                    self.cursor = 0;
                    None
                }
                Some('k') => {
                    self.buf.truncate(self.cursor);
                    None
                }
                Some('w') => {
                    let mut start = self.cursor;
                    while start > 0 && self.buf[start - 1] == ' ' {
                        start -= 1;
                    }
                    while start > 0 && self.buf[start - 1] != ' ' {
                        start -= 1;
                    }
                    self.buf.drain(start..self.cursor);
                    self.cursor = start;
                    None
                }
                Some('h') => {
                    self.backspace();
                    None
                }
                Some('d') => {
                    self.delete();
                    None
                }
                Some('b') => self.left(),
                Some('f') => self.right(),
                // Ctrl+Shift+V is a paste, handled by the caller; Ctrl+L
                // only redraws.
                Some('v') | Some('l') => None,
                _ => {
                    self.uncertain = true;
                    None
                }
            };
        }
        match keysym {
            RETURN | KP_ENTER => self.enter(),
            BACKSPACE => {
                self.backspace();
                None
            }
            DELETE => {
                self.delete();
                None
            }
            LEFT => self.left(),
            RIGHT => self.right(),
            HOME => {
                self.cursor = 0;
                None
            }
            END => {
                self.cursor = self.buf.len();
                None
            }
            TAB | UP | DOWN | PAGE_UP | PAGE_DOWN | ESCAPE => {
                self.uncertain = true;
                None
            }
            k => {
                if let Some(c) = keysym_char(k) {
                    self.insert(c);
                }
                None
            }
        }
    }

    /// Pasted text: inserted where the cursor is; each line break enters a
    /// line.
    pub fn paste(&mut self, text: &str) -> Vec<Line> {
        let mut out = Vec::new();
        let text = text.replace("\r\n", "\n");
        for c in text.chars() {
            if c == '\n' || c == '\r' {
                self.pasted = true;
                out.extend(self.enter());
            } else if !c.is_control() || c == '\t' {
                self.pasted = true;
                self.insert(if c == '\t' { ' ' } else { c });
            }
        }
        out
    }

    fn insert(&mut self, c: char) {
        if self.buf.len() >= MAX_LINE {
            self.uncertain = true;
            return;
        }
        self.buf.insert(self.cursor, c);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.buf.remove(self.cursor);
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.buf.len() {
            self.buf.remove(self.cursor);
        }
    }

    fn left(&mut self) -> Option<Line> {
        self.cursor = self.cursor.saturating_sub(1);
        None
    }

    fn right(&mut self) -> Option<Line> {
        self.cursor = (self.cursor + 1).min(self.buf.len());
        None
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.uncertain = false;
        self.pasted = false;
    }

    fn enter(&mut self) -> Option<Line> {
        let text: String = self.buf.iter().collect();
        let line = Line {
            text: text.trim().to_string(),
            uncertain: self.uncertain,
            pasted: self.pasted,
            redacted: false,
        };
        self.clear();
        // An empty line with history or completion may still have run
        // something.
        (!line.text.is_empty() || line.uncertain).then_some(line)
    }
}

/// Watches the instructions a browser sends to an SSH session and turns its
/// keystrokes, clipboard and pastes into lines.
pub struct SshWatch {
    reader: LineReader,
    /// The clipboard the browser last gave guacd: what a paste inserts.
    clipboard: String,
    /// A text clipboard stream being received: (stream, base64 so far).
    incoming: Option<(String, String)>,
    mouse: u32,
    carry: String,
    /// Until when (seconds) the next one-word line is redacted.
    redact_until: Option<u64>,
    prompting: regex::Regex,
}

impl Default for SshWatch {
    fn default() -> Self {
        SshWatch {
            reader: LineReader::default(),
            clipboard: String::new(),
            incoming: None,
            mouse: 0,
            carry: String::new(),
            redact_until: None,
            prompting: regex::Regex::new(PROMPTING).expect("valid pattern"),
        }
    }
}

impl SshWatch {
    /// The next chunk the browser sent (after the transfer filter), at
    /// `now` (seconds). Errors when a partial instruction grows too large.
    pub fn observe(&mut self, text: &str, now: u64) -> Result<Vec<Line>, String> {
        self.carry.push_str(text);
        let end = last_instruction_boundary(self.carry.as_bytes()).unwrap_or(0);
        if end == 0 {
            if self.carry.len() > MAX_CARRY {
                self.carry.clear();
                return Err("instruction too large for the SSH command log".into());
            }
            return Ok(Vec::new());
        }
        let complete: String = self.carry.drain(..end).collect();
        let mut lines = Vec::new();
        let mut pos = 0;
        while pos < complete.len() {
            let Some((e, next)) = read_instruction(&complete, pos) else {
                break;
            };
            pos = next;
            self.one(&e, &mut lines);
        }
        Ok(lines.into_iter().map(|l| self.redact(l, now)).collect())
    }

    fn one(&mut self, e: &[&str], lines: &mut Vec<Line>) {
        let arg = |i: usize| e.get(i).copied().unwrap_or("");
        match e[0] {
            "key" => {
                let (Ok(k), pressed) = (arg(1).parse::<u32>(), arg(2) == "1") else {
                    return;
                };
                // Ctrl+Shift+V: guacd pastes its clipboard.
                if pressed && self.reader.ctrl && k == 'V' as u32 {
                    let clip = self.clipboard.clone();
                    lines.extend(self.reader.paste(&clip));
                    return;
                }
                lines.extend(self.reader.key(k, pressed));
            }
            "mouse" => {
                let mask: u32 = arg(3).parse().unwrap_or(0);
                // Releasing the middle (2) or right (4) button pastes.
                let released = self.mouse & !mask;
                self.mouse = mask;
                if released & 0b110 != 0 {
                    let clip = self.clipboard.clone();
                    lines.extend(self.reader.paste(&clip));
                }
            }
            "clipboard" if arg(2).starts_with("text/") => {
                self.incoming = Some((arg(1).to_string(), String::new()));
            }
            "blob" => {
                if let Some((stream, data)) = self.incoming.as_mut() {
                    if stream == arg(1) && data.len() < MAX_CLIPBOARD * 2 {
                        data.push_str(arg(2));
                    }
                }
            }
            "end" if self.incoming.as_ref().is_some_and(|(s, _)| s == arg(1)) => {
                let (_, data) = self.incoming.take().unwrap_or_default();
                self.clipboard = decode_blobs(&data);
            }
            _ => {}
        }
    }

    fn redact(&mut self, mut line: Line, now: u64) -> Line {
        if self.redact_until.take().is_some_and(|until| now <= until)
            && !line.text.is_empty()
            && !line.text.contains(char::is_whitespace)
            && !line.pasted
        {
            line.text.clear();
            line.redacted = true;
            return line;
        }
        if self.prompting.is_match(&line.text) {
            self.redact_until = Some(now + REDACT_SECS);
        }
        line
    }
}

/// Clipboard blobs are base64 chunks, each padded on its own.
fn decode_blobs(data: &str) -> String {
    let mut bytes = Vec::new();
    let engine = base64::engine::general_purpose::STANDARD;
    let mut rest = data;
    while !rest.is_empty() {
        // A chunk ends after its padding, or at the end.
        let end = rest
            .find('=')
            .map(|i| {
                let pad = rest[i..].chars().take_while(|&c| c == '=').count();
                i + pad
            })
            .unwrap_or(rest.len());
        if let Ok(b) = engine.decode(&rest[..end]) {
            bytes.extend(b);
        }
        rest = &rest[end..];
    }
    let mut s = String::from_utf8_lossy(&bytes).into_owned();
    if s.len() > MAX_CLIPBOARD {
        let mut cut = MAX_CLIPBOARD;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

// ── Store ──

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ssh_command_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            at          INTEGER NOT NULL,
            session_id  TEXT NOT NULL,
            actor       TEXT NOT NULL,
            requester   TEXT NOT NULL DEFAULT '',
            target      TEXT NOT NULL DEFAULT '',
            line        TEXT NOT NULL,
            uncertain   INTEGER NOT NULL DEFAULT 0,
            pasted      INTEGER NOT NULL DEFAULT 0,
            redacted    INTEGER NOT NULL DEFAULT 0,
            policy      TEXT,
            effect      TEXT
        );
        CREATE INDEX IF NOT EXISTS ssh_command_log_session ON ssh_command_log (session_id, id);
        CREATE INDEX IF NOT EXISTS ssh_command_log_at ON ssh_command_log (at);",
    )
}

#[derive(Debug, Serialize)]
pub struct CommandRow {
    pub id: i64,
    pub at: i64,
    pub session_id: String,
    pub actor: String,
    pub requester: String,
    pub target: String,
    pub line: String,
    pub uncertain: bool,
    pub pasted: bool,
    pub redacted: bool,
    /// The rule that alerted on it, and its effect.
    pub policy: Option<String>,
    pub effect: Option<String>,
}

/// Newest first. `session` narrows to one session; `q` to lines, actors or
/// targets containing it.
pub fn list(
    conn: &Connection,
    session: Option<&str>,
    q: Option<&str>,
    alerts_only: bool,
    limit: u32,
) -> rusqlite::Result<Vec<CommandRow>> {
    let like = q.map(|q| {
        format!(
            "%{}%",
            q.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let mut stmt = conn.prepare(
        "SELECT id, at, session_id, actor, requester, target, line, uncertain, pasted, redacted,
             policy, effect
         FROM ssh_command_log
         WHERE (?1 IS NULL OR session_id = ?1)
           AND (?2 IS NULL OR line LIKE ?2 ESCAPE '\\' OR actor LIKE ?2 ESCAPE '\\'
                OR target LIKE ?2 ESCAPE '\\')
           AND (?3 = 0 OR policy IS NOT NULL)
         ORDER BY id DESC LIMIT ?4",
    )?;
    let rows = stmt.query_map(params![session, like, alerts_only as i64, limit], |r| {
        Ok(CommandRow {
            id: r.get(0)?,
            at: r.get(1)?,
            session_id: r.get(2)?,
            actor: r.get(3)?,
            requester: r.get(4)?,
            target: r.get(5)?,
            line: r.get(6)?,
            uncertain: r.get::<_, i64>(7)? != 0,
            pasted: r.get::<_, i64>(8)? != 0,
            redacted: r.get::<_, i64>(9)? != 0,
            policy: r.get(10)?,
            effect: r.get(11)?,
        })
    })?;
    rows.collect()
}

/// Drop lines older than `days`; how many.
pub fn prune(conn: &Connection, days: u32, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM ssh_command_log WHERE at < ?1",
        [now - i64::from(days) * 86_400],
    )
}

/// The rule a line alerts on, if any: one that would deny it through
/// `run_ssh`, hold it with a command pattern, or allow it with an alert.
fn alerting<'a>(
    rules: &'a [super::Rule],
    c: &SessionControls,
    line: &Line,
) -> Option<&'a super::Rule> {
    let (Some(who), Some(res)) = (&c.who, &c.resource) else {
        return None;
    };
    if line.redacted || line.text.is_empty() {
        return None;
    }
    match evaluate(rules, who, Action::SshCommand, res, Some(&line.text)) {
        Decision::Deny { rule } => Some(rule),
        Decision::RequireApproval { rule } if !rule.commands.is_empty() => Some(rule),
        Decision::Allow {
            rule: Some(rule),
            alert: true,
        } => Some(rule),
        _ => None,
    }
}

/// A writer for the lines `actor` types in session `session_id`: stores
/// them, in order, and alerts on the ones a command rule flags. The task
/// ends when the sender is dropped.
pub fn recorder(
    db: crate::db::Db,
    c: SessionControls,
    session_id: String,
    actor: String,
) -> tokio::sync::mpsc::UnboundedSender<Vec<Line>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<Line>>();
    tokio::spawn(async move {
        while let Some(lines) = rx.recv().await {
            let (db, c, session_id, actor) =
                (db.clone(), c.clone(), session_id.clone(), actor.clone());
            let _ = tokio::task::spawn_blocking(move || write(&db, &c, &session_id, &actor, lines))
                .await;
        }
    });
    tx
}

fn write(db: &crate::db::Db, c: &SessionControls, session_id: &str, actor: &str, lines: Vec<Line>) {
    let Ok(conn) = db.lock() else { return };
    let now = super::store::now_secs();
    let rules = super::store::list_rules(&conn).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Cannot load policies for the SSH command log");
        Vec::new()
    });
    for line in lines {
        let hit = alerting(&rules, c, &line);
        if let Err(e) = conn.execute(
            "INSERT INTO ssh_command_log (at, session_id, actor, requester, target, line,
                     uncertain, pasted, redacted, policy, effect)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                now,
                session_id,
                actor,
                c.requester,
                c.target,
                line.text,
                line.uncertain as i64,
                line.pasted as i64,
                line.redacted as i64,
                hit.map(|r| r.name.as_str()),
                hit.map(|r| r.effect.as_str()),
            ],
        ) {
            tracing::warn!(error = %e, "Failed to log an SSH command");
            continue;
        }
        let Some(rule) = hit else { continue };
        tracing::warn!(
            session_id = %session_id,
            actor = %actor,
            target = %c.target,
            policy = %rule.name,
            "Interactive SSH command flagged by policy"
        );
        let detail = serde_json::json!({
            "session_id": session_id,
            "line": line.text,
            "uncertain": line.uncertain,
        })
        .to_string();
        let row = super::store::AuditEvent {
            event: "ssh_command_alert",
            actor,
            requester: &c.requester,
            action: Action::SshCommand.as_str(),
            target: &c.target,
            policy: Some(&rule.name),
            effect: Some(rule.effect.as_str()),
            detail: Some(&detail),
            ..Default::default()
        };
        if let Err(e) = super::store::audit(&conn, &row, now) {
            tracing::warn!(error = %e, "Failed to audit an SSH command alert");
        }
        crate::telegram::alert(crate::telegram::CommandAlert {
            actor: actor.to_string(),
            target: c.target.clone(),
            line: line.text.clone(),
            policy: rule.name.clone(),
            denied: rule.effect == Effect::Deny,
            uncertain: line.uncertain,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(op: &str, args: &[&str]) -> String {
        let el = |s: &str| format!("{}.{}", s.chars().count(), s);
        let mut out = el(op);
        for a in args {
            out.push(',');
            out.push_str(&el(a));
        }
        out.push(';');
        out
    }

    fn key(k: u32, pressed: bool) -> String {
        ins("key", &[&k.to_string(), if pressed { "1" } else { "0" }])
    }

    /// Press and release each character, then Return.
    fn typed(s: &str) -> String {
        let mut out = String::new();
        for c in s.chars() {
            let k = if (c as u32) < 0x100 {
                c as u32
            } else {
                c as u32 + 0x0100_0000
            };
            out += &key(k, true);
            out += &key(k, false);
        }
        out
    }

    fn enter() -> String {
        key(RETURN, true) + &key(RETURN, false)
    }

    fn ctrl(c: char) -> String {
        key(CONTROL_L, true) + &key(c as u32, true) + &key(c as u32, false) + &key(CONTROL_L, false)
    }

    fn texts(lines: &[Line]) -> Vec<&str> {
        lines.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn typed_lines_are_rebuilt() {
        let mut w = SshWatch::default();
        let lines = w
            .observe(
                &(typed("ls -la /etc") + &enter() + &typed("uptime") + &enter()),
                0,
            )
            .unwrap();
        assert_eq!(texts(&lines), vec!["ls -la /etc", "uptime"]);
        assert!(lines.iter().all(|l| !l.uncertain && !l.pasted));
    }

    #[test]
    fn editing_keys_are_followed() {
        let mut w = SshWatch::default();
        // "rm -rf /tmp/x", fixed up with backspace, cursor moves and Ctrl+U.
        let s = typed("echo nope")
            + &ctrl('u')
            + &typed("rm -rf /tmpx")
            + &key(LEFT, true)
            + &typed("/")
            + &key(END, true)
            + &key(BACKSPACE, true)
            + &typed("y")
            + &enter();
        assert_eq!(texts(&w.observe(&s, 0).unwrap()), vec!["rm -rf /tmp/y"]);
        // Ctrl+W deletes a word, Ctrl+C drops the line.
        let s = typed("cat /etc/shadow") + &ctrl('w') + &typed("hosts") + &enter();
        assert_eq!(texts(&w.observe(&s, 0).unwrap()), vec!["cat hosts"]);
        let s = typed("reboot") + &ctrl('c') + &typed("date") + &enter();
        assert_eq!(texts(&w.observe(&s, 0).unwrap()), vec!["date"]);
    }

    #[test]
    fn completion_and_history_make_a_line_uncertain() {
        let mut w = SshWatch::default();
        let s = typed("systemctl rest") + &key(TAB, true) + &typed(" nginx") + &enter();
        let lines = w.observe(&s, 0).unwrap();
        assert!(lines[0].uncertain);
        // History recall with nothing typed is still logged.
        let lines = w.observe(&(key(UP, true) + &enter()), 0).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].uncertain && lines[0].text.is_empty());
        // Empty lines are not.
        assert!(w.observe(&enter(), 0).unwrap().is_empty());
    }

    #[test]
    fn pastes_are_followed() {
        let mut w = SshWatch::default();
        let b64 = base64::engine::general_purpose::STANDARD.encode("whoami\nid -u");
        let clip = ins("clipboard", &["3", "text/plain"])
            + &ins("blob", &["3", &b64])
            + &ins("end", &["3"]);
        assert!(w.observe(&clip, 0).unwrap().is_empty());
        // Ctrl+Shift+V pastes: the first line runs, the second waits.
        let paste = key(CONTROL_L, true)
            + &key(SHIFT_L, true)
            + &key('V' as u32, true)
            + &key('V' as u32, false)
            + &key(SHIFT_L, false)
            + &key(CONTROL_L, false);
        let lines = w.observe(&paste, 0).unwrap();
        assert_eq!(texts(&lines), vec!["whoami"]);
        assert!(lines[0].pasted);
        let lines = w.observe(&(typed(" -n") + &enter()), 0).unwrap();
        assert_eq!(texts(&lines), vec!["id -u -n"]);
        // A right click pastes too.
        let click = ins("mouse", &["5", "5", "4"]) + &ins("mouse", &["5", "5", "0"]);
        let lines = w.observe(&click, 0).unwrap();
        assert_eq!(texts(&lines), vec!["whoami"]);
    }

    #[test]
    fn the_word_after_sudo_is_redacted() {
        let mut w = SshWatch::default();
        let lines = w
            .observe(
                &(typed("sudo -i") + &enter() + &typed("hunter2") + &enter()),
                100,
            )
            .unwrap();
        assert_eq!(texts(&lines), vec!["sudo -i", ""]);
        assert!(lines[1].redacted);
        // Only the next line, and only within the window.
        let lines = w.observe(&(typed("whoami") + &enter()), 101).unwrap();
        assert!(!lines[0].redacted);
        w.observe(&(typed("ssh db01") + &enter()), 200).unwrap();
        let lines = w
            .observe(&(typed("uptime") + &enter()), 200 + REDACT_SECS + 1)
            .unwrap();
        assert_eq!(texts(&lines), vec!["uptime"]);
        // A line with spaces is a command, not a password.
        w.observe(&(typed("su -") + &enter()), 300).unwrap();
        let lines = w.observe(&(typed("ls /root") + &enter()), 301).unwrap();
        assert_eq!(texts(&lines), vec!["ls /root"]);
    }

    #[test]
    fn unicode_and_split_instructions() {
        let mut w = SshWatch::default();
        let s = typed("echo héllo ✓") + &enter();
        let (a, b) = s.split_at(s.len() / 2 + 1);
        let mut lines = w.observe(a, 0).unwrap();
        lines.extend(w.observe(b, 0).unwrap());
        assert_eq!(texts(&lines), vec!["echo héllo ✓"]);
    }

    #[test]
    fn blobs_are_decoded_chunk_by_chunk() {
        let e = base64::engine::general_purpose::STANDARD;
        let data = e.encode("ab") + &e.encode("cde") + &e.encode("f");
        assert_eq!(decode_blobs(&data), "abcdef");
    }

    fn rule(name: &str, effect: Effect, commands: &[&str]) -> super::super::Rule {
        super::super::Rule {
            id: 1,
            name: name.into(),
            subject: super::super::Subject::Any,
            target: super::super::Target::Any,
            action: Action::SshCommand,
            effect,
            approvers: vec![super::super::Approver::Role("admin".into())],
            grant_minutes: 60,
            timeout_minutes: 30,
            enabled: true,
            commands: commands.iter().map(|s| s.to_string()).collect(),
            web_only: false,
            direction: None,
        }
    }

    #[test]
    fn alerts_follow_the_command_rules() {
        let c = SessionControls {
            who: Some(super::super::Requester {
                email: Some("op@x".into()),
                api_key: None,
                ai_agent: None,
                role: "operator".into(),
                groups: vec![],
            }),
            resource: Some(super::super::Resource::AdHoc {
                host: "10.0.0.5".into(),
            }),
            ..Default::default()
        };
        let line = |t: &str| Line {
            text: t.into(),
            ..Default::default()
        };
        let rules = vec![
            rule("no rm", Effect::Deny, &[r"rm\s+-rf"]),
            rule("approve all", Effect::RequireApproval, &[]),
            rule("watch shutdown", Effect::AllowAndAlert, &["shutdown"]),
        ];
        let name = |t: &str| alerting(&rules, &c, &line(t)).map(|r| r.name.clone());
        assert_eq!(name("rm -rf /var"), Some("no rm".into()));
        assert_eq!(name("shutdown -h now"), Some("watch shutdown".into()));
        // Held by a rule without patterns: that is command mode's business.
        assert_eq!(name("uptime"), None);
        let held = vec![rule(
            "approve restarts",
            Effect::RequireApproval,
            &["restart"],
        )];
        assert!(alerting(&held, &c, &line("systemctl restart nginx")).is_some());
        // Redacted lines are never checked.
        let mut r = line("rm -rf /");
        r.redacted = true;
        assert!(alerting(&rules, &c, &r).is_none());
    }

    #[test]
    fn lines_are_stored_and_searched() {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        for (i, l) in ["ls", "cat 50%_off", "uptime"].iter().enumerate() {
            c.execute(
                "INSERT INTO ssh_command_log (at, session_id, actor, line, policy)
                 VALUES (?1, ?2, 'op@x', ?3, ?4)",
                params![
                    i as i64,
                    if i == 2 { "s2" } else { "s1" },
                    l,
                    (i == 1).then_some("p")
                ],
            )
            .unwrap();
        }
        let all = list(&c, None, None, false, 10).unwrap();
        assert_eq!(
            all.iter().map(|r| r.line.as_str()).collect::<Vec<_>>(),
            vec!["uptime", "cat 50%_off", "ls"]
        );
        assert_eq!(list(&c, Some("s1"), None, false, 10).unwrap().len(), 2);
        assert_eq!(list(&c, None, Some("50%_"), false, 10).unwrap().len(), 1);
        assert_eq!(list(&c, None, Some("%"), false, 10).unwrap().len(), 1);
        assert_eq!(
            list(&c, None, None, true, 10).unwrap()[0].line,
            "cat 50%_off"
        );
        assert_eq!(prune(&c, 1, 86_402).unwrap(), 2);
    }
}
