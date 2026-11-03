//! Clipboard and file-transfer filter on the WebSocket bridge.
//!
//! guacd is already told not to copy, paste, upload or download when a
//! policy denies it (`disable-copy`, `disable-upload`, …); this filter is the
//! second line, and the one that audits `allow_and_alert` transfers. It reads
//! the instructions that start a transfer, in each direction:
//!
//! - to the target (browser → guacd): `clipboard` (paste), `file` and `put`
//!   (upload);
//! - from the target (guacd → browser): `clipboard` (copy), `file` and `body`
//!   (download; a `body` with a directory listing is not a download), and
//!   `filesystem`, dropped when both upload and download are denied.
//!
//! A denied transfer is dropped along with its `blob`/`end` instructions, and
//! the sender is told with an `ack` carrying `CLIENT_FORBIDDEN`, so a browser
//! upload fails visibly and guacd closes its side of a download.

use std::collections::HashSet;

use super::{SessionControls, Transfer};
use crate::protocol::{last_instruction_boundary, Instruction};

/// Guacamole's `CLIENT_FORBIDDEN` status.
const FORBIDDEN: &str = "771";
/// The mimetype of a directory listing in a `body` reply.
const STREAM_INDEX_MIME: &str = "application/vnd.glyptodon.guacamole.stream-index+json";
/// The most a partial instruction may hold while the filter waits for its
/// end. Browser blobs are a few KiB; anything this large is refused.
const MAX_CARRY: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Browser → guacd.
    ToTarget,
    /// guacd → browser.
    FromTarget,
}

/// A transfer the filter saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// For the audit log: `clipboard_copy`, `clipboard_paste`,
    /// `file_upload`, `file_download`.
    pub kind: &'static str,
    pub blocked: bool,
    pub mimetype: String,
    pub name: Option<String>,
}

impl Event {
    pub fn action(&self) -> super::Action {
        if self.kind.starts_with("clipboard") {
            super::Action::Clipboard
        } else {
            super::Action::FileTransfer
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Filtered {
    /// What goes on to the other side.
    pub forward: String,
    /// Instructions back to the sender (`ack`s for dropped streams).
    pub reply: String,
    pub events: Vec<Event>,
}

pub struct TransferFilter {
    side: Side,
    clipboard: Transfer,
    file: Transfer,
    /// Both upload and download denied: hide the file browser.
    no_files: bool,
    /// Streams being dropped.
    dropped: HashSet<String>,
    carry: String,
}

impl TransferFilter {
    pub fn new(c: &SessionControls, side: Side) -> Self {
        let (clipboard, file) = match side {
            Side::ToTarget => (c.paste, c.upload),
            Side::FromTarget => (c.copy, c.download),
        };
        TransferFilter {
            side,
            clipboard,
            file,
            no_files: c.upload == Transfer::Deny && c.download == Transfer::Deny,
            dropped: HashSet::new(),
            carry: String::new(),
        }
    }

    /// Nothing to enforce or audit this way: data can go straight through.
    pub fn is_passthrough(&self) -> bool {
        self.clipboard == Transfer::Allow
            && self.file == Transfer::Allow
            && !(self.no_files && self.side == Side::FromTarget)
    }

    /// Filter the next chunk. A partial instruction at the end is held until
    /// the rest arrives. Errors when one grows past `MAX_CARRY`.
    pub fn filter(&mut self, text: &str) -> Result<Filtered, String> {
        self.carry.push_str(text);
        let end = last_instruction_boundary(self.carry.as_bytes()).unwrap_or(0);
        if end == 0 {
            if self.carry.len() > MAX_CARRY {
                return Err("instruction too large for the transfer filter".into());
            }
            return Ok(Filtered::default());
        }
        let complete: String = self.carry.drain(..end).collect();
        let mut out = Filtered::default();
        let mut pos = 0;
        while pos < complete.len() {
            let Some((elems, next)) = read_instruction(&complete, pos) else {
                // Unreachable for data before a proven boundary; pass it on.
                out.forward.push_str(&complete[pos..]);
                break;
            };
            let raw = &complete[pos..next];
            pos = next;
            self.one(&elems, raw, &mut out);
        }
        Ok(out)
    }

    fn one(&mut self, e: &[&str], raw: &str, out: &mut Filtered) {
        let arg = |i: usize| e.get(i).copied().unwrap_or("");
        match e[0] {
            "blob" | "end" if self.dropped.contains(arg(1)) => {
                if e[0] == "end" {
                    self.dropped.remove(arg(1));
                }
                return;
            }
            "filesystem" if self.side == Side::FromTarget && self.no_files => return,
            _ => {}
        }
        // (kind, policy, stream, mimetype, name)
        let started = match (self.side, e[0]) {
            (Side::ToTarget, "clipboard") => {
                Some(("clipboard_paste", self.clipboard, arg(1), arg(2), None))
            }
            (Side::ToTarget, "file") => {
                Some(("file_upload", self.file, arg(1), arg(2), Some(arg(3))))
            }
            (Side::ToTarget, "put") => {
                Some(("file_upload", self.file, arg(2), arg(3), Some(arg(4))))
            }
            (Side::FromTarget, "clipboard") => {
                Some(("clipboard_copy", self.clipboard, arg(1), arg(2), None))
            }
            (Side::FromTarget, "file") => {
                Some(("file_download", self.file, arg(1), arg(2), Some(arg(3))))
            }
            (Side::FromTarget, "body") if arg(3) != STREAM_INDEX_MIME => {
                Some(("file_download", self.file, arg(2), arg(3), Some(arg(4))))
            }
            _ => None,
        };
        let Some((kind, policy, stream, mimetype, name)) = started else {
            out.forward.push_str(raw);
            return;
        };
        let event = |blocked| Event {
            kind,
            blocked,
            mimetype: mimetype.to_string(),
            name: name.map(str::to_string),
        };
        match policy {
            Transfer::Allow => out.forward.push_str(raw),
            Transfer::Alert => {
                out.forward.push_str(raw);
                out.events.push(event(false));
            }
            Transfer::Deny => {
                self.dropped.insert(stream.to_string());
                out.reply.push_str(
                    &Instruction::new(
                        "ack",
                        vec![
                            stream.to_string(),
                            "Blocked by policy".into(),
                            FORBIDDEN.into(),
                        ],
                    )
                    .encode(),
                );
                out.events.push(event(true));
            }
        }
    }
}

/// Write the transfers a session's filter saw to the policy audit log, in
/// the background: `clipboard_copy`, `file_upload_blocked`, and so on.
pub fn audit(db: &crate::db::Db, c: &SessionControls, session_id: &str, events: Vec<Event>) {
    if events.is_empty() {
        return;
    }
    let (db, c, session_id) = (db.clone(), c.clone(), session_id.to_string());
    tokio::task::spawn_blocking(move || {
        let Ok(conn) = db.lock() else { return };
        let now = super::store::now_secs();
        for e in events {
            let event = if e.blocked {
                format!("{}_blocked", e.kind)
            } else {
                e.kind.to_string()
            };
            let detail = serde_json::json!({
                "session_id": session_id,
                "mimetype": e.mimetype,
                "name": e.name,
            })
            .to_string();
            let row = super::store::AuditEvent {
                event: &event,
                actor: &c.actor,
                requester: &c.requester,
                action: e.action().as_str(),
                target: &c.target,
                detail: Some(&detail),
                ..Default::default()
            };
            if let Err(err) = super::store::audit(&conn, &row, now) {
                tracing::warn!(error = %err, "Failed to audit a transfer");
            }
        }
    });
}

/// The first few elements of the instruction at byte `pos` of `s` (the
/// opcode and up to five arguments; the rest is skipped, not copied), and
/// the byte after its `;`. `None` when it is malformed or incomplete.
pub(super) fn read_instruction(s: &str, mut pos: usize) -> Option<(Vec<&str>, usize)> {
    let bytes = s.as_bytes();
    let mut elems = Vec::new();
    loop {
        let len_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == len_start || bytes.get(pos) != Some(&b'.') {
            return None;
        }
        let len: usize = s[len_start..pos].parse().ok()?;
        pos += 1;
        // Lengths count characters, not bytes.
        let start = pos;
        let end = match s[start..].char_indices().nth(len) {
            Some((i, _)) => start + i,
            None if s[start..].chars().count() == len => s.len(),
            None => return None,
        };
        if elems.len() < 6 {
            elems.push(&s[start..end]);
        }
        pos = end;
        match bytes.get(pos) {
            Some(b',') => pos += 1,
            Some(b';') => return Some((elems, pos + 1)),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode with lengths in characters, as guacd and the browser do.
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

    fn controls(
        copy: Transfer,
        paste: Transfer,
        upload: Transfer,
        download: Transfer,
    ) -> SessionControls {
        SessionControls {
            copy,
            paste,
            upload,
            download,
            ..Default::default()
        }
    }

    use Transfer::{Alert, Allow, Deny};

    #[test]
    fn open_controls_pass_everything_through() {
        let c = controls(Allow, Allow, Allow, Allow);
        assert!(TransferFilter::new(&c, Side::ToTarget).is_passthrough());
        assert!(TransferFilter::new(&c, Side::FromTarget).is_passthrough());
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        let paste = ins("clipboard", &["1", "text/plain"]) + &ins("blob", &["1", "aGk="]);
        assert_eq!(f.filter(&paste).unwrap().forward, paste);
    }

    #[test]
    fn a_denied_paste_is_dropped_with_its_blobs() {
        let c = controls(Allow, Deny, Allow, Allow);
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        let key = ins("key", &["65", "1"]);
        let data = ins("clipboard", &["3", "text/plain"])
            + &ins("blob", &["3", "c2VjcmV0"])
            + &key
            + &ins("blob", &["4", "b3RoZXI="])
            + &ins("end", &["3"]);
        let out = f.filter(&data).unwrap();
        assert_eq!(out.forward, key.clone() + &ins("blob", &["4", "b3RoZXI="]));
        assert_eq!(out.reply, ins("ack", &["3", "Blocked by policy", "771"]));
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].blocked && out.events[0].kind == "clipboard_paste");
        // Stream 3 is reusable after its end.
        assert_eq!(
            f.filter(&ins("blob", &["3", "eA=="])).unwrap().forward,
            ins("blob", &["3", "eA=="])
        );
    }

    #[test]
    fn an_instruction_split_across_messages_is_still_caught() {
        let c = controls(Allow, Deny, Allow, Allow);
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        let clip = ins("clipboard", &["5", "text/plain"]);
        let (a, b) = clip.split_at(7);
        let first = f.filter(a).unwrap();
        assert_eq!(first, Filtered::default());
        let second = f.filter(b).unwrap();
        assert!(second.forward.is_empty() && second.events[0].blocked);
    }

    #[test]
    fn uploads_and_downloads() {
        let c = controls(Allow, Allow, Deny, Alert);
        let mut to = TransferFilter::new(&c, Side::ToTarget);
        let out = to
            .filter(
                &(ins("file", &["7", "application/pdf", "plans.pdf"])
                    + &ins("put", &["0", "8", "text/plain", "/a.txt"])),
            )
            .unwrap();
        assert!(out.forward.is_empty());
        assert_eq!(
            out.events
                .iter()
                .map(|e| e.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("plans.pdf"), Some("/a.txt")]
        );
        assert_eq!(out.reply.matches("771").count(), 2);

        let mut from = TransferFilter::new(&c, Side::FromTarget);
        let listing = ins("body", &["0", "9", STREAM_INDEX_MIME, "/"]);
        let dl = ins("file", &["10", "application/zip", "dump.zip"]);
        let out = from.filter(&(listing.clone() + &dl)).unwrap();
        assert_eq!(out.forward, listing + &dl);
        assert_eq!(
            out.events,
            vec![Event {
                kind: "file_download",
                blocked: false,
                mimetype: "application/zip".into(),
                name: Some("dump.zip".into())
            }]
        );
    }

    #[test]
    fn a_denied_download_acks_guacd_and_hides_nothing_else() {
        let c = controls(Deny, Allow, Allow, Deny);
        let mut from = TransferFilter::new(&c, Side::FromTarget);
        let img = ins("img", &["1", "14", "0", "image/png", "0", "0"]);
        let out = from
            .filter(
                &(ins("clipboard", &["2", "text/plain"])
                    + &ins("blob", &["2", "eA=="])
                    + &img
                    + &ins("body", &["0", "3", "text/plain", "/etc/passwd"])
                    + &ins("end", &["2"])),
            )
            .unwrap();
        assert_eq!(out.forward, img);
        assert_eq!(
            out.reply,
            ins("ack", &["2", "Blocked by policy", "771"])
                + &ins("ack", &["3", "Blocked by policy", "771"])
        );
        // Upload is still allowed, so the file browser stays.
        let fs = ins("filesystem", &["0", "Shared Drive"]);
        assert_eq!(from.filter(&fs).unwrap().forward, fs);
    }

    #[test]
    fn no_file_transfer_at_all_hides_the_file_browser() {
        let c = controls(Allow, Allow, Deny, Deny);
        let mut from = TransferFilter::new(&c, Side::FromTarget);
        assert!(!from.is_passthrough());
        assert!(from
            .filter(&ins("filesystem", &["0", "Shared Drive"]))
            .unwrap()
            .forward
            .is_empty());
    }

    #[test]
    fn lengths_count_characters() {
        let c = controls(Allow, Deny, Allow, Allow);
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        let name = ins("file", &["1", "text/plain", "résumé ✓.txt"]);
        // Paste denied, uploads allowed: the file goes through untouched.
        let out = f.filter(&name).unwrap();
        assert!(out.forward == name && out.events.is_empty());
        let c = controls(Allow, Allow, Deny, Allow);
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        let out = f.filter(&name).unwrap();
        assert_eq!(out.events[0].name.as_deref(), Some("résumé ✓.txt"));
    }

    #[test]
    fn huge_partial_instructions_are_refused() {
        let c = controls(Allow, Deny, Allow, Allow);
        let mut f = TransferFilter::new(&c, Side::ToTarget);
        assert!(f.filter(&format!("{}.", MAX_CARRY + 10)).is_ok());
        assert!(f.filter(&"x".repeat(MAX_CARRY)).is_err());
    }
}
