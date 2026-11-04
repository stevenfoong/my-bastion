//! Input for a session, as the Guacamole instructions a browser would send:
//! `mouse,x,y,mask` and `key,keysym,pressed`.

use crate::protocol::Instruction;

/// Mouse buttons, as Guacamole's button mask.
pub const LEFT: u32 = 1;
pub const MIDDLE: u32 = 2;
pub const RIGHT: u32 = 4;
const WHEEL_UP: u32 = 8;
const WHEEL_DOWN: u32 = 16;

/// The longest text `type_text` takes in one call.
pub const MAX_TEXT: usize = 4000;
/// The most wheel clicks in one `scroll`.
pub const MAX_SCROLL: i32 = 50;

pub fn mouse(x: u32, y: u32, mask: u32) -> String {
    Instruction::new(
        "mouse",
        vec![x.to_string(), y.to_string(), mask.to_string()],
    )
    .encode()
}

pub fn key(keysym: u32, pressed: bool) -> String {
    Instruction::new(
        "key",
        vec![keysym.to_string(), if pressed { "1" } else { "0" }.into()],
    )
    .encode()
}

pub fn button(name: &str) -> Option<u32> {
    match name {
        "" | "left" => Some(LEFT),
        "middle" => Some(MIDDLE),
        "right" => Some(RIGHT),
        _ => None,
    }
}

/// Move to (x, y) and click `mask` once, or twice.
pub fn click(x: u32, y: u32, mask: u32, double: bool) -> String {
    let mut out = mouse(x, y, 0);
    for _ in 0..if double { 2 } else { 1 } {
        out += &mouse(x, y, mask);
        out += &mouse(x, y, 0);
    }
    out
}

/// Turn the wheel at (x, y): positive `dy` scrolls down.
pub fn scroll(x: u32, y: u32, dy: i32) -> String {
    let mask = if dy < 0 { WHEEL_UP } else { WHEEL_DOWN };
    let mut out = mouse(x, y, 0);
    for _ in 0..dy.unsigned_abs().min(MAX_SCROLL as u32) {
        out += &mouse(x, y, mask);
        out += &mouse(x, y, 0);
    }
    out
}

/// The keysym that types `c`.
fn char_keysym(c: char) -> u32 {
    match c {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        c if matches!(c as u32, 0x20..=0x7e | 0xa0..=0xff) => c as u32,
        c => 0x0100_0000 + c as u32,
    }
}

/// Press and release a key for each character.
pub fn text(s: &str) -> String {
    let mut out = String::new();
    let mut last_cr = false;
    for c in s.chars() {
        // A CRLF is one Return.
        if c == '\n' && last_cr {
            last_cr = false;
            continue;
        }
        last_cr = c == '\r';
        if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
            continue;
        }
        let k = char_keysym(c);
        out += &key(k, true);
        out += &key(k, false);
    }
    out
}

fn named_key(name: &str) -> Option<u32> {
    let k = match name {
        "ctrl" | "control" => 0xffe3,
        "alt" => 0xffe9,
        "shift" => 0xffe1,
        "win" | "super" | "meta" | "cmd" => 0xffeb,
        "altgr" => 0xfe03,
        "enter" | "return" => 0xff0d,
        "tab" => 0xff09,
        "esc" | "escape" => 0xff1b,
        "backspace" => 0xff08,
        "delete" | "del" => 0xffff,
        "insert" | "ins" => 0xff63,
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" | "pgup" => 0xff55,
        "pagedown" | "pgdn" => 0xff56,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "space" => 0x20,
        "printscreen" | "print" => 0xff61,
        "menu" => 0xff67,
        "capslock" => 0xffe5,
        "pause" => 0xff13,
        f if f.len() >= 2 && f.starts_with('f') => {
            let n: u32 = f[1..].parse().ok()?;
            if !(1..=24).contains(&n) {
                return None;
            }
            0xffbe + n - 1
        }
        _ => {
            let mut chars = name.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            char_keysym(c)
        }
    };
    Some(k)
}

/// A key combination such as `ctrl+alt+del`, `win+r`, `enter` or `shift+F10`:
/// every key pressed in order, then released in reverse. `None` names an
/// unknown key.
pub fn combo(spec: &str) -> Option<String> {
    let spec = spec.trim().to_ascii_lowercase();
    // "+" on its own (or at the end) is the plus key.
    let mut parts: Vec<String> = spec.split('+').map(|p| p.trim().to_string()).collect();
    if spec.ends_with("++") || spec == "+" {
        parts.retain(|p| !p.is_empty());
        parts.push("+".into());
    }
    if parts.iter().any(String::is_empty) || parts.len() > 6 {
        return None;
    }
    let keys: Vec<u32> = parts.iter().map(|p| named_key(p)).collect::<Option<_>>()?;
    let mut out = String::new();
    for k in &keys {
        out += &key(*k, true);
    }
    for k in keys.iter().rev() {
        out += &key(*k, false);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clicks_and_scrolls() {
        assert_eq!(
            click(10, 20, LEFT, false),
            "5.mouse,2.10,2.20,1.0;5.mouse,2.10,2.20,1.1;5.mouse,2.10,2.20,1.0;"
        );
        assert_eq!(click(1, 1, RIGHT, true).matches(",1.4;").count(), 2);
        assert_eq!(scroll(5, 5, -2).matches(",1.8;").count(), 2);
        assert_eq!(scroll(5, 5, 3).matches(",2.16;").count(), 3);
        assert_eq!(
            scroll(5, 5, 1000).matches(",2.16;").count(),
            MAX_SCROLL as usize
        );
        assert_eq!(button("middle"), Some(MIDDLE));
        assert_eq!(button("thumb"), None);
    }

    #[test]
    fn text_presses_and_releases_each_key() {
        assert_eq!(text("a"), "3.key,2.97,1.1;3.key,2.97,1.0;");
        // CRLF is one Return; other control characters are dropped.
        assert_eq!(text("a\r\nb\u{7}").matches("65293").count(), 2);
        assert_eq!(text("\u{7}"), "");
        // Beyond Latin-1, Unicode keysyms.
        assert!(text("✓").contains(&(0x0100_0000u32 + 0x2713).to_string()));
    }

    #[test]
    fn combos() {
        let c = combo("Ctrl+Alt+Del").unwrap();
        let order: Vec<&str> = c.split(';').filter(|s| !s.is_empty()).collect();
        assert_eq!(order.len(), 6);
        assert!(order[0].contains("65507") && order[0].ends_with("1.1"));
        assert!(order[2].contains("65535") && order[2].ends_with("1.1"));
        assert!(order[3].contains("65535") && order[3].ends_with("1.0"));
        assert!(order[5].contains("65507") && order[5].ends_with("1.0"));
        assert!(combo("win+r").unwrap().contains(",3.114,"));
        assert!(combo("F5").unwrap().contains(&0xffc2u32.to_string()));
        assert!(combo("ctrl++").unwrap().contains(",2.43,"));
        assert_eq!(combo("ctrl+nope"), None);
        assert_eq!(combo("f30"), None);
        assert_eq!(combo(""), None);
    }
}
