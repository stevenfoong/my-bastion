// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Guacamole protocol instruction encoding and decoding.
//!
//! Wire format: `LENGTH.ELEMENT,LENGTH.ELEMENT,...;`
//! Example: `4.size,3.800,3.600;`

use std::fmt;

/// A single Guacamole protocol instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub opcode: String,
    pub args: Vec<String>,
}

impl Instruction {
    pub fn new(opcode: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            opcode: opcode.into(),
            args,
        }
    }

    /// Encode this instruction into Guacamole wire format.
    pub fn encode(&self) -> String {
        let mut out = encode_element(&self.opcode);
        for arg in &self.args {
            out.push(',');
            out.push_str(&encode_element(arg));
        }
        out.push(';');
        out
    }

    /// Parse a single instruction from a complete instruction string. The
    /// trailing `;` is optional.
    pub fn parse(data: &str) -> Result<Self, ParseError> {
        if data.is_empty() || data == ";" {
            return Err(ParseError::Empty);
        }
        let (inst, consumed) = parse_prefix(data, false)?;
        if consumed != data.len() {
            return Err(ParseError::UnexpectedChar);
        }
        Ok(inst)
    }
}

/// Parse the instruction at the start of `data`, returning it and the number
/// of bytes it took. Element lengths count Unicode characters (code points),
/// as guacd's `guac_parser_append` and guacamole-common-js do.
///
/// With `need_terminator`, running out of input before the `;` is
/// `Truncated` (the streaming parser waits for more); without it, the end of
/// input also ends the instruction.
fn parse_prefix(data: &str, need_terminator: bool) -> Result<(Instruction, usize), ParseError> {
    let bytes = data.as_bytes();
    let mut elements = Vec::new();
    let mut pos = 0usize;

    loop {
        // Length: ASCII digits up to the '.'.
        let len_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == len_start {
            if pos >= bytes.len() && need_terminator {
                return Err(ParseError::Truncated);
            }
            return Err(ParseError::InvalidLength);
        }
        let len: usize = data[len_start..pos]
            .parse()
            .map_err(|_| ParseError::InvalidLength)?;
        if pos >= bytes.len() {
            return Err(if need_terminator {
                ParseError::Truncated
            } else {
                ParseError::MalformedElement
            });
        }
        if bytes[pos] != b'.' {
            return Err(ParseError::MalformedElement);
        }
        pos += 1;

        // Value: `len` characters.
        let rest = &data[pos..];
        let value_len = match rest.char_indices().nth(len) {
            Some((i, _)) => i,
            None if rest.chars().count() == len => rest.len(),
            None => return Err(ParseError::Truncated),
        };
        elements.push(rest[..value_len].to_string());
        pos += value_len;

        // Terminator.
        match bytes.get(pos) {
            Some(b',') => pos += 1,
            Some(b';') => {
                pos += 1;
                break;
            }
            None if !need_terminator => break,
            None => return Err(ParseError::Truncated),
            Some(_) => return Err(ParseError::UnexpectedChar),
        }
    }

    let opcode = elements.remove(0);
    Ok((
        Instruction {
            opcode,
            args: elements,
        },
        pos,
    ))
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

fn encode_element(s: &str) -> String {
    // Length is the number of Unicode characters (code points), not bytes:
    // guacd's parser steps over `guac_utf8_charsize` bytes per counted
    // character, and guacamole-common-js uses `codePointCount`.
    format!("{}.{}", s.chars().count(), s)
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    MalformedElement,
    InvalidLength,
    Truncated,
    UnexpectedChar,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty instruction"),
            ParseError::MalformedElement => write!(f, "malformed element (missing '.')"),
            ParseError::InvalidLength => write!(f, "invalid length prefix"),
            ParseError::Truncated => write!(f, "instruction truncated"),
            ParseError::UnexpectedChar => write!(f, "unexpected character in instruction"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Find the byte offset just past the last complete Guacamole instruction in
/// `buf`. Returns `None` if no complete instruction is present.
///
/// Walks element-by-element using the wire format's length prefix (which
/// counts UTF-8 characters per `guac_utf8_strlen` in libguac), so element
/// data containing literal `;` characters (clipboard text, text streams)
/// does not produce a false boundary.
///
/// On the first malformed byte it returns the boundary discovered so far
/// rather than scanning the rest of the buffer.
pub fn last_instruction_boundary(buf: &[u8]) -> Option<usize> {
    let mut last_end: Option<usize> = None;
    let mut pos = 0usize;

    loop {
        // Each instruction is 1+ comma-separated elements, terminated by ';'.
        loop {
            // Length prefix: ASCII decimal digits up to the '.' separator.
            let len_start = pos;
            while pos < buf.len() && buf[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos == len_start || pos >= buf.len() || buf[pos] != b'.' {
                return last_end;
            }
            let len: usize = match std::str::from_utf8(&buf[len_start..pos])
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(n) => n,
                None => return last_end,
            };
            pos += 1; // skip '.'

            // Skip `len` UTF-8 characters of element data.
            let mut chars_skipped = 0;
            while chars_skipped < len {
                if pos >= buf.len() {
                    return last_end; // truncated mid-element
                }
                let b = buf[pos];
                let char_len = if b < 0x80 {
                    1
                } else if b < 0xC0 {
                    // Lone continuation byte — input is malformed UTF-8.
                    // Bail out with whatever boundary we've already proven.
                    return last_end;
                } else if b < 0xE0 {
                    2
                } else if b < 0xF0 {
                    3
                } else {
                    4
                };
                if pos + char_len > buf.len() {
                    return last_end; // truncated multibyte
                }
                pos += char_len;
                chars_skipped += 1;
            }

            // Element terminator.
            if pos >= buf.len() {
                return last_end;
            }
            match buf[pos] {
                b',' => {
                    pos += 1;
                    // Continue inner loop: next element of this instruction.
                }
                b';' => {
                    pos += 1;
                    last_end = Some(pos);
                    break; // Out of element loop; start scanning next instruction.
                }
                _ => return last_end,
            }
        }

        // Falls through on `;`: continue 'instructions to scan more.
        if pos >= buf.len() {
            return last_end;
        }
    }
}

/// Streaming parser that accumulates data and yields complete instructions.
#[derive(Default)]
pub struct InstructionParser {
    buffer: String,
}

impl InstructionParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed data into the parser and return any complete instructions.
    pub fn receive(&mut self, data: &str) -> Vec<Result<Instruction, ParseError>> {
        self.buffer.push_str(data);

        if self.buffer.len() > 1_048_576 {
            self.buffer.clear();
            return vec![];
        }

        let mut results = Vec::new();

        // Frame by element lengths, so a `;` inside an element value is data.
        loop {
            match parse_prefix(&self.buffer, true) {
                Ok((inst, consumed)) => {
                    self.buffer.drain(..consumed);
                    results.push(Ok(inst));
                }
                Err(ParseError::Truncated) => break,
                Err(e) => {
                    // Malformed: resynchronise after the next ';', if any yet.
                    match self.buffer.find(';') {
                        Some(semi) => {
                            self.buffer.drain(..=semi);
                            results.push(Err(e));
                        }
                        None => break,
                    }
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple() {
        let inst = Instruction::new("size", vec!["800".into(), "600".into()]);
        assert_eq!(inst.encode(), "4.size,3.800,3.600;");
    }

    #[test]
    fn test_encode_no_args() {
        let inst = Instruction::new("nop", vec![]);
        assert_eq!(inst.encode(), "3.nop;");
    }

    #[test]
    fn test_encode_select() {
        let inst = Instruction::new("select", vec!["ssh".into()]);
        assert_eq!(inst.encode(), "6.select,3.ssh;");
    }

    #[test]
    fn test_parse_simple() {
        let inst = Instruction::parse("4.size,3.800,3.600").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_with_semicolon() {
        let inst = Instruction::parse("4.size,3.800,3.600;").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_no_args() {
        let inst = Instruction::parse("3.nop").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert!(inst.args.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let original = Instruction::new(
            "connect",
            vec![
                "10.0.0.5".into(),
                "22".into(),
                "admin".into(),
                "password123".into(),
            ],
        );
        let encoded = original.encode();
        let parsed = Instruction::parse(&encoded).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_streaming_parser() {
        let mut parser = InstructionParser::new();

        // Feed partial data
        let results = parser.receive("4.size,3.80");
        assert!(results.is_empty());

        // Complete the instruction and start another
        let results = parser.receive("0,3.600;3.nop;");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().opcode, "size");
        assert_eq!(results[1].as_ref().unwrap().opcode, "nop");
    }

    // ── Adversarial parser cases ───────────────────────────────────────────
    // guacd is a trust boundary: even under compromise, the mybastion parser
    // must refuse to panic, must reject malformed frames cleanly, and must
    // bound memory. Every negative case here should produce a ParseError or
    // be dropped by the 1 MiB buffer cap — never a panic or OOM.

    #[test]
    fn parse_rejects_length_longer_than_data() {
        // Claims 10 bytes but only 3 are present.
        let err = Instruction::parse("10.abc").unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_rejects_non_numeric_length() {
        let err = Instruction::parse("x.size").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_negative_length() {
        // `-1` is not valid usize — must be rejected, not cast.
        let err = Instruction::parse("-1.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_overflow_length() {
        // 2^65 overflows usize on every platform and must be a clean error.
        let err = Instruction::parse("36893488147419103232.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_missing_dot() {
        let err = Instruction::parse("4size").unwrap_err();
        assert!(matches!(err, ParseError::MalformedElement));
    }

    #[test]
    fn parse_rejects_unexpected_separator() {
        // After the element body we must see `,` or end. A bare letter
        // should produce UnexpectedChar, not silently continue.
        let err = Instruction::parse("4.sizeX3.800").unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedChar));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(
            Instruction::parse("").unwrap_err(),
            ParseError::Empty
        ));
        assert!(matches!(
            Instruction::parse(";").unwrap_err(),
            ParseError::Empty
        ));
    }

    #[test]
    fn parse_rejects_byte_length_for_multibyte_char() {
        // '€' is one character but three bytes (E2 82 AC). A byte-counted
        // length of 3 asks for two characters that are not there.
        let err = Instruction::parse("3.€").unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_accepts_character_length() {
        let inst = Instruction::parse("1.€").unwrap();
        assert_eq!(inst.opcode, "€");
    }

    // ── Non-ASCII elements ─────────────────────────────────────────────────
    // Lengths count Unicode characters (code points), as guacd's parser
    // (`guac_utf8_charsize`) and guacamole-common-js (`codePointCount`) do.

    #[test]
    fn encode_counts_characters_not_bytes() {
        let inst = Instruction::new("résumé", vec!["🔑".into(), "p€ss".into()]);
        assert_eq!(inst.encode(), "6.résumé,1.🔑,4.p€ss;");
    }

    #[test]
    fn non_ascii_roundtrip_through_parse_and_boundary() {
        let original = Instruction::new(
            "connect",
            vec![
                "résumé.txt".into(),
                "pässwörd;🔑".into(),
                "".into(),
                "日本語".into(),
            ],
        );
        let encoded = original.encode();
        assert_eq!(Instruction::parse(&encoded).unwrap(), original);
        assert_eq!(
            last_instruction_boundary(encoded.as_bytes()),
            Some(encoded.len())
        );

        // Followed by a partial instruction, the boundary stays at the end of
        // the first one.
        let two = format!("{encoded}4.sync,3.12");
        assert_eq!(
            last_instruction_boundary(two.as_bytes()),
            Some(encoded.len())
        );
    }

    #[test]
    fn streaming_parser_non_ascii_split_at_every_char() {
        let a = Instruction::new("clipboard", vec!["0".into(), "a;é🙂".into()]);
        let b = Instruction::new("nop", vec![]);
        let full = format!("{}{}", a.encode(), b.encode());
        let mut parser = InstructionParser::new();
        let mut all = Vec::new();
        for ch in full.chars() {
            all.extend(parser.receive(ch.encode_utf8(&mut [0u8; 4])));
        }
        let all: Vec<_> = all.into_iter().map(Result::unwrap).collect();
        assert_eq!(all, vec![a, b]);
    }

    #[test]
    fn streaming_parser_keeps_semicolon_inside_element() {
        let mut parser = InstructionParser::new();
        let out = parser.receive("5.error,11.hello;world,3.519;3.nop;");
        assert_eq!(out.len(), 2);
        let err = out[0].as_ref().unwrap();
        assert_eq!(err.args, vec!["hello;world", "519"]);
        assert_eq!(out[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn parse_accepts_zero_length_element() {
        let inst = Instruction::parse("3.nop,0.,3.foo").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert_eq!(inst.args, vec!["", "foo"]);
    }

    #[test]
    fn parse_accepts_embedded_semicolon_within_length() {
        // Length includes the `;` so it's part of the element, not a
        // terminator. The caller's framing must respect length; this test
        // proves parse() honours the length over the semicolon.
        let inst = Instruction::parse("5.a;b;c").unwrap();
        assert_eq!(inst.opcode, "a;b;c");
    }

    #[test]
    fn streaming_parser_caps_buffer_at_1_mib() {
        // Feed > 1 MiB in a single receive with no terminator. The buffer
        // must clear in-place rather than grow unbounded, and the call
        // must return cleanly without panicking. After the clear, a fresh
        // well-formed frame parses normally.
        let mut parser = InstructionParser::new();
        let huge = "x".repeat(1_100_000);
        let out = parser.receive(&huge);
        // Over-cap input is dropped entirely (no partial instruction yield).
        assert!(out.is_empty());
        // Fresh input parses correctly — buffer is empty, no residue.
        let out2 = parser.receive("3.nop;");
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_split_at_every_boundary() {
        // Feed a well-formed frame byte-by-byte; the parser must assemble
        // correctly regardless of where chunks break.
        let full = "4.size,3.800,3.600;3.nop;";
        let mut parser = InstructionParser::new();
        let mut all = Vec::new();
        for ch in full.chars() {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            all.extend(parser.receive(s));
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_ref().unwrap().opcode, "size");
        assert_eq!(all[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_emits_error_for_malformed_frame() {
        // A malformed-but-terminated frame yields a Result::Err, not a panic.
        let mut parser = InstructionParser::new();
        let out = parser.receive("not-a-valid-instruction;3.nop;");
        assert_eq!(out.len(), 2);
        assert!(out[0].is_err());
        assert_eq!(out[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn boundary_empty_buffer() {
        assert_eq!(last_instruction_boundary(b""), None);
    }

    #[test]
    fn boundary_complete_instruction() {
        let s = b"4.size,3.800,3.600;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_partial_no_terminator() {
        assert_eq!(last_instruction_boundary(b"4.size,3.80"), None);
    }

    #[test]
    fn boundary_two_instructions_first_complete() {
        let s = b"4.size,3.800,3.600;3.foo";
        assert_eq!(last_instruction_boundary(s), Some(19));
    }

    #[test]
    fn boundary_two_instructions_both_complete() {
        let s = b"4.size,3.800,3.600;3.nop;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_ignores_semicolon_inside_element_value() {
        // Clipboard text containing `;`: the embedded `;` MUST NOT be treated
        // as an instruction terminator. Length prefix 11 covers "hello;world".
        let s = b"9.clipboard,1.0,11.hello;world;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_partial_when_split_inside_element_data() {
        // Reader landed mid-clipboard-element: only "hello;" of the 11-char
        // value is present. The trailing `;` is data, not a terminator.
        let s = b"9.clipboard,1.0,11.hello;";
        assert_eq!(last_instruction_boundary(s), None);
    }

    #[test]
    fn boundary_empty_opcode_ping() {
        // `0.,4.ping,13.1234567890123;` — empty opcode (length 0) is valid.
        let s = b"0.,4.ping,13.1234567890123;";
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_handles_utf8_multibyte_in_element() {
        // "café" — 4 UTF-8 chars, 5 bytes. Length prefix counts characters.
        let s = "9.clipboard,1.0,4.café;".as_bytes();
        assert_eq!(last_instruction_boundary(s), Some(s.len()));
    }

    #[test]
    fn boundary_truncated_mid_multibyte() {
        // "9.clipboard,1.0,4.caf" + first byte of "é" only — must not advance.
        let mut s = b"9.clipboard,1.0,4.caf".to_vec();
        s.push(0xC3); // first byte of `é` (UTF-8 0xC3 0xA9)
        assert_eq!(last_instruction_boundary(&s), None);
    }

    #[test]
    fn boundary_returns_last_complete_when_trailing_garbage() {
        // First instruction is complete; what follows is malformed. We
        // should still report the first boundary so the proxy can flush it.
        let s = b"3.nop;garbage";
        assert_eq!(last_instruction_boundary(s), Some(6));
    }
}
