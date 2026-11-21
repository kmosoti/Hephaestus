//! Pure `#![no_std]` RFC 8785 (JCS) deterministic JSON canonicalizer for log metadata hashing.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use thiserror::Error;

/// Errors produced when parsing or canonicalizing JSON metadata.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JcsError {
    /// Unexpected token or syntax error at byte offset.
    #[error("invalid JSON syntax at byte offset {0}")]
    Syntax(usize),
    /// Nesting exceeded maximum supported depth.
    #[error("JSON nesting depth exceeded")]
    MaxDepth,
}

const MAX_DEPTH: usize = 64;

#[derive(Debug)]
enum JsonVal {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonVal>),
    Object(Vec<(String, JsonVal)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    const fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonVal, JcsError> {
        if depth > MAX_DEPTH {
            return Err(JcsError::MaxDepth);
        }
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_lit(b"null").map(|()| JsonVal::Null),
            Some(b't') => self.parse_lit(b"true").map(|()| JsonVal::Bool(true)),
            Some(b'f') => self.parse_lit(b"false").map(|()| JsonVal::Bool(false)),
            Some(b'"') => self.parse_string().map(JsonVal::Str),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(JsonVal::Number),
            _ => Err(JcsError::Syntax(self.pos)),
        }
    }

    fn parse_lit(&mut self, lit: &[u8]) -> Result<(), JcsError> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(JcsError::Syntax(self.pos))
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JcsError> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or(JcsError::Syntax(self.pos))?;
        let mut val = 0u16;
        for &b in slice {
            let d = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return Err(JcsError::Syntax(self.pos)),
            };
            val = (val << 4) | d;
        }
        self.pos += 4;
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, JcsError> {
        if self.peek() != Some(b'"') {
            return Err(JcsError::Syntax(self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = *self.bytes.get(self.pos).ok_or(JcsError::Syntax(self.pos))?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err(JcsError::Syntax(self.pos));
                            }
                            self.pos += 2;
                            let low = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(JcsError::Syntax(self.pos));
                            }
                            let cp = 0x10000
                                + (((u32::from(code) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
                            let ch = char::from_u32(cp).ok_or(JcsError::Syntax(self.pos))?;
                            out.push(ch);
                        } else {
                            let ch = char::from_u32(u32::from(code))
                                .ok_or(JcsError::Syntax(self.pos))?;
                            out.push(ch);
                        }
                    }
                    _ => return Err(JcsError::Syntax(self.pos)),
                }
            } else if b < 0x20 {
                return Err(JcsError::Syntax(self.pos));
            } else {
                let rest = core::str::from_utf8(&self.bytes[self.pos..])
                    .map_err(|_| JcsError::Syntax(self.pos))?;
                let ch = rest.chars().next().ok_or(JcsError::Syntax(self.pos))?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err(JcsError::Syntax(self.pos))
    }

    fn parse_number(&mut self) -> Result<String, JcsError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JcsError::Syntax(self.pos)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JcsError::Syntax(self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JcsError::Syntax(self.pos));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let raw = core::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JcsError::Syntax(start))?;
        // Normalize integer -0 to 0 and validate finite IEEE-754 number.
        if raw == "-0" {
            return Ok(String::from("0"));
        }
        let val: f64 = raw.parse().map_err(|_| JcsError::Syntax(start))?;
        if !val.is_finite() {
            return Err(JcsError::Syntax(start));
        }
        if val == 0.0 {
            Ok(String::from("0"))
        } else {
            Ok(String::from(raw))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonVal, JcsError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonVal::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonVal::Array(items));
                }
                _ => return Err(JcsError::Syntax(self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonVal, JcsError> {
        self.pos += 1; // '{'
        let mut entries: Vec<(String, JsonVal)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonVal::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(JcsError::Syntax(self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            if let Some(existing) = entries.iter_mut().find(|(k, _)| k == &key) {
                existing.1 = val;
            } else {
                entries.push((key, val));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonVal::Object(entries));
                }
                _ => return Err(JcsError::Syntax(self.pos)),
            }
        }
    }
}

fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_jcs_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.push_str("\\u00");
                out.push(HEX[((code >> 4) & 0xF) as usize] as char);
                out.push(HEX[(code & 0xF) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_jcs(val: &mut JsonVal, out: &mut String) {
    match val {
        JsonVal::Null => out.push_str("null"),
        JsonVal::Bool(true) => out.push_str("true"),
        JsonVal::Bool(false) => out.push_str("false"),
        JsonVal::Number(n) => out.push_str(n),
        JsonVal::Str(s) => write_jcs_string(s, out),
        JsonVal::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter_mut().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs(item, out);
            }
            out.push(']');
        }
        JsonVal::Object(entries) => {
            entries.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
            out.push('{');
            for (idx, (k, v)) in entries.iter_mut().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_string(k, out);
                out.push(':');
                write_jcs(v, out);
            }
            out.push('}');
        }
    }
}

/// Parses and canonicalizes JSON per RFC 8785 (sorted UTF-16 object keys, minimal whitespace).
pub fn canonicalize_json(input: &str) -> Result<String, JcsError> {
    let mut parser = Parser::new(input);
    let mut val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(JcsError::Syntax(parser.pos));
    }
    let mut out = String::with_capacity(input.len());
    write_jcs(&mut val, &mut out);
    Ok(out)
}
