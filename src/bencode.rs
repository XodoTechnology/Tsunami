//! Minimal bencode codec for the HTTP tracker protocol (BEP 3 / BEP 12).
//!
//! Supports decode of dicts/lists/ints/byte-strings and encode of the
//! response shapes trackers need. No allocation beyond what is required.

use std::collections::BTreeMap;
use std::io::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.get(key),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Parse a single bencode value from the front of `input`.
    /// Returns (value, bytes_consumed).
    pub fn decode(input: &[u8]) -> Result<(Value, usize), DecodeError> {
        let mut p = Parser { input, pos: 0 };
        let v = p.value()?;
        Ok((v, p.pos))
    }

    /// Decode an announce-style dictionary body (POST /announce).
    /// Tolerant: missing keys yield None.
    pub fn decode_dict(input: &[u8]) -> Result<BTreeMap<Vec<u8>, Value>, DecodeError> {
        match Self::decode(input)? {
            (Value::Dict(d), _) => Ok(d),
            _ => Err(DecodeError::Type),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Eof,
    Type,
    Overflow,
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        match self.peek().ok_or(DecodeError::Eof)? {
            b'i' => self.integer(),
            b'l' => self.list(),
            b'd' => self.dict(),
            b'0'..=b'9' => self.bytes(),
            _ => Err(DecodeError::Type),
        }
    }

    fn integer(&mut self) -> Result<Value, DecodeError> {
        self.pos += 1; // 'i'
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(DecodeError::Type);
        }
        let end = self.pos;
        if self.peek() != Some(b'e') {
            return Err(DecodeError::Type);
        }
        self.pos += 1;
        let s = std::str::from_utf8(&self.input[start..end]).map_err(|_| DecodeError::Type)?;
        let v: i64 = s.parse().map_err(|_| DecodeError::Overflow)?;
        Ok(Value::Int(v))
    }

    fn bytes(&mut self) -> Result<Value, DecodeError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() != Some(b':') {
            return Err(DecodeError::Type);
        }
        let len_str = std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| DecodeError::Type)?;
        let len: usize = len_str.parse().map_err(|_| DecodeError::Overflow)?;
        self.pos += 1; // ':'
        let end = self.pos.checked_add(len).ok_or(DecodeError::Overflow)?;
        if end > self.input.len() {
            return Err(DecodeError::Eof);
        }
        let out = self.input[self.pos..end].to_vec();
        self.pos = end;
        Ok(Value::Bytes(out))
    }

    fn list(&mut self) -> Result<Value, DecodeError> {
        self.pos += 1; // 'l'
        let mut items = Vec::new();
        loop {
            match self.peek().ok_or(DecodeError::Eof)? {
                b'e' => {
                    self.pos += 1;
                    return Ok(Value::List(items));
                }
                _ => items.push(self.value()?),
            }
        }
    }

    fn dict(&mut self) -> Result<Value, DecodeError> {
        self.pos += 1; // 'd'
        let mut map = BTreeMap::new();
        loop {
            match self.peek().ok_or(DecodeError::Eof)? {
                b'e' => {
                    self.pos += 1;
                    return Ok(Value::Dict(map));
                }
                b'0'..=b'9' => {
                    let k = match self.bytes()? {
                        Value::Bytes(b) => b,
                        _ => return Err(DecodeError::Type),
                    };
                    let v = self.value()?;
                    map.insert(k, v);
                }
                _ => return Err(DecodeError::Type),
            }
        }
    }
}

// ---------------- Encoding ----------------

/// Encode helpers producing a bencode byte string.
pub struct Encoder {
    pub buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn int(&mut self, v: i64) {
        let _ = write!(self.buf, "i{}e", v);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        let _ = write!(self.buf, "{}:", b.len());
        self.buf.extend_from_slice(b);
    }

    /// Begin a dict: writes 'd'. Caller must write keys/values then call `dict_end`.
    pub fn dict_begin(&mut self) {
        self.buf.push(b'd');
    }

    pub fn dict_end(&mut self) {
        self.buf.push(b'e');
    }

    pub fn list_begin(&mut self) {
        self.buf.push(b'l');
    }

    pub fn list_end(&mut self) {
        self.buf.push(b'e');
    }

    /// Dict key (raw bytes) followed by an int value.
    pub fn dict_int(&mut self, key: &[u8], v: i64) {
        self.bytes(key);
        self.int(v);
    }

    /// Dict key followed by a bytes value.
    pub fn dict_bytes(&mut self, key: &[u8], v: &[u8]) {
        self.bytes(key);
        self.bytes(v);
    }

    /// Dict key followed by a nested container already encoded into `v`.
    pub fn dict_raw(&mut self, key: &[u8], v: &[u8]) {
        self.bytes(key);
        self.buf.extend_from_slice(v);
    }

    /// Append a nested container already encoded into `v` to the current list.
    pub fn list_raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut e = Encoder::new();
        e.dict_begin();
        e.dict_int(b"interval", 900);
        e.dict_int(b"complete", 5);
        e.dict_bytes(b"name", b"test");
        e.dict_end();
        let bytes = e.into_vec();

        let (v, n) = Value::decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        let d = match v {
            Value::Dict(d) => d,
            _ => panic!(),
        };
        assert_eq!(d[b"interval".as_slice()].as_int(), Some(900));
        assert_eq!(d[b"name".as_slice()].as_str(), Some("test"));
    }

    #[test]
    fn nested() {
        let input = b"d3:foo3:bare1:xye";
        // intentionally malformed-ish; just ensure no panic path crashes
        let _ = Value::decode(input);
        let good = b"d1:ai1e1:bl4:spam4:eggsee";
        let (v, _) = Value::decode(good).unwrap();
        assert!(matches!(v, Value::Dict(_)));
    }
}
