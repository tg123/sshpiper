use std::collections::BTreeMap;

use crate::{Error, Result};

pub fn extensions(packet: &[u8]) -> Result<BTreeMap<&str, &[u8]>> {
    let mut reader = Reader(packet);
    if reader.byte()? != 7 {
        return Err(Error::Protocol("expected SSH extension information"));
    }
    let mut extensions = BTreeMap::new();
    for _ in 0..reader.uint()? {
        let name = reader.text()?;
        let value = reader.string()?;
        if extensions.insert(name, value).is_some() {
            return Err(Error::Protocol("duplicate SSH extension"));
        }
    }
    reader.end()?;
    Ok(extensions)
}

pub fn string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

pub(crate) fn mpint(out: &mut Vec<u8>, value: &[u8]) {
    let start = value.iter().position(|b| *b != 0).unwrap_or(value.len());
    let value = &value[start..];
    let pad = value.first().is_some_and(|b| b & 0x80 != 0);
    out.extend_from_slice(&((value.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(value);
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(Error::Protocol("truncated message"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn boolean(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    pub fn text(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.string()?).map_err(|_| Error::Protocol("invalid UTF-8 string"))
    }

    pub fn uint(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.uint()? as usize;
        self.take(len)
    }

    pub fn end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("trailing message data"))
        }
    }
}
