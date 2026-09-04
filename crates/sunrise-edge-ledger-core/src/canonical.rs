//! Independent, from-scratch decoder for Sunrise Edge's canonical
//! field-framed wire format.
//!
//! This module deliberately does not depend on, share code with, or copy
//! source from the Sunrise Edge node workspace's `canonical-encoding` crate.
//! It reimplements the same documented wire shape from `SIGNING.md` so this
//! device application can independently verify frames a host claims are
//! canonical: a stable 4-byte magic, little-endian `type_id`/`version`/
//! `field_count` header, then that many `(field_id: u16 LE, len: u32 LE,
//! bytes)` entries with strictly increasing `field_id`s and no trailing
//! bytes.
//!
//! Given that shape, a successfully decoded frame is *already* the unique
//! canonical encoding of its fields: field order is forced ascending by the
//! strictly-increasing check (matching the encoder's own ascending-by-id
//! output), every field's length is exact (no padding or truncation is
//! possible), and no trailing or duplicate data survives decoding. A
//! defensive re-encode/compare round trip is therefore not needed to detect
//! non-canonical input for this fixed-width, length-prefixed shape; the
//! strict decode itself is the canonicality check.

/// Stable protocol magic prefixed to every canonical payload.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"SNRE";

/// Errors returned while decoding a canonical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    /// The input ended before a complete value could be read.
    Truncated,
    /// The protocol magic did not match [`PROTOCOL_MAGIC`].
    InvalidMagic,
    /// Field identifiers were not strictly increasing.
    NonCanonicalFieldOrder,
    /// Bytes remained after the declared fields.
    TrailingBytes,
    /// A requested field was absent.
    MissingField(u16),
    /// A schema decoder encountered a field it does not define.
    UnexpectedField(u16),
    /// A typed field had a different byte length than required.
    InvalidFieldLength {
        /// Field identifier.
        field_id: u16,
        /// Required byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// A string field was not valid UTF-8.
    InvalidUtf8(u16),
    /// A caller expected a different canonical type identifier.
    UnexpectedTypeId {
        /// Required type identifier.
        expected: u16,
        /// Decoded type identifier.
        actual: u16,
    },
    /// A caller expected a different encoding version.
    UnexpectedVersion {
        /// Required encoding version.
        expected: u16,
        /// Decoded encoding version.
        actual: u16,
    },
}

/// A validated, zero-copy view over one canonical frame.
///
/// Holding this view borrows `input`; no field is copied until a caller
/// explicitly extracts one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalFrame<'a> {
    type_id: u16,
    version: u16,
    field_count: u16,
    fields_start: usize,
    input: &'a [u8],
}

impl<'a> CanonicalFrame<'a> {
    /// Returns the decoded canonical type identifier.
    #[must_use]
    pub const fn type_id(&self) -> u16 {
        self.type_id
    }

    /// Returns the decoded encoding version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the number of decoded fields.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.field_count as usize
    }

    /// Checks the decoded type identifier.
    pub fn require_type(&self, expected: u16) -> Result<(), CanonicalError> {
        if self.type_id != expected {
            return Err(CanonicalError::UnexpectedTypeId {
                expected,
                actual: self.type_id,
            });
        }
        Ok(())
    }

    /// Checks the decoded encoding version.
    pub fn require_version(&self, expected: u16) -> Result<(), CanonicalError> {
        if self.version != expected {
            return Err(CanonicalError::UnexpectedVersion {
                expected,
                actual: self.version,
            });
        }
        Ok(())
    }

    /// Returns an optional raw field by re-scanning the field section.
    ///
    /// Re-scanning avoids storing a field table, keeping this type
    /// allocation-free; frames in this profile have at most a handful of
    /// fields, so the repeated linear scan is cheap and bounded by
    /// [`field_count`](Self::field_count).
    #[must_use]
    pub fn field(&self, field_id: u16) -> Option<&'a [u8]> {
        let mut offset = self.fields_start;
        for _ in 0..self.field_count {
            let id = read_u16(self.input, &mut offset).ok()?;
            let len = read_u32(self.input, &mut offset).ok()?;
            let len = usize::try_from(len).ok()?;
            let bytes = take(self.input, &mut offset, len).ok()?;
            if id == field_id {
                return Some(bytes);
            }
        }
        None
    }

    /// Returns a required raw field.
    pub fn required_field(&self, field_id: u16) -> Result<&'a [u8], CanonicalError> {
        self.field(field_id)
            .ok_or(CanonicalError::MissingField(field_id))
    }

    /// Rejects any field outside a schema's explicit allow-list.
    pub fn require_only_fields(&self, allowed: &[u16]) -> Result<(), CanonicalError> {
        let mut offset = self.fields_start;
        for _ in 0..self.field_count {
            let id = read_u16(self.input, &mut offset)?;
            let len = read_u32(self.input, &mut offset)?;
            let len = usize::try_from(len).map_err(|_| CanonicalError::Truncated)?;
            take(self.input, &mut offset, len)?;
            if !allowed.contains(&id) {
                return Err(CanonicalError::UnexpectedField(id));
            }
        }
        Ok(())
    }

    /// Decodes a required little-endian `u16` field.
    pub fn required_u16(&self, field_id: u16) -> Result<u16, CanonicalError> {
        let bytes = self.required_field(field_id)?;
        let array: [u8; 2] = bytes
            .try_into()
            .map_err(|_| CanonicalError::InvalidFieldLength {
                field_id,
                expected: 2,
                actual: bytes.len(),
            })?;
        Ok(u16::from_le_bytes(array))
    }

    /// Decodes a required little-endian `u32` field.
    pub fn required_u32(&self, field_id: u16) -> Result<u32, CanonicalError> {
        let bytes = self.required_field(field_id)?;
        let array: [u8; 4] = bytes
            .try_into()
            .map_err(|_| CanonicalError::InvalidFieldLength {
                field_id,
                expected: 4,
                actual: bytes.len(),
            })?;
        Ok(u32::from_le_bytes(array))
    }

    /// Decodes a required little-endian `u64` field.
    pub fn required_u64(&self, field_id: u16) -> Result<u64, CanonicalError> {
        let bytes = self.required_field(field_id)?;
        let array: [u8; 8] = bytes
            .try_into()
            .map_err(|_| CanonicalError::InvalidFieldLength {
                field_id,
                expected: 8,
                actual: bytes.len(),
            })?;
        Ok(u64::from_le_bytes(array))
    }

    /// Decodes a required fixed-length byte array field.
    pub fn required_array<const N: usize>(&self, field_id: u16) -> Result<[u8; N], CanonicalError> {
        let bytes = self.required_field(field_id)?;
        bytes
            .try_into()
            .map_err(|_| CanonicalError::InvalidFieldLength {
                field_id,
                expected: N,
                actual: bytes.len(),
            })
    }

    /// Decodes a required UTF-8 field.
    pub fn required_str(&self, field_id: u16) -> Result<&'a str, CanonicalError> {
        let bytes = self.required_field(field_id)?;
        core::str::from_utf8(bytes).map_err(|_| CanonicalError::InvalidUtf8(field_id))
    }
}

/// Decodes and validates one complete canonical frame without copying
/// fields.
///
/// Beyond the header and per-field shape, this validates: strictly
/// increasing field identifiers (which rejects both duplicates and
/// out-of-order fields in one check), that every declared field fits inside
/// `input`, and that no bytes remain after the last declared field.
pub fn decode_canonical_frame(input: &[u8]) -> Result<CanonicalFrame<'_>, CanonicalError> {
    let mut offset = 0_usize;
    let magic = take(input, &mut offset, PROTOCOL_MAGIC.len())?;
    if magic != PROTOCOL_MAGIC {
        return Err(CanonicalError::InvalidMagic);
    }
    let type_id = read_u16(input, &mut offset)?;
    let version = read_u16(input, &mut offset)?;
    let field_count = read_u16(input, &mut offset)?;
    let fields_start = offset;

    let mut previous: Option<u16> = None;
    for _ in 0..field_count {
        let field_id = read_u16(input, &mut offset)?;
        if let Some(previous_id) = previous {
            if field_id <= previous_id {
                return Err(CanonicalError::NonCanonicalFieldOrder);
            }
        }
        let field_len = read_u32(input, &mut offset)?;
        let field_len = usize::try_from(field_len).map_err(|_| CanonicalError::Truncated)?;
        take(input, &mut offset, field_len)?;
        previous = Some(field_id);
    }

    if offset != input.len() {
        return Err(CanonicalError::TrailingBytes);
    }

    Ok(CanonicalFrame {
        type_id,
        version,
        field_count,
        fields_start,
        input,
    })
}

fn read_u16(input: &[u8], offset: &mut usize) -> Result<u16, CanonicalError> {
    let bytes = take(input, offset, 2)?;
    let array: [u8; 2] = bytes.try_into().map_err(|_| CanonicalError::Truncated)?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32, CanonicalError> {
    let bytes = take(input, offset, 4)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| CanonicalError::Truncated)?;
    Ok(u32::from_le_bytes(array))
}

fn take<'a>(
    input: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], CanonicalError> {
    let start = *offset;
    let end = start.checked_add(length).ok_or(CanonicalError::Truncated)?;
    let bytes = input.get(start..end).ok_or(CanonicalError::Truncated)?;
    *offset = end;
    Ok(bytes)
}
