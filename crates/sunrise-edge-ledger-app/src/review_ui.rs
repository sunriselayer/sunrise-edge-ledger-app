//! Bounded, allocation-free UI formatting for the 32 clear-signed facts.
//!
//! Every displayed fact is a pure function of the exact signed frame bytes,
//! matching the 32 lines defined in Hardware Signing Profile v1 and verified
//! by `RECOGNIZED_TRANSFER_LINES`. No host-supplied display metadata is ever
//! accepted or shown.

use core::str;
use sunrise_edge_ledger_core::review::ClearSigningReview;
use sunrise_edge_ledger_core::types::Digest32;

/// Maximum ASCII length of a clear-signing review line value (see `SIGNING.md`:
/// "bytes per ASCII display line | 96").
pub const MAX_FACT_LEN: usize = 96;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// A signed fact could not be represented exactly by the fixed review UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewFormatError {
    /// Text is not ASCII and therefore is not safe for the pinned display
    /// profile.
    NonAscii,
    /// A value would exceed [`MAX_FACT_LEN`]; values are never truncated.
    ValueTooLong,
    /// The recognized transfer review did not contain exactly three access
    /// entries.
    WrongAccessCount,
    /// The recognized transfer review did not contain its signed fee.
    MissingFee,
    /// Internal bytes violated the ASCII invariant.
    InvalidInternalText,
}

/// A bounded, fixed-capacity ASCII string holding at most [`MAX_FACT_LEN`] bytes
/// without heap allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedFactStr {
    buf: [u8; MAX_FACT_LEN],
    len: usize,
}

impl BoundedFactStr {
    /// Creates an empty string.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; MAX_FACT_LEN],
            len: 0,
        }
    }

    /// Copies an ASCII string slice without truncation.
    pub fn try_from_str(s: &str) -> Result<Self, ReviewFormatError> {
        if !s.is_ascii() {
            return Err(ReviewFormatError::NonAscii);
        }
        if s.len() > MAX_FACT_LEN {
            return Err(ReviewFormatError::ValueTooLong);
        }
        let mut out = Self::empty();
        let bytes: &[u8] = s.as_bytes();
        let mut i: usize = 0;
        while i < bytes.len() {
            out.buf[i] = bytes[i];
            i += 1;
        }
        out.len = bytes.len();
        Ok(out)
    }
}

impl BoundedFactStr {
    /// Formats an unsigned 64-bit integer into a decimal ASCII string.
    #[must_use]
    pub fn from_u64(val: u64) -> Self {
        let mut out = Self::empty();
        if val == 0 {
            out.buf[0] = b'0';
            out.len = 1;
            return out;
        }

        let mut temp: [u8; 20] = [0u8; 20];
        let mut num: u64 = val;
        let mut digits: usize = 0;
        while num > 0 {
            let digit = (num % 10) as u8;
            temp[digits] = b'0' + digit;
            digits += 1;
            num /= 10;
        }

        let mut i: usize = 0;
        while i < digits {
            out.buf[i] = temp[digits - 1 - i];
            i += 1;
        }
        out.len = digits;
        out
    }

    /// Formats a byte slice into lowercase hexadecimal ASCII characters.
    pub fn try_from_hex(bytes: &[u8]) -> Result<Self, ReviewFormatError> {
        let encoded_len: usize = bytes
            .len()
            .checked_mul(2)
            .ok_or(ReviewFormatError::ValueTooLong)?;
        if encoded_len > MAX_FACT_LEN {
            return Err(ReviewFormatError::ValueTooLong);
        }
        let mut out = Self::empty();
        let mut i: usize = 0;
        while i < bytes.len() {
            let b = bytes[i];
            out.buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
            out.buf[i * 2 + 1] = HEX_CHARS[(b & 0x0F) as usize];
            i += 1;
        }
        out.len = encoded_len;
        Ok(out)
    }

    /// Formats a 32-byte digest as `{algorithm}:{hex}`.
    pub fn try_from_digest(digest: &Digest32) -> Result<Self, ReviewFormatError> {
        let mut out = Self::empty();
        let prefix = digest.algorithm().label();
        let prefix_bytes = prefix.as_bytes();
        let digest_hex_len: usize = digest
            .bytes()
            .len()
            .checked_mul(2)
            .ok_or(ReviewFormatError::ValueTooLong)?;
        let required_len: usize = prefix_bytes
            .len()
            .checked_add(1)
            .and_then(|len: usize| len.checked_add(digest_hex_len))
            .ok_or(ReviewFormatError::ValueTooLong)?;
        if required_len > MAX_FACT_LEN {
            return Err(ReviewFormatError::ValueTooLong);
        }
        let mut len = prefix_bytes.len();
        let mut i: usize = 0;
        while i < len {
            out.buf[i] = prefix_bytes[i];
            i += 1;
        }
        out.buf[len] = b':';
        len += 1;
        let digest_bytes = digest.bytes();
        let mut j: usize = 0;
        while j < digest_bytes.len() {
            let b = digest_bytes[j];
            out.buf[len] = HEX_CHARS[(b >> 4) as usize];
            out.buf[len + 1] = HEX_CHARS[(b & 0x0F) as usize];
            len += 2;
            j += 1;
        }
        out.len = len;
        Ok(out)
    }

    /// Returns the string slice.
    pub fn as_str(&self) -> Result<&str, ReviewFormatError> {
        str::from_utf8(&self.buf[..self.len]).map_err(|_| ReviewFormatError::InvalidInternalText)
    }
}

/// One clear-signing review fact: exact key name and bounded string value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewFact {
    /// Fact key name (e.g. `"chain_id"`, `"protocol_version"`).
    pub name: &'static str,
    /// Bounded fact value.
    pub value: BoundedFactStr,
}

/// Formats all and only 32 signed facts from `review` in the exact deterministic order
/// defined by Hardware Signing Profile v1 and verified by `RECOGNIZED_TRANSFER_LINES`.
#[allow(clippy::too_many_lines)]
pub fn format_review_facts(
    review: &ClearSigningReview,
) -> Result<[ReviewFact; 32], ReviewFormatError> {
    if review.access_entries.len() != 3 {
        return Err(ReviewFormatError::WrongAccessCount);
    }
    let mut access_iter = review.access_lines();
    let access_0 = access_iter
        .next()
        .ok_or(ReviewFormatError::WrongAccessCount)?;
    let access_1 = access_iter
        .next()
        .ok_or(ReviewFormatError::WrongAccessCount)?;
    let access_2 = access_iter
        .next()
        .ok_or(ReviewFormatError::WrongAccessCount)?;
    if access_iter.next().is_some() {
        return Err(ReviewFormatError::WrongAccessCount);
    }
    let fee = review.fee.ok_or(ReviewFormatError::MissingFee)?;

    Ok([
        ReviewFact {
            name: "chain_id",
            value: BoundedFactStr::try_from_str(review.chain_id.as_str())?,
        },
        ReviewFact {
            name: "protocol_version",
            value: BoundedFactStr::from_u64(u64::from(review.protocol_version)),
        },
        ReviewFact {
            name: "epoch",
            value: BoundedFactStr::from_u64(review.epoch),
        },
        ReviewFact {
            name: "message_type",
            value: BoundedFactStr::try_from_str(review.message_type.as_str())?,
        },
        ReviewFact {
            name: "scheme",
            value: BoundedFactStr::try_from_str(review.scheme.label())?,
        },
        ReviewFact {
            name: "sender",
            value: BoundedFactStr::try_from_hex(review.sender.as_bytes())?,
        },
        ReviewFact {
            name: "nonce",
            value: BoundedFactStr::from_u64(review.nonce),
        },
        ReviewFact {
            name: "module_id",
            value: BoundedFactStr::try_from_hex(review.module_id.as_bytes())?,
        },
        ReviewFact {
            name: "module_version",
            value: BoundedFactStr::from_u64(review.module_version),
        },
        ReviewFact {
            name: "module_digest",
            value: BoundedFactStr::try_from_digest(&review.module_digest)?,
        },
        ReviewFact {
            name: "entrypoint",
            value: BoundedFactStr::try_from_str(review.entrypoint.as_str())?,
        },
        ReviewFact {
            name: review.amount_label,
            value: BoundedFactStr::from_u64(review.amount),
        },
        ReviewFact {
            name: "gas_limit",
            value: BoundedFactStr::from_u64(review.gas_limit),
        },
        ReviewFact {
            name: "manifest_count",
            value: BoundedFactStr::from_u64(review.access_entries.len() as u64),
        },
        ReviewFact {
            name: "access[0].mode",
            value: BoundedFactStr::try_from_str(access_0.mode.label())?,
        },
        ReviewFact {
            name: "access[0].object_id",
            value: BoundedFactStr::try_from_hex(access_0.object_id.as_bytes())?,
        },
        ReviewFact {
            name: "access[0].version",
            value: BoundedFactStr::from_u64(access_0.version),
        },
        ReviewFact {
            name: "access[0].digest",
            value: BoundedFactStr::try_from_digest(&access_0.digest)?,
        },
        ReviewFact {
            name: "access[1].mode",
            value: BoundedFactStr::try_from_str(access_1.mode.label())?,
        },
        ReviewFact {
            name: "access[1].object_id",
            value: BoundedFactStr::try_from_hex(access_1.object_id.as_bytes())?,
        },
        ReviewFact {
            name: "access[1].version",
            value: BoundedFactStr::from_u64(access_1.version),
        },
        ReviewFact {
            name: "access[1].digest",
            value: BoundedFactStr::try_from_digest(&access_1.digest)?,
        },
        ReviewFact {
            name: "access[2].mode",
            value: BoundedFactStr::try_from_str(access_2.mode.label())?,
        },
        ReviewFact {
            name: "access[2].object_id",
            value: BoundedFactStr::try_from_hex(access_2.object_id.as_bytes())?,
        },
        ReviewFact {
            name: "access[2].version",
            value: BoundedFactStr::from_u64(access_2.version),
        },
        ReviewFact {
            name: "access[2].digest",
            value: BoundedFactStr::try_from_digest(&access_2.digest)?,
        },
        ReviewFact {
            name: "fee_payment",
            // Reaching this point proves `review.fee` was `Some`; missing
            // fees returned `MissingFee` above rather than displaying this
            // signed fact inaccurately.
            value: BoundedFactStr::try_from_str("present")?,
        },
        ReviewFact {
            name: "fee_asset",
            value: BoundedFactStr::try_from_hex(fee.asset_id.as_bytes())?,
        },
        ReviewFact {
            name: "fee_max",
            value: BoundedFactStr::from_u64(fee.max_fee),
        },
        ReviewFact {
            name: "fee_object_id",
            value: BoundedFactStr::try_from_hex(fee.fee_object_id.as_bytes())?,
        },
        ReviewFact {
            name: "fee_object_version",
            value: BoundedFactStr::from_u64(fee.fee_object_version),
        },
        ReviewFact {
            name: "fee_object_digest",
            value: BoundedFactStr::try_from_digest(&fee.fee_object_digest)?,
        },
    ])
}
