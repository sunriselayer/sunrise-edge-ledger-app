//! Exactly-once RFC 8032 compressed Ed25519 public key conversion.
//!
//! Starting from `ECPrivateKey::public_key`'s raw, uncompressed output
//! (a 65-byte `04 || X || Y` point, `X` and `Y` each 32 bytes in big-endian byte
//! order per Ledger SDK conventions), this module converts it to the standard
//! RFC 8032 compressed Ed25519 encoding:
//!
//! * 32 little-endian bytes of the point's `Y` coordinate.
//! * The sign bit of `X` packed into the most-significant bit of the final byte
//!   (bit 7 of byte index 31).
//!
//! This conversion is performed exactly once; re-compressing an already compressed
//! key or double-inverting byte order would silently corrupt the public key and
//! on-chain address.

/// Errors that can occur when compressing an uncompressed Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionError {
    /// The leading byte of the uncompressed point was not `0x04`.
    InvalidPointHeader(u8),
    /// The Y coordinate exceeds the Ed25519 field prime $2^{255}-19$.
    FieldOverflow,
}

/// Compresses a 65-byte uncompressed point (`04 || X || Y`) into a 32-byte RFC 8032
/// compressed Ed25519 public key.
///
/// * `raw[0]` must be `0x04` (the uncompressed point marker).
/// * `raw[1..33]` is `X` (32 bytes, big-endian).
/// * `raw[33..65]` is `Y` (32 bytes, big-endian).
///
/// Reverses `Y` from big-endian to little-endian, verifies $Y < 2^{255}-19$, and sets
/// the most-significant bit of the last byte to 1 if `X` is odd (`(raw[32] & 1) != 0`).
pub fn compress_ed25519_point(raw: &[u8; 65]) -> Result<[u8; 32], CompressionError> {
    if raw[0] != 0x04 {
        return Err(CompressionError::InvalidPointHeader(raw[0]));
    }
    let x_bytes: &[u8] = &raw[1..33];
    let y_bytes: &[u8] = &raw[33..65];

    let mut compressed: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32 {
        compressed[i] = y_bytes[31 - i];
        i += 1;
    }

    // Ed25519 field prime p = 2^255 - 19.
    // In little-endian, byte 31 is the most significant byte.
    // In field F_p, Y must be strictly less than 2^255 - 19.
    // Thus the highest bit (bit 7) of compressed[31] must be 0 before packing the sign bit.
    if (compressed[31] & 0x80) != 0 {
        return Err(CompressionError::FieldOverflow);
    }
    // Strict field bound check: if Y >= 2^255 - 19, fail closed.
    // p in little-endian: [0xED, 0xFF, ..., 0xFF, 0x7F].
    if compressed[31] == 0x7F {
        let mut overflow: bool = true;
        let mut b: usize = 30;
        while b >= 1 {
            if compressed[b] != 0xFF {
                overflow = false;
                break;
            }
            if b == 1 {
                break;
            }
            b -= 1;
        }
        if overflow && compressed[0] >= 0xED {
            return Err(CompressionError::FieldOverflow);
        }
    }

    // Set sign bit from X parity: odd X (least-significant bit of big-endian X is x_bytes[31])
    // sets bit 7 of the final compressed byte.
    let x_is_odd: bool = (x_bytes[31] & 1) != 0;
    if x_is_odd {
        compressed[31] |= 0x80;
    }

    Ok(compressed)
}
