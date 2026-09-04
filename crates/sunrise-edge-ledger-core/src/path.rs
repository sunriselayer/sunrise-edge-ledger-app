//! The exact provisional devnet derivation path from `SIGNING.md`,
//! "Provisional derivation policy": `m/44'/21333'/account'/0'/0'`, every
//! component hardened, encoded on the wire as one depth byte followed by
//! that many big-endian `u32` hardened components.
//!
//! This module only validates path *shape*; it never derives a key. Actual
//! SLIP-0010 Ed25519 derivation is a future device-SDK integration
//! explicitly out of scope for this slice (see `README.md`).

/// Number of path components Profile v1 requires.
pub const PATH_DEPTH: u8 = 5;

/// Wire length of an encoded path: one depth byte plus five 4-byte
/// components.
pub const PATH_ENCODED_LEN: usize = 1 + (PATH_DEPTH as usize) * 4;

const HARDENED_BIT: u32 = 0x8000_0000;
const PURPOSE: u32 = 44;
const COIN_TYPE: u32 = 21_333;

/// Errors returned while decoding or validating a derivation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The encoded path was not exactly [`PATH_ENCODED_LEN`] bytes.
    WrongLength {
        /// Actual byte length.
        actual: usize,
    },
    /// The depth byte was not [`PATH_DEPTH`].
    WrongDepth {
        /// Actual depth byte.
        actual: u8,
    },
    /// A path component's hardened bit was not set.
    NotHardened {
        /// Zero-based component index.
        index: usize,
    },
    /// The purpose component was not `44'`.
    WrongPurpose,
    /// The coin-type component was not `21333'`.
    WrongCoinType,
    /// The change component was not `0'`.
    WrongChange,
    /// The address-index component was not `0'`.
    WrongAddressIndex,
}

/// The exact, validated provisional devnet path `m/44'/21333'/account'/0'/0'`.
///
/// Only `account` varies; every other component is pinned by Profile v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    account: u32,
}

impl DerivationPath {
    /// Returns the caller-selected, non-hardened `account` value.
    #[must_use]
    pub const fn account(self) -> u32 {
        self.account
    }
}

/// Decodes and strictly validates a wire-encoded derivation path.
///
/// Rejects another depth, prefix, unhardened component, change, or address
/// index, exactly as `SIGNING.md` requires.
pub fn decode_path(bytes: &[u8]) -> Result<DerivationPath, PathError> {
    if bytes.len() != PATH_ENCODED_LEN {
        return Err(PathError::WrongLength {
            actual: bytes.len(),
        });
    }
    let depth = *bytes.first().ok_or(PathError::WrongLength { actual: 0 })?;
    if depth != PATH_DEPTH {
        return Err(PathError::WrongDepth { actual: depth });
    }

    let component = |index: usize| -> Result<u32, PathError> {
        let start = 1 + index * 4;
        let end = start + 4;
        let slice = bytes.get(start..end).ok_or(PathError::WrongLength {
            actual: bytes.len(),
        })?;
        let array: [u8; 4] = slice.try_into().map_err(|_| PathError::WrongLength {
            actual: bytes.len(),
        })?;
        Ok(u32::from_be_bytes(array))
    };

    let purpose = component(0)?;
    let coin_type = component(1)?;
    let account_raw = component(2)?;
    let change = component(3)?;
    let address_index = component(4)?;

    for (index, raw) in [purpose, coin_type, account_raw, change, address_index]
        .into_iter()
        .enumerate()
    {
        if raw & HARDENED_BIT == 0 {
            return Err(PathError::NotHardened { index });
        }
    }

    if purpose & !HARDENED_BIT != PURPOSE {
        return Err(PathError::WrongPurpose);
    }
    if coin_type & !HARDENED_BIT != COIN_TYPE {
        return Err(PathError::WrongCoinType);
    }
    if change & !HARDENED_BIT != 0 {
        return Err(PathError::WrongChange);
    }
    if address_index & !HARDENED_BIT != 0 {
        return Err(PathError::WrongAddressIndex);
    }

    Ok(DerivationPath {
        account: account_raw & !HARDENED_BIT,
    })
}
