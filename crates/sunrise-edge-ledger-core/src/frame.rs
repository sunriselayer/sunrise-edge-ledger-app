//! Independent decoder for the exact `CanonicalStruct(0x2001, v1)` signature
//! frame from `SIGNING.md`, "Signed input and bounds".
//!
//! Field layout (all required, exactly fields 1 through 6):
//!
//! 1. `chain_id` UTF-8 string
//! 2. `protocol_version` little-endian `u32`
//! 3. `epoch` little-endian `u64`
//! 4. `message_type` UTF-8 string
//! 5. `signature_scheme_id` little-endian `u16`
//! 6. canonical payload bytes (the inner [`crate::transaction`] frame)

use crate::canonical::{decode_canonical_frame, CanonicalError};
use crate::types::{BoundedStr, BoundedStrError, Epoch, ProtocolVersion, SignatureSchemeId};

/// Stable canonical type identifier for a signature frame.
pub const SIGNATURE_FRAME_TYPE_ID: u16 = 0x2001;
/// Stable canonical encoding version for [`SIGNATURE_FRAME_TYPE_ID`].
pub const SIGNATURE_FRAME_VERSION: u16 = 1;

const ALLOWED_FIELDS: [u16; 6] = [1, 2, 3, 4, 5, 6];

/// Maximum accepted `chain_id` byte length (`SIGNING.md` profile bound).
pub const MAX_CHAIN_ID_BYTES: usize = 64;
/// Maximum accepted `message_type` byte length (`SIGNING.md` profile bound).
pub const MAX_MESSAGE_TYPE_BYTES: usize = 32;

/// Errors returned while decoding the outer signature frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The canonical frame itself failed to decode.
    Canonical(CanonicalError),
    /// The `chain_id` field was empty or exceeded [`MAX_CHAIN_ID_BYTES`].
    ChainId(BoundedStrError),
    /// The `message_type` field was empty or exceeded
    /// [`MAX_MESSAGE_TYPE_BYTES`].
    MessageType(BoundedStrError),
    /// The `signature_scheme_id` was not a known scheme.
    UnknownSignatureScheme(u16),
    /// The `chain_id` field was present but blank (all whitespace).
    EmptyChainId,
    /// The `message_type` field was present but blank (all whitespace).
    EmptyMessageType,
}

impl From<CanonicalError> for FrameError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// A strictly decoded outer signature frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureFrame<'a> {
    /// Destination chain identifier (bounded, non-blank).
    pub chain_id: BoundedStr<MAX_CHAIN_ID_BYTES>,
    /// Active protocol version.
    pub protocol_version: ProtocolVersion,
    /// Active epoch.
    pub epoch: Epoch,
    /// Semantic message family (bounded, non-blank).
    pub message_type: BoundedStr<MAX_MESSAGE_TYPE_BYTES>,
    /// Signature scheme identifier.
    pub signature_scheme_id: SignatureSchemeId,
    /// The framed canonical payload (field 6), exactly as signed, borrowed
    /// from the caller's buffer.
    pub payload: &'a [u8],
}

/// Strictly decodes a [`SIGNATURE_FRAME_TYPE_ID`] frame.
///
/// Requires exactly fields 1 through 6 (no more, no fewer), the exact type
/// id and version, a non-blank `chain_id` within [`MAX_CHAIN_ID_BYTES`], a
/// non-blank `message_type` within [`MAX_MESSAGE_TYPE_BYTES`], and a known
/// `signature_scheme_id`. Never truncates or substitutes a default for a
/// malformed field.
pub fn decode_signature_frame(input: &[u8]) -> Result<SignatureFrame<'_>, FrameError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(SIGNATURE_FRAME_TYPE_ID)?;
    frame.require_version(SIGNATURE_FRAME_VERSION)?;
    frame.require_only_fields(&ALLOWED_FIELDS)?;

    let chain_id_bytes = frame.required_field(1)?;
    let chain_id = BoundedStr::from_utf8_slice(chain_id_bytes).map_err(FrameError::ChainId)?;
    if chain_id.as_str().trim().is_empty() {
        return Err(FrameError::EmptyChainId);
    }

    let protocol_version = frame.required_u32(2)?;
    let epoch = frame.required_u64(3)?;

    let message_type_bytes = frame.required_field(4)?;
    let message_type =
        BoundedStr::from_utf8_slice(message_type_bytes).map_err(FrameError::MessageType)?;
    if message_type.as_str().trim().is_empty() {
        return Err(FrameError::EmptyMessageType);
    }

    let scheme_id = frame.required_u16(5)?;
    let signature_scheme_id = SignatureSchemeId::try_from_u16(scheme_id)
        .ok_or(FrameError::UnknownSignatureScheme(scheme_id))?;

    let payload = frame.required_field(6)?;

    Ok(SignatureFrame {
        chain_id,
        protocol_version,
        epoch,
        message_type,
        signature_scheme_id,
        payload,
    })
}
