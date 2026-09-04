//! Independent decoder for the exact `CanonicalStruct(0x6001, v1)`
//! `TransactionSignable` shape from `SIGNING.md`, plus every nested frame it
//! carries (object references, the access manifest, and fee payments).
//!
//! Field layout (required fields 1-10, optional field 11; field 12, the
//! signature, is never present in a signable payload and is always
//! rejected):
//!
//! 1. `chain_id` UTF-8 string
//! 2. `protocol_version` little-endian `u32`
//! 3. `epoch` little-endian `u64`
//! 4. `sender` 32-byte address
//! 5. `nonce` little-endian `u64`
//! 6. `access_manifest` nested frame
//! 7. `module_ref` nested object-reference frame
//! 8. `entrypoint` UTF-8 string
//! 9. `args` canonically encoded argument bytes
//! 10. `gas_limit` little-endian `u64`
//! 11. `fee_payment` nested frame (optional)

use crate::canonical::{decode_canonical_frame, CanonicalError};
use crate::types::{
    AccessEntry, AccessManifest, AccessMode, Address, AssetId, BoundedStr, BoundedStrError,
    CapacityError, Digest32, Epoch, FeePayment, HashAlgorithmId, ObjectId, ObjectRef,
    ProtocolVersion,
};

const DIGEST_TYPE_ID: u16 = 0x0103;
const OBJECT_ID_TYPE_ID: u16 = 0x4001;
const OBJECT_REF_TYPE_ID: u16 = 0x4004;
const ACCESS_MODE_TYPE_ID: u16 = 0x4006;
const ACCESS_ENTRY_TYPE_ID: u16 = 0x5001;
const ACCESS_MANIFEST_TYPE_ID: u16 = 0x5002;
const ASSET_ID_TYPE_ID: u16 = 0x7001;
const FEE_PAYMENT_TYPE_ID: u16 = 0x7002;

/// Stable canonical type identifier for a Transaction v1 signable frame.
pub const TRANSACTION_TYPE_ID: u16 = 0x6001;
/// Stable canonical encoding version for [`TRANSACTION_TYPE_ID`].
pub const ENCODING_VERSION: u16 = 1;

const ALLOWED_FIELDS: [u16; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/// Maximum accepted `entrypoint` byte length (`SIGNING.md` profile bound).
pub const MAX_ENTRYPOINT_BYTES: usize = 64;
/// Maximum accepted `args` byte length (`SIGNING.md` profile bound).
pub const MAX_ARGS_BYTES: usize = 40;
/// Maximum accepted `chain_id` byte length (`SIGNING.md` profile bound),
/// shared with the outer signature frame's bound.
pub const MAX_CHAIN_ID_BYTES: usize = crate::frame::MAX_CHAIN_ID_BYTES;

/// Errors returned while decoding a `TransactionSignable` or any frame it
/// nests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    /// A canonical frame failed to decode.
    Canonical(CanonicalError),
    /// The `chain_id` field was empty or too large.
    ChainId(BoundedStrError),
    /// The `sender` field was not a 32-byte address.
    Sender,
    /// The `entrypoint` field was empty or too large.
    Entrypoint(BoundedStrError),
    /// The `entrypoint` field was present but blank.
    EmptyEntrypoint,
    /// The `args` field exceeded [`MAX_ARGS_BYTES`].
    Args(CapacityError),
    /// An object identifier was not 32 bytes.
    ObjectId,
    /// An access-mode tag was unknown.
    UnknownAccessMode(u8),
    /// The access-manifest declared more entries than the shared decode
    /// bound allows, or than fit its own field layout.
    AccessManifestShape,
    /// The access manifest names the same object more than once.
    DuplicateObjectId(ObjectId),
    /// A self-describing digest named an unknown hash algorithm.
    UnknownHashAlgorithm(u16),
}

impl From<CanonicalError> for TransactionError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// The exact signable fields of a canonical Transaction v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSignable<'a> {
    /// Chain replay-protection identifier.
    pub chain_id: BoundedStr<MAX_CHAIN_ID_BYTES>,
    /// Protocol version replay protection.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay protection.
    pub epoch: Epoch,
    /// Address of the transaction sender.
    pub sender: Address,
    /// Sender nonce for intra-epoch replay protection.
    pub nonce: u64,
    /// All objects the transaction may access, with their access modes.
    pub access_manifest: AccessManifest,
    /// Reference to the module/entrypoint the transaction will execute.
    pub module_ref: ObjectRef,
    /// Entry-point function to invoke inside the module.
    pub entrypoint: BoundedStr<MAX_ENTRYPOINT_BYTES>,
    /// Canonically encoded arguments passed to the entry-point, exactly as
    /// signed (borrowed from the caller's buffer).
    pub args: &'a [u8],
    /// Maximum gas units the sender is willing to spend.
    pub gas_limit: u64,
    /// Stablecoin-denominated fee payment authorization, if any.
    pub fee_payment: Option<FeePayment>,
}

fn decode_digest32(input: &[u8]) -> Result<Digest32, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(DIGEST_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let algorithm_id = frame.required_u16(1)?;
    let algorithm = HashAlgorithmId::try_from_u16(algorithm_id)
        .ok_or(TransactionError::UnknownHashAlgorithm(algorithm_id))?;
    let bytes: [u8; 32] = frame.required_array(2)?;
    Ok(Digest32::new(algorithm, bytes))
}

fn decode_object_id(input: &[u8]) -> Result<ObjectId, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_ID_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1])?;
    let bytes: [u8; 32] = frame
        .required_array(1)
        .map_err(|_| TransactionError::ObjectId)?;
    Ok(ObjectId::new(bytes))
}

fn decode_object_ref(input: &[u8]) -> Result<ObjectRef, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_REF_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let id = decode_object_id(frame.required_field(1)?)?;
    let version = frame.required_u64(2)?;
    let digest = decode_digest32(frame.required_field(3)?)?;
    Ok(ObjectRef {
        id,
        version,
        digest,
    })
}

fn decode_access_mode(input: &[u8]) -> Result<AccessMode, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_MODE_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1])?;
    let bytes = frame.required_field(1)?;
    let array: [u8; 1] = bytes
        .try_into()
        .map_err(|_| CanonicalError::InvalidFieldLength {
            field_id: 1,
            expected: 1,
            actual: bytes.len(),
        })?;
    AccessMode::try_from_u8(array[0]).ok_or(TransactionError::UnknownAccessMode(array[0]))
}

fn decode_access_entry(input: &[u8]) -> Result<AccessEntry, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_ENTRY_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let object_ref = decode_object_ref(frame.required_field(1)?)?;
    let mode = decode_access_mode(frame.required_field(2)?)?;
    Ok(AccessEntry { object_ref, mode })
}

/// Decodes a bounded access manifest, rejecting more entries than
/// `max_entries`, a declared count that disagrees with the frame's actual
/// field layout, or any duplicate `ObjectId` across entries.
///
/// The duplicate-`ObjectId` check applies uniformly to every entry, not
/// only the transfer-shaped subset a later policy inspects: `SIGNING.md`
/// requires the device check this "even when every mode/position is
/// otherwise well-formed".
fn decode_access_manifest(
    input: &[u8],
    max_entries: usize,
) -> Result<AccessManifest, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_MANIFEST_TYPE_ID)?;
    frame.require_version(1)?;

    let declared_count = frame.required_u32(1)?;
    let declared_count =
        usize::try_from(declared_count).map_err(|_| TransactionError::AccessManifestShape)?;
    if declared_count > max_entries {
        return Err(TransactionError::AccessManifestShape);
    }
    let expected_field_count = declared_count
        .checked_add(1)
        .ok_or(TransactionError::AccessManifestShape)?;
    if frame.field_count() != expected_field_count {
        return Err(TransactionError::AccessManifestShape);
    }

    let mut manifest = AccessManifest::new();
    for index in 0..declared_count {
        let field_id = u16::try_from(
            index
                .checked_add(2)
                .ok_or(TransactionError::AccessManifestShape)?,
        )
        .map_err(|_| TransactionError::AccessManifestShape)?;
        let entry = decode_access_entry(frame.required_field(field_id)?)?;
        manifest
            .push(entry)
            .map_err(|_| TransactionError::AccessManifestShape)?;
    }

    // Pairwise duplicate-`ObjectId` check. `max_entries` is small (profile
    // bound: at most `MAX_ACCESS_ENTRIES`), so the O(n^2) scan below is
    // cheap and needs no heap-allocated sort buffer.
    for (i, left) in manifest.iter().enumerate() {
        for right in manifest.iter().skip(i.saturating_add(1)) {
            if left.object_ref.id == right.object_ref.id {
                return Err(TransactionError::DuplicateObjectId(left.object_ref.id));
            }
        }
    }

    Ok(manifest)
}

fn decode_asset_id(input: &[u8]) -> Result<AssetId, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ASSET_ID_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1])?;
    let bytes: [u8; 32] = frame
        .required_array(1)
        .map_err(|_| TransactionError::ObjectId)?;
    Ok(AssetId::new(bytes))
}

fn decode_fee_payment(input: &[u8]) -> Result<FeePayment, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FEE_PAYMENT_TYPE_ID)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let asset_id = decode_asset_id(frame.required_field(1)?)?;
    let max_fee = frame.required_u64(2)?;
    let fee_object = decode_object_ref(frame.required_field(3)?)?;
    Ok(FeePayment {
        asset_id,
        max_fee,
        fee_object,
    })
}

/// Strictly decodes the exact bytes carried in field 6 of a
/// [`crate::frame::SignatureFrame`] (a `TransactionSignable`).
///
/// Beyond the shared canonical-frame guarantees (correct magic, no
/// truncation/trailing bytes, strictly increasing field order, no duplicate
/// fields), this additionally: requires [`TRANSACTION_TYPE_ID`] and
/// [`ENCODING_VERSION`]; requires exactly fields 1-10 with optional field
/// 11, rejecting any other field id (in particular, field 12 — the
/// signature — is always rejected, since a signable payload never carries
/// one); recursively decodes and validates every nested frame with the same
/// strict rules; applies this profile's bounds to `chain_id`, `entrypoint`,
/// and `args` before copying attacker-controlled bytes out of the borrowed
/// frame; and rejects an empty `entrypoint`.
pub fn decode_transaction_signable(
    input: &[u8],
) -> Result<TransactionSignable<'_>, TransactionError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(TRANSACTION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&ALLOWED_FIELDS)?;

    let chain_id_bytes = frame.required_field(1)?;
    let chain_id =
        BoundedStr::from_utf8_slice(chain_id_bytes).map_err(TransactionError::ChainId)?;

    let protocol_version = frame.required_u32(2)?;
    let epoch = frame.required_u64(3)?;
    let sender_bytes: [u8; 32] = frame
        .required_array(4)
        .map_err(|_| TransactionError::Sender)?;
    let sender = Address::new(sender_bytes);
    let nonce = frame.required_u64(5)?;

    let access_manifest =
        decode_access_manifest(frame.required_field(6)?, crate::types::MAX_ACCESS_ENTRIES)?;

    let module_ref = decode_object_ref(frame.required_field(7)?)?;

    let entrypoint_bytes = frame.required_field(8)?;
    let entrypoint =
        BoundedStr::from_utf8_slice(entrypoint_bytes).map_err(TransactionError::Entrypoint)?;
    if entrypoint.is_empty() {
        return Err(TransactionError::EmptyEntrypoint);
    }

    let args_bytes = frame.required_field(9)?;
    if args_bytes.len() > MAX_ARGS_BYTES {
        return Err(TransactionError::Args(CapacityError {
            actual: args_bytes.len(),
            maximum: MAX_ARGS_BYTES,
        }));
    }
    // `args` is exposed borrowed (see `TransactionSignable::args`); the
    // bound above is still enforced eagerly so a caller never observes an
    // over-sized slice.
    let args = args_bytes;

    let gas_limit = frame.required_u64(10)?;
    let fee_payment = match frame.field(11) {
        Some(bytes) => Some(decode_fee_payment(bytes)?),
        None => None,
    };

    Ok(TransactionSignable {
        chain_id,
        protocol_version,
        epoch,
        sender,
        nonce,
        access_manifest,
        module_ref,
        entrypoint,
        args,
        gas_limit,
        fee_payment,
    })
}
