//! A bounded, allocation-free clear-signing review model.
//!
//! Every field here is a pure function of the exact signed frame bytes, per
//! `SIGNING.md`, "Clear-signing policy": "Every displayed value is a pure
//! function of the exact signed frame bytes. Host-supplied display
//! metadata ... is excluded and must never be presented as signed content."
//! There is no destination-owner field (`SIGNING.md` notes it is
//! intentionally absent because it is not in Transaction v1), no asset
//! symbol, no request id, and no blind-signing/raw-argument fallback path:
//! [`crate::apdu::dispatch`] emits a [`ClearSigningReview`] only through
//! [`build_review`] after full frame decode and exact policy recognition
//! succeed. The fields remain public for a future UI adapter; that adapter
//! must trust only the value carried by `DispatchOutcome::ReviewTransaction`,
//! never construct one from host-supplied display metadata.
//!
//! This module renders no pixels and owns no display driver; it is the
//! bounded data a future device-side UI adapter would page through.

use crate::frame::{SignatureFrame, MAX_CHAIN_ID_BYTES, MAX_MESSAGE_TYPE_BYTES};
use crate::policy::{ClearSigningPolicy, PolicyError};
use crate::transaction::{TransactionSignable, MAX_ENTRYPOINT_BYTES};
use crate::types::{
    AccessEntry, AccessManifest, AssetId, BoundedStr, Digest32, Epoch, FeePayment, ObjectId,
    ProtocolVersion, SignatureSchemeId,
};

/// Errors returned while building a [`ClearSigningReview`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// The outer frame's `message_type` was not
    /// [`crate::TRANSACTION_V1_MESSAGE_TYPE`].
    UnsupportedMessageType,
    /// The outer frame's `signature_scheme_id` was not Ed25519 (the only
    /// scheme Profile v1 accepts).
    UnsupportedSignatureScheme,
    /// The outer signature frame and the inner transaction payload each
    /// independently carry `chain_id`/`protocol_version`/`epoch`; both are
    /// signed, and a mismatch between them is a typed rejection rather than
    /// silently preferring one copy.
    SignedContextMismatch,
    /// The clear-signing policy rejected the transaction.
    Policy(PolicyError),
}

impl From<PolicyError> for ReviewError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

/// One rendered access-manifest line's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessLine {
    /// Requested access mode.
    pub mode: crate::types::AccessMode,
    /// Referenced object identifier.
    pub object_id: ObjectId,
    /// Referenced object version.
    pub version: u64,
    /// Referenced object digest.
    pub digest: Digest32,
}

/// The signed fee fields, present only when the transaction authorizes a
/// fee payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeLine {
    /// Signed fee asset.
    pub asset_id: AssetId,
    /// Signed maximum fee.
    pub max_fee: u64,
    /// Fee object identifier.
    pub fee_object_id: ObjectId,
    /// Fee object version.
    pub fee_object_version: u64,
    /// Fee object digest.
    pub fee_object_digest: Digest32,
}

/// A bounded, ASCII-safe clear-signing review: only the signed fields
/// `SIGNING.md` requires a device to display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearSigningReview {
    /// Destination chain identifier.
    pub chain_id: BoundedStr<MAX_CHAIN_ID_BYTES>,
    /// Active protocol version.
    pub protocol_version: ProtocolVersion,
    /// Active epoch.
    pub epoch: Epoch,
    /// Signature message-type family.
    pub message_type: BoundedStr<MAX_MESSAGE_TYPE_BYTES>,
    /// Signature scheme (always Ed25519 under Profile v1).
    pub scheme: SignatureSchemeId,
    /// Transaction sender, byte-identical to the derived public key that
    /// authorized this review (checked before construction).
    pub sender: crate::types::Address,
    /// Sender nonce.
    pub nonce: u64,
    /// Recognized module identifier.
    pub module_id: ObjectId,
    /// Recognized module version.
    pub module_version: u64,
    /// Recognized module code digest.
    pub module_digest: Digest32,
    /// Recognized entrypoint.
    pub entrypoint: BoundedStr<MAX_ENTRYPOINT_BYTES>,
    /// Policy-recognized non-zero transfer amount.
    pub amount: u64,
    /// Policy-recognized argument label for `amount` (e.g. `"amount"`).
    pub amount_label: &'static str,
    /// Maximum gas units the sender authorizes.
    pub gas_limit: u64,
    /// Ordered access-manifest entries.
    pub access_entries: AccessManifest,
    /// Signed fee fields, if a fee payment is present.
    pub fee: Option<FeeLine>,
}

impl ClearSigningReview {
    /// Returns the ordered access-manifest lines.
    pub fn access_lines(&self) -> impl Iterator<Item = AccessLine> + '_ {
        self.access_entries
            .iter()
            .map(|entry: &AccessEntry| AccessLine {
                mode: entry.mode,
                object_id: entry.object_ref.id,
                version: entry.object_ref.version,
                digest: entry.object_ref.digest,
            })
    }
}

/// Builds a [`ClearSigningReview`] from an already-decoded outer frame and
/// inner transaction, applying `policy` only after every signed field has
/// been decoded and bounded.
///
/// A mismatch anywhere rejects the transaction; there is no generic
/// raw-argument or blind-signing fallback. This function performs no
/// sender/public-key comparison: callers (see [`crate::apdu`]) must
/// independently check the supplied derived public key against
/// `transaction.sender` before treating this review as approvable, exactly
/// as `SIGNING.md`'s LAST-chunk rule requires.
///
/// Direct callers must also enforce the profile's 4096-byte complete-frame
/// and 3072-byte inner-payload bounds before decoding. The APDU composition
/// does both before it reaches this function; the lower-level zero-copy
/// decoders intentionally enforce only their own structural and field bounds.
pub fn build_review(
    frame: &SignatureFrame<'_>,
    transaction: &TransactionSignable<'_>,
    policy: &ClearSigningPolicy,
) -> Result<ClearSigningReview, ReviewError> {
    if frame.message_type.as_str() != crate::TRANSACTION_V1_MESSAGE_TYPE {
        return Err(ReviewError::UnsupportedMessageType);
    }
    if frame.signature_scheme_id != SignatureSchemeId::Ed25519 {
        return Err(ReviewError::UnsupportedSignatureScheme);
    }
    if transaction.chain_id.as_str() != frame.chain_id.as_str()
        || transaction.protocol_version != frame.protocol_version
        || transaction.epoch != frame.epoch
    {
        return Err(ReviewError::SignedContextMismatch);
    }

    let amount = policy.recognize(transaction)?;

    let fee = transaction
        .fee_payment
        .map(|fee_payment: FeePayment| FeeLine {
            asset_id: fee_payment.asset_id,
            max_fee: fee_payment.max_fee,
            fee_object_id: fee_payment.fee_object.id,
            fee_object_version: fee_payment.fee_object.version,
            fee_object_digest: fee_payment.fee_object.digest,
        });

    Ok(ClearSigningReview {
        chain_id: frame.chain_id,
        protocol_version: frame.protocol_version,
        epoch: frame.epoch,
        message_type: frame.message_type,
        scheme: frame.signature_scheme_id,
        sender: transaction.sender,
        nonce: transaction.nonce,
        module_id: transaction.module_ref.id,
        module_version: transaction.module_ref.version,
        module_digest: transaction.module_ref.digest,
        entrypoint: transaction.entrypoint,
        amount,
        amount_label: policy.args_label(),
        gas_limit: transaction.gas_limit,
        access_entries: transaction.access_manifest,
        fee,
    })
}
