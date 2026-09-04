//! Exact-match clear-signing policy for one preinstalled module's
//! arguments, per `SIGNING.md`, "Clear-signing policy".
//!
//! There is deliberately no generic-display fallback: a transaction is
//! either recognized in full or rejected before any review is built. This
//! mirrors the source workspace's `crates/signing-view/src/policy.rs`
//! `ClearSigningPolicy`/`DEVNET_ASSET_TRANSFER_POLICY`, reimplemented here
//! from scratch (no shared code, no dependency on that crate).

use crate::canonical::decode_canonical_frame;
use crate::transaction::TransactionSignable;
use crate::types::{AccessMode, AssetId, HashAlgorithmId, ObjectId};

/// Exact reason a signed transaction did not match a clear-signing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The signed chain identifier was not allowlisted.
    ChainId,
    /// The signed protocol version was not allowlisted.
    ProtocolVersion,
    /// The signed epoch was not allowlisted.
    Epoch,
    /// The module object identifier was not allowlisted.
    ModuleId,
    /// The module version was not allowlisted.
    ModuleVersion,
    /// The module digest algorithm was not allowlisted.
    ModuleDigestAlgorithm,
    /// The module digest bytes were not allowlisted.
    ModuleDigest,
    /// The entrypoint was not allowlisted.
    Entrypoint,
    /// The declared object-access shape was not the exact transfer shape
    /// (exactly three `Write` entries).
    AccessShape,
    /// The transfer profile requires a fee authorization.
    FeeRequired,
    /// The fee object was not the exact source reference at manifest
    /// index 0.
    FeeObjectMismatch,
    /// The signed fee asset was not allowlisted.
    FeeAsset,
    /// The argument bytes were not one complete, well-formed canonical
    /// frame.
    ArgumentsEncoding,
    /// The argument type identifier was not allowlisted.
    ArgumentsTypeId(u16),
    /// The argument encoding version was not allowlisted.
    ArgumentsVersion(u16),
    /// The argument fields were not the exact allowlisted shape.
    ArgumentsShape,
    /// The amount was zero.
    ZeroAmount,
}

/// An exact-match clear-signing policy: recognizes one specific
/// preinstalled module version/entrypoint/argument shape and gives its
/// sole argument a human-meaningful label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearSigningPolicy {
    chain_id: &'static str,
    protocol_version: u32,
    epoch: u64,
    module_id: [u8; 32],
    module_version: u64,
    code_digest_algorithm: HashAlgorithmId,
    code_digest_bytes: [u8; 32],
    entrypoint: &'static str,
    args_type_id: u16,
    args_version: u16,
    args_field_id: u16,
    args_label: &'static str,
    fee_asset_id: [u8; 32],
}

impl ClearSigningPolicy {
    /// Deterministic ASCII label for the recognized argument and device UI.
    #[must_use]
    pub const fn args_label(&self) -> &'static str {
        self.args_label
    }

    /// Recognizes one signed transaction in full and returns its non-zero
    /// transfer amount. Every mismatch is a typed rejection; there is no
    /// raw-argument or blind-signing fallback.
    pub fn recognize(&self, transaction: &TransactionSignable<'_>) -> Result<u64, PolicyError> {
        if transaction.chain_id.as_str() != self.chain_id {
            return Err(PolicyError::ChainId);
        }
        if transaction.protocol_version != self.protocol_version {
            return Err(PolicyError::ProtocolVersion);
        }
        if transaction.epoch != self.epoch {
            return Err(PolicyError::Epoch);
        }
        let module_ref = &transaction.module_ref;
        if module_ref.id != ObjectId::new(self.module_id) {
            return Err(PolicyError::ModuleId);
        }
        if module_ref.version != self.module_version {
            return Err(PolicyError::ModuleVersion);
        }
        if module_ref.digest.algorithm() != self.code_digest_algorithm {
            return Err(PolicyError::ModuleDigestAlgorithm);
        }
        if module_ref.digest.bytes() != self.code_digest_bytes {
            return Err(PolicyError::ModuleDigest);
        }
        if transaction.entrypoint.as_str() != self.entrypoint {
            return Err(PolicyError::Entrypoint);
        }

        if transaction.access_manifest.len() != 3
            || transaction
                .access_manifest
                .iter()
                .any(|entry| entry.mode != AccessMode::Write)
        {
            return Err(PolicyError::AccessShape);
        }
        let fee_payment = transaction.fee_payment.ok_or(PolicyError::FeeRequired)?;
        let source_entry = transaction
            .access_manifest
            .get(0)
            .ok_or(PolicyError::AccessShape)?;
        if fee_payment.fee_object != source_entry.object_ref {
            return Err(PolicyError::FeeObjectMismatch);
        }
        if fee_payment.asset_id != AssetId::new(self.fee_asset_id) {
            return Err(PolicyError::FeeAsset);
        }

        let frame =
            decode_canonical_frame(transaction.args).map_err(|_| PolicyError::ArgumentsEncoding)?;
        if frame.type_id() != self.args_type_id {
            return Err(PolicyError::ArgumentsTypeId(frame.type_id()));
        }
        if frame.version() != self.args_version {
            return Err(PolicyError::ArgumentsVersion(frame.version()));
        }
        frame
            .require_only_fields(&[self.args_field_id])
            .map_err(|_| PolicyError::ArgumentsShape)?;
        let value = frame
            .required_u64(self.args_field_id)
            .map_err(|_| PolicyError::ArgumentsShape)?;
        if value == 0 {
            return Err(PolicyError::ZeroAmount);
        }

        Ok(value)
    }
}

/// The current local-devnet asset-account transfer module.
///
/// This is a provisional, narrow reference-build recognition entry, not a
/// general module-registration mechanism (see `SIGNING.md`, "Clear-signing
/// policy"). The exact code digest is valid only for one reference build:
/// `chain_id = "sunrise-local-devnet"`, `protocol_version = 3`, `epoch = 0`.
/// Every constant below is copied as data from `SIGNING.md` and from the
/// source workspace's `crates/signing-view/src/policy.rs`
/// `DEVNET_ASSET_TRANSFER_POLICY`, commit `1dd4d2d`.
pub const DEVNET_ASSET_TRANSFER_POLICY: ClearSigningPolicy = ClearSigningPolicy {
    chain_id: "sunrise-local-devnet",
    protocol_version: 3,
    epoch: 0,
    module_id: [
        0x0D, 0x5D, 0xD1, 0x0A, 0xEC, 0x2C, 0x31, 0x5B, 0x1D, 0xC5, 0x64, 0xC6, 0x94, 0x43, 0x9E,
        0x46, 0xBA, 0xC4, 0xB6, 0x14, 0x26, 0xD2, 0x2E, 0x0D, 0x7D, 0xDB, 0x76, 0x4C, 0x49, 0x19,
        0x7F, 0xE7,
    ],
    module_version: 3,
    code_digest_algorithm: HashAlgorithmId::Sha2_256,
    code_digest_bytes: [
        0x01, 0x53, 0x41, 0x28, 0xF1, 0x2E, 0xB4, 0xCF, 0x46, 0x9B, 0xFA, 0x29, 0x67, 0x7B, 0xBC,
        0xED, 0x13, 0x44, 0x87, 0x9D, 0xE2, 0x87, 0x03, 0x15, 0x84, 0x7C, 0xBB, 0x7F, 0xAE, 0xC2,
        0x16, 0x19,
    ],
    entrypoint: "transfer",
    args_type_id: 0xF002,
    args_version: 1,
    args_field_id: 1,
    args_label: "amount",
    fee_asset_id: [
        0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47, 0xBC,
        0x11, 0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B, 0x43,
        0x3E, 0xA8,
    ],
};
