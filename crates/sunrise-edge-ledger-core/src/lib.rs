//! Pure, `no_std`, allocation-free Hardware Signing Profile v1 core logic
//! for the Sunrise Edge Ledger application.
//!
//! This crate is the SDK-independent core used by the sibling Ledger device
//! crate. It contains no Ledger dependency, APDU transport, key derivation,
//! signing primitive, or display driver. Everything here is a pure function
//! over borrowed byte slices and fixed-size, `Copy` value types:
//!
//! * [`apdu`] — the exact application-owned APDU state machine and status
//!   words from `SIGNING.md`, "Future APDU contract", as transport-free
//!   logic.
//! * [`path`] — the exact provisional devnet derivation path shape from
//!   `SIGNING.md`, "Provisional derivation policy" (validation only, no
//!   derivation).
//! * [`canonical`] — an independent, from-scratch decoder for Sunrise
//!   Edge's canonical field-framed wire format.
//! * [`frame`] — the outer `CanonicalStruct(0x2001, v1)` signature frame.
//! * [`transaction`] — the inner `CanonicalStruct(0x6001, v1)`
//!   `TransactionSignable`, plus every nested frame it carries.
//! * [`policy`] — the exact-match clear-signing policy for the one
//!   allowlisted devnet asset-transfer shape.
//! * [`review`] — the bounded, signed-fields-only model consumed by the
//!   on-device UI adapter.
//! * [`types`] — fixed-capacity containers and protocol identifiers shared
//!   by the modules above.
//!
//! None of this is copied from, or dependent on, the Sunrise Edge node
//! workspace's crates (`canonical-encoding`, `crypto`, `objects`, `abi`,
//! `fees`, `protocol-types`, `signing-view`); every wire shape is
//! reimplemented from the `SIGNING.md` specification and cross-checked
//! against that workspace's own published test fixture (see
//! `tests/conformance.rs`).

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Concise public docs are a project requirement (see AGENTS.md); per-error
// `# Errors` sections and blanket `#[must_use]` annotations on every typed
// accessor would add doc-comment bulk without adding information beyond
// the error/return types already in each signature.
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]
// This crate is allocation-free by requirement (see README.md): bounded
// values such as `ClearSigningReview` are deliberately fixed-size, `Copy`,
// stack values rather than heap-indirected ones, so they are necessarily
// larger than clippy's generic perf heuristics expect.
#![allow(clippy::large_enum_variant, clippy::large_types_passed_by_value)]

pub mod apdu;
pub mod canonical;
pub mod frame;
pub mod path;
pub mod policy;
pub mod review;
pub mod transaction;
pub mod types;

/// The exact Transaction v1 signature message-type family Profile v1
/// recognizes (`SIGNING.md`: "Profile v1 accepts only
/// `message_type=transaction-v1`").
pub const TRANSACTION_V1_MESSAGE_TYPE: &str = "transaction-v1";
