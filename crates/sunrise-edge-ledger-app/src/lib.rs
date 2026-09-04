//! Dedicated Ledger device application for Sunrise Edge (Hardware Signing Profile v1).
//!
//! This crate integrates the pure `sunrise-edge-ledger-core` state machine with
//! Ledger device hardware and SDK:
//!
//! * [`compression`] — exactly-once RFC 8032 Ed25519 public key compression from raw
//!   uncompressed `04 || X || Y` points.
//! * [`review_ui`] — bounded, allocation-free formatting of the 32 clear-signing facts.
//! * [`status`] — application status words matching the core contract.
//! * [`derivation`] — SLIP-0010 Ed25519 key derivation and signing primitives.
//! * [`app_ui`] — on-device NBGL review and menu interfaces.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

pub mod app_ui;
pub mod compression;
pub mod derivation;
pub mod review_ui;
pub mod status;
