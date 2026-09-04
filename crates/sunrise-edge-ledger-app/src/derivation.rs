//! Device key derivation and signing primitives using SLIP-0010 Ed25519.

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use crate::compression::compress_ed25519_point;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::ecc::Ed25519;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_core::apdu::{FrameSigner, PublicKeyDeriver};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_core::path::DerivationPath;

/// Key deriver implementation backed by the Ledger SDK's SLIP-0010 Ed25519 derivation.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub struct DeviceDeriver;

/// Exact-frame signer backed by Ledger SLIP-0010 Ed25519 derivation.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub struct DeviceSigner;

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
impl PublicKeyDeriver for DeviceDeriver {
    fn derive(&mut self, path: DerivationPath) -> Option<[u8; 32]> {
        let components: [u32; 5] = path.to_bip32_components();
        let sk = Ed25519::derive_from_path_slip10(&components);
        let pk = sk.public_key().ok()?;
        compress_ed25519_point(&pk.pubkey).ok()
    }
}

/// Signs a buffered signature frame using SLIP-0010 Ed25519 derivation.
///
/// Returns the exact 64-byte Ed25519 signature on success, or `None` on device failure.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
impl FrameSigner for DeviceSigner {
    fn sign(&mut self, path: DerivationPath, frame: &[u8]) -> Option<[u8; 64]> {
        let components: [u32; 5] = path.to_bip32_components();
        let sk = Ed25519::derive_from_path_slip10(&components);
        let (signature, signature_len) = sk.sign(frame).ok()?;
        if signature_len != 64 {
            return None;
        }
        Some(signature)
    }
}
