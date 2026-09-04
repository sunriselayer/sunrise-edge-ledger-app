//! Fixed-capacity, allocation-free containers and protocol identifiers.
//!
//! Every type here is `Copy` and stack-allocated with a compile-time
//! capacity bound, so decoding attacker-controlled bytes never allocates and
//! never depends on input size beyond the fixed maximum.

use core::fmt;
use core::str;

/// A slice did not fit a fixed-capacity destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError {
    /// Number of bytes that were rejected.
    pub actual: usize,
    /// Maximum number of bytes the destination can hold.
    pub maximum: usize,
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "value is {} bytes, maximum is {}",
            self.actual, self.maximum
        )
    }
}

/// A fixed-capacity byte buffer holding `0..=N` bytes without heap allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedBytes<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedBytes<N> {
    /// Returns an empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// Copies `slice` into a new bounded buffer.
    ///
    /// Rejects any slice longer than `N` bytes before copying anything, so
    /// this never truncates attacker-controlled input.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CapacityError> {
        if slice.len() > N {
            return Err(CapacityError {
                actual: slice.len(),
                maximum: N,
            });
        }
        let mut buf = [0u8; N];
        if let Some(dest) = buf.get_mut(..slice.len()) {
            dest.copy_from_slice(slice);
        }
        Ok(Self {
            buf,
            len: slice.len(),
        })
    }

    /// Returns the stored bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Returns the number of stored bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the buffer holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for BoundedBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed-capacity UTF-8 string holding `0..=N` bytes without heap
/// allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedStr<const N: usize> {
    bytes: BoundedBytes<N>,
}

/// Errors returned while constructing a [`BoundedStr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedStrError {
    /// The input exceeded the destination's byte capacity.
    Capacity(CapacityError),
    /// The input was not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for BoundedStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(error) => error.fmt(f),
            Self::InvalidUtf8 => f.write_str("value is not valid UTF-8"),
        }
    }
}

impl<const N: usize> BoundedStr<N> {
    /// Copies `slice` into a new bounded string, requiring valid UTF-8.
    pub fn from_utf8_slice(slice: &[u8]) -> Result<Self, BoundedStrError> {
        let bytes = BoundedBytes::from_slice(slice).map_err(BoundedStrError::Capacity)?;
        if str::from_utf8(bytes.as_bytes()).is_err() {
            return Err(BoundedStrError::InvalidUtf8);
        }
        Ok(Self { bytes })
    }

    /// Returns the string contents.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Validated as UTF-8 at construction time in `from_utf8_slice`.
        str::from_utf8(self.bytes.as_bytes()).unwrap_or("")
    }

    /// Returns the number of stored bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<const N: usize> fmt::Display for BoundedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An explicit protocol version (outer signature frame field 2 / inner
/// transaction field 2).
pub type ProtocolVersion = u32;

/// An explicit epoch number (outer signature frame field 3 / inner
/// transaction field 3).
pub type Epoch = u64;

/// Consensus-supported hash algorithm identifiers.
///
/// Duplicated as data from the Sunrise Edge node's
/// `protocol_types::HashAlgorithmId` (see `SIGNING.md`); this crate does not
/// depend on that node workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithmId {
    /// SHA-256.
    Sha2_256,
    /// SHA3-256.
    Sha3_256,
    /// BLAKE3-256.
    Blake3_256,
}

impl HashAlgorithmId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Sha2_256 => 0x0001,
            Self::Sha3_256 => 0x0002,
            Self::Blake3_256 => 0x0003,
        }
    }

    /// Returns a stable display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha2_256 => "sha2-256",
            Self::Sha3_256 => "sha3-256",
            Self::Blake3_256 => "blake3-256",
        }
    }

    /// Parses a wire identifier, rejecting anything unknown.
    pub const fn try_from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Sha2_256),
            0x0002 => Some(Self::Sha3_256),
            0x0003 => Some(Self::Blake3_256),
            _ => None,
        }
    }
}

impl fmt::Display for HashAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A self-describing 32-byte digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest32 {
    algorithm: HashAlgorithmId,
    bytes: [u8; 32],
}

impl Digest32 {
    /// Creates a digest value.
    #[must_use]
    pub const fn new(algorithm: HashAlgorithmId, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the algorithm identifier.
    #[must_use]
    pub const fn algorithm(self) -> HashAlgorithmId {
        self.algorithm
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.algorithm)?;
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Signature scheme identifiers recognized by the outer signature frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureSchemeId {
    /// Ed25519. The only scheme Hardware Signing Profile v1 accepts.
    Ed25519,
    /// Secp256k1. Decodable, but always an [`crate::frame::FrameError`]
    /// rejection under Profile v1.
    Secp256k1,
}

impl SignatureSchemeId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Ed25519 => 0x0001,
            Self::Secp256k1 => 0x0002,
        }
    }

    /// Returns a stable display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1 => "secp256k1",
        }
    }

    /// Parses a wire identifier, rejecting anything unknown.
    pub const fn try_from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Ed25519),
            0x0002 => Some(Self::Secp256k1),
            _ => None,
        }
    }
}

/// A stable 32-byte object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Creates an object identifier from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A stable 32-byte account address (also a raw RFC 8032 Ed25519 public
/// key, per `SIGNING.md`'s provisional derivation policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address([u8; 32]);

impl Address {
    /// Creates an address from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A stable 32-byte canonical asset identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetId([u8; 32]);

impl AssetId {
    /// Creates an asset identifier from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A versioned, digest-authenticated reference to an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Version used for replay protection.
    pub version: u64,
    /// Digest of the referenced object version.
    pub digest: Digest32,
}

/// Access mode requested for an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    /// Read-only access.
    Read,
    /// Mutable access.
    Write,
    /// Consuming access.
    Consume,
}

impl AccessMode {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Consume => 3,
        }
    }

    /// Returns a stable display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Consume => "consume",
        }
    }

    /// Parses a wire identifier, rejecting anything unknown.
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Consume),
            _ => None,
        }
    }
}

/// One access-manifest entry: an object and the access mode requested for
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessEntry {
    /// The referenced object.
    pub object_ref: ObjectRef,
    /// The requested access mode.
    pub mode: AccessMode,
}

/// Maximum access-manifest entries this device profile accepts (see
/// `SIGNING.md`, "Hardware Signing Profile v1").
pub const MAX_ACCESS_ENTRIES: usize = 8;

/// The complete, bounded set of object accesses declared by a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessManifest {
    entries: [Option<AccessEntry>; MAX_ACCESS_ENTRIES],
    len: usize,
}

impl AccessManifest {
    /// Returns an empty manifest.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ACCESS_ENTRIES],
            len: 0,
        }
    }

    /// Appends an entry, rejecting anything past [`MAX_ACCESS_ENTRIES`].
    pub fn push(&mut self, entry: AccessEntry) -> Result<(), CapacityError> {
        let Some(slot) = self.entries.get_mut(self.len) else {
            return Err(CapacityError {
                actual: self.len.saturating_add(1),
                maximum: MAX_ACCESS_ENTRIES,
            });
        };
        *slot = Some(entry);
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Returns the declared entries in wire order.
    pub fn iter(&self) -> impl Iterator<Item = &AccessEntry> {
        self.entries
            .get(..self.len)
            .unwrap_or(&[])
            .iter()
            .filter_map(Option::as_ref)
    }

    /// Returns one entry by index, in wire order.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&AccessEntry> {
        if index >= self.len {
            return None;
        }
        self.entries.get(index).and_then(Option::as_ref)
    }

    /// Returns the number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the manifest has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for AccessManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// A user-authorized fee payment for one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePayment {
    /// Canonical fee asset chosen by the sender.
    pub asset_id: AssetId,
    /// Maximum amount the sender authorizes in that asset.
    pub max_fee: u64,
    /// Object containing the approved fee balance.
    pub fee_object: ObjectRef,
}
