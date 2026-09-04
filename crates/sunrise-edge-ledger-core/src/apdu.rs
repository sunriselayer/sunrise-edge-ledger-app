//! The exact application-owned APDU contract from `SIGNING.md`, "Future
//! APDU contract", as pure, transport-free logic.
//!
//! This module never touches USB/HID/Speculos: [`dispatch`] is a plain
//! function from `(session state, one APDU command, a caller-supplied key
//! deriver)` to either an immediate reply or a pending user-review request.
//! Two things are deliberately injected by the sibling device adapter:
//!
//! * **Key derivation.** SLIP-0010 Ed25519 derivation from a
//!   [`crate::path::DerivationPath`] requires the device SDK and is not
//!   implemented in this pure-logic crate. Every entry point that needs a
//!   derived public key (`verify public key`, and `sign transaction`'s
//!   `LAST` chunk) instead takes a [`PublicKeyDeriver`] callback. Crucially,
//!   this module — not the caller — chooses which path is derived:
//!   [`dispatch`] always calls the deriver with the exact path it just
//!   decoded from `verify public key`'s command data, or with the exact path
//!   captured on `FIRST` for `sign transaction`'s `LAST` chunk. This makes
//!   the device adapter's derivation obligation explicit and prevents
//!   the dispatch caller from independently choosing a path and a key.
//! * **Signing.** `LAST`'s real success response is a 64-byte Ed25519
//!   signature over the buffered frame. This crate does not sign: once
//!   `LAST` fully validates (frame parse, exact policy recognition,
//!   duplicate-`ObjectId` rejection, and a sender/public-key match), it
//!   returns [`DispatchOutcome::ReviewTransaction`] — a validated review
//!   value — rather than fabricating signature bytes. Producing the real signature
//!   (after on-device user approval) is performed by the device adapter via
//!   [`SigningSession::approve_and_sign`].

use crate::frame::decode_signature_frame;
use crate::path::{decode_path, DerivationPath, PATH_ENCODED_LEN};
use crate::policy::ClearSigningPolicy;
use crate::review::{build_review, ClearSigningReview};
use crate::transaction::decode_transaction_signable;

/// Derives the 32-byte RFC 8032 compressed Ed25519 public key for a
/// validated [`DerivationPath`].
///
/// This crate never derives keys itself (see the module documentation): the
/// device adapter supplies an implementation backed by real
/// SLIP-0010 derivation. [`dispatch`] always calls this with a path it has
/// itself validated and captured — never with a caller-selected replacement
/// path. The device adapter is the trusted implementation boundary: it
/// must derive from its `path` argument and return `None` on device failure.
pub trait PublicKeyDeriver {
    /// Derives the public key for `path`, or `None` on derivation failure.
    fn derive(&mut self, path: DerivationPath) -> Option<[u8; 32]>;
}

/// Signs the exact buffered signature frame with the exact derivation path
/// captured from the `FIRST` command.
///
/// [`SigningSession::approve_and_sign`] owns selection of both inputs. A
/// device adapter therefore cannot accidentally sign host-supplied bytes or a
/// path different from the one whose public key was checked before review.
pub trait FrameSigner {
    /// Returns an exact 64-byte Ed25519 signature, or `None` on device
    /// failure.
    fn sign(&mut self, path: DerivationPath, frame: &[u8]) -> Option<[u8; 64]>;
}

impl<F> FrameSigner for F
where
    F: FnMut(DerivationPath, &[u8]) -> Option<[u8; 64]>,
{
    fn sign(&mut self, path: DerivationPath, frame: &[u8]) -> Option<[u8; 64]> {
        self(path, frame)
    }
}

impl<F> PublicKeyDeriver for F
where
    F: FnMut(DerivationPath) -> Option<[u8; 32]>,
{
    fn derive(&mut self, path: DerivationPath) -> Option<[u8; 32]> {
        self(path)
    }
}

/// This app's own CLA. See `SIGNING.md`: CLA `B0` is Ledger's own
/// dashboard CLA and is intercepted before reaching this application; this
/// module never sees or emits it.
pub const CLA: u8 = 0xE0;

/// Instruction codes for [`CLA`].
pub mod ins {
    /// `get configuration`.
    pub const GET_CONFIGURATION: u8 = 0x00;
    /// `verify public key`.
    pub const VERIFY_PUBLIC_KEY: u8 = 0x02;
    /// `sign transaction`.
    pub const SIGN_TRANSACTION: u8 = 0x04;
    /// `reset signing`.
    pub const RESET_SIGNING: u8 = 0x06;
}

/// `P1` sub-states for [`ins::SIGN_TRANSACTION`].
pub mod sign_p1 {
    /// Valid only while idle.
    pub const FIRST: u8 = 0x00;
    /// Valid only while collecting.
    pub const CONTINUE: u8 = 0x01;
    /// Valid only while collecting.
    pub const LAST: u8 = 0x02;
}

/// Maximum complete signed-frame bytes this profile buffers (`SIGNING.md`:
/// "complete signature frame | 4096 bytes").
pub const MAX_FRAME_LEN: usize = 4096;
/// Maximum inner transaction payload bytes (`SIGNING.md`: "inner
/// transaction payload | 3072 bytes").
pub const MAX_TRANSACTION_PAYLOAD_LEN: usize = 3072;
/// Maximum signed-frame payload bytes per chunk (`SIGNING.md`: "Each frame
/// chunk carries at most 230 bytes of signed-frame payload").
pub const MAX_CHUNK_LEN: usize = 230;
/// Minimum `FIRST` command-data length: 4-byte `total_length` + 21-byte
/// path + a 1-byte minimum non-empty chunk.
pub const FIRST_MIN_DATA_LEN: usize = 4 + PATH_ENCODED_LEN + 1;
/// Maximum `FIRST` command-data length: 4-byte `total_length` + 21-byte
/// path + a 230-byte maximum chunk.
pub const FIRST_MAX_DATA_LEN: usize = 4 + PATH_ENCODED_LEN + MAX_CHUNK_LEN;

/// Exact app status words, from `SIGNING.md`, "Future APDU contract".
///
/// This is this app's own `E0`-CLA status-word contract only. SDK/OS
/// status words (`6E03`, `5515`, `E000`) and CLA `B0` interception are
/// documentation-only per `SIGNING.md` and are never emitted by this
/// module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusWord {
    /// `9000`: success.
    Success,
    /// `6985`: user rejected.
    UserRejected,
    /// `6986`: invalid signing state.
    InvalidState,
    /// `6A80`: invalid or unrecognized data.
    InvalidData,
    /// `6A84`: profile bound exceeded.
    ProfileBoundExceeded,
    /// `6A86`: invalid P1/P2.
    InvalidP1P2,
    /// `6D00`: unsupported INS.
    UnsupportedIns,
    /// `6E00`: unsupported CLA.
    UnsupportedCla,
    /// `6F00`: internal failure after state wipe.
    InternalFailure,
}

impl StatusWord {
    /// Returns the exact two-byte status-word value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Success => 0x9000,
            Self::UserRejected => 0x6985,
            Self::InvalidState => 0x6986,
            Self::InvalidData => 0x6A80,
            Self::ProfileBoundExceeded => 0x6A84,
            Self::InvalidP1P2 => 0x6A86,
            Self::UnsupportedIns => 0x6D00,
            Self::UnsupportedCla => 0x6E00,
            Self::InternalFailure => 0x6F00,
        }
    }
}

/// One inbound APDU, already framed by the device SDK transport layer.
///
/// `cla`/`ins`/`p1`/`p2`/`data` mirror the standard APDU header fields;
/// this module assumes `Lc`/length framing has already happened (see
/// `SIGNING.md`'s `6E03` note) and `data` is exactly the command-data
/// bytes.
#[derive(Clone, Copy, Debug)]
pub struct ApduCommand<'a> {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data.
    pub data: &'a [u8],
}

/// Immediate response data for an APDU command that does not require UI or
/// device signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImmediateResponse {
    /// Empty response bytes.
    Empty,
    /// `get configuration` success: exactly 6 bytes (profile `u16` BE,
    /// major/minor/patch `u8` each, flags `u8`).
    Configuration([u8; 6]),
}

/// An immediate APDU reply that is safe to put on the wire as-is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApduReply {
    /// The exact status word.
    pub status: StatusWord,
    /// Response data, meaningful only when `status` is
    /// [`StatusWord::Success`].
    pub response: ImmediateResponse,
}

impl ApduReply {
    const fn success(response: ImmediateResponse) -> Self {
        Self {
            status: StatusWord::Success,
            response,
        }
    }

    const fn failure(status: StatusWord) -> Self {
        Self {
            status,
            response: ImmediateResponse::Empty,
        }
    }
}

/// Pure dispatch result. Review variants are deliberately not represented as
/// `9000`: the device adapter must first obtain user approval and, for a
/// transaction, produce the exact signature response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// A complete immediate APDU reply.
    Reply(ApduReply),
    /// A validated public key/path pair that still requires on-device address
    /// confirmation. Approval returns the public key; rejection returns
    /// [`StatusWord::UserRejected`].
    ReviewPublicKey {
        /// Validated provisional derivation path.
        path: DerivationPath,
        /// Derived RFC 8032 compressed Ed25519 public key.
        public_key: [u8; 32],
    },
    /// A fully validated transaction review. The session retains the exact
    /// frame and path until the adapter calls
    /// [`SigningSession::approve_and_sign`] or
    /// [`SigningSession::reject_review`].
    ReviewTransaction(ClearSigningReview),
}

/// Internal signing-session state. `AwaitingApproval` is an adapter handoff,
/// not a third host-visible APDU chunk state: the Ledger SDK rejects a second
/// APDU with its SDK-owned `0x6901` while the synchronous review UI is active,
/// before it can reach [`dispatch`]. At the reusable core boundary, any known
/// non-reset command received while approval is pending fails closed with
/// [`StatusWord::InvalidState`]; an unknown INS retains its stable
/// [`StatusWord::UnsupportedIns`] response. Both paths wipe the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    Idle,
    Collecting,
    AwaitingApproval,
}

/// The device-side `sign transaction` state machine: a bounded frame
/// buffer plus the path captured on `FIRST`.
///
/// Every failure, rejection, or `reset signing` call wipes the buffered
/// frame and derivation state back to idle (`buffer` bytes are explicitly
/// zeroed, not merely marked unused). No state survives app restart,
/// mirrored here by [`SigningSession::new`] always starting idle.
pub struct SigningSession {
    state: SessionState,
    buffer: [u8; MAX_FRAME_LEN],
    buffered_len: usize,
    declared_total: u32,
    received_len: u32,
    path: Option<DerivationPath>,
}

impl SigningSession {
    /// Creates a new, idle session.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::Idle,
            buffer: [0u8; MAX_FRAME_LEN],
            buffered_len: 0,
            declared_total: 0,
            received_len: 0,
            path: None,
        }
    }

    /// Returns whether the session is idle (no signing sequence in
    /// progress).
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.state == SessionState::Idle
    }

    /// Returns the path captured on `FIRST`, if a sequence is in progress.
    #[must_use]
    pub fn path(&self) -> Option<DerivationPath> {
        self.path
    }

    /// Returns the exact signed frame while a validated transaction is waiting
    /// for user approval. It is unavailable in every other state.
    #[must_use]
    pub fn pending_frame(&self) -> Option<&[u8]> {
        if self.state != SessionState::AwaitingApproval {
            return None;
        }
        self.buffer.get(..self.buffered_len)
    }

    /// Signs the exact pending frame with the captured path and then wipes all
    /// buffered signing material before returning, whether signing succeeds
    /// or fails.
    ///
    /// The signer never receives caller-selected bytes or a caller-selected
    /// path. Calling this outside the awaiting-approval state fails closed and
    /// also wipes any partial state.
    pub fn approve_and_sign(
        &mut self,
        signer: &mut impl FrameSigner,
    ) -> Result<[u8; 64], StatusWord> {
        if self.state != SessionState::AwaitingApproval {
            self.wipe();
            return Err(StatusWord::InvalidState);
        }
        let Some(path) = self.path else {
            self.wipe();
            return Err(StatusWord::InternalFailure);
        };
        let Some(frame) = self.buffer.get(..self.buffered_len) else {
            self.wipe();
            return Err(StatusWord::InternalFailure);
        };
        let signature = signer.sign(path, frame);
        self.wipe();
        signature.ok_or(StatusWord::InternalFailure)
    }

    /// Rejects a pending review and wipes all buffered signing material.
    /// Calling it in another state is still a safe, idempotent wipe.
    pub fn reject_review(&mut self) {
        self.wipe();
    }

    fn wipe(&mut self) {
        if let Some(used) = self.buffer.get_mut(..self.buffered_len) {
            for byte in used {
                *byte = 0;
            }
        }
        self.state = SessionState::Idle;
        self.buffered_len = 0;
        self.declared_total = 0;
        self.received_len = 0;
        self.path = None;
    }

    /// `reset signing`: idempotent, always wipes.
    pub fn reset(&mut self) {
        self.wipe();
    }

    fn append_chunk(&mut self, chunk: &[u8]) -> Result<(), StatusWord> {
        let new_received = self
            .received_len
            .checked_add(u32::try_from(chunk.len()).map_err(|_| StatusWord::InternalFailure)?)
            .ok_or(StatusWord::InternalFailure)?;
        if new_received > self.declared_total {
            return Err(StatusWord::ProfileBoundExceeded);
        }
        let new_len = self
            .buffered_len
            .checked_add(chunk.len())
            .ok_or(StatusWord::InternalFailure)?;
        let dest = self
            .buffer
            .get_mut(self.buffered_len..new_len)
            .ok_or(StatusWord::InternalFailure)?;
        dest.copy_from_slice(chunk);
        self.buffered_len = new_len;
        self.received_len = new_received;
        Ok(())
    }
}

impl Default for SigningSession {
    fn default() -> Self {
        Self::new()
    }
}

/// `get configuration`'s pinned profile identifier (`SIGNING.md`: "pinned
/// to exactly `1` for Hardware Signing Profile v1").
pub const CONFIGURATION_PROFILE: u16 = 1;
/// This crate's semantic-version major component, reported by `get
/// configuration`.
pub const CONFIGURATION_MAJOR: u8 = 0;
/// This crate's semantic-version minor component, reported by `get
/// configuration`.
pub const CONFIGURATION_MINOR: u8 = 1;
/// This crate's semantic-version patch component, reported by `get
/// configuration`.
pub const CONFIGURATION_PATCH: u8 = 0;
/// `get configuration`'s flags byte. `SIGNING.md`: "Every flags bit
/// defined by this document is currently `0`."
pub const CONFIGURATION_FLAGS: u8 = 0;

fn handle_get_configuration(p1: u8, p2: u8, data: &[u8]) -> DispatchOutcome {
    if p1 != 0x00 || p2 != 0x00 {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidP1P2));
    }
    if !data.is_empty() {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    let profile_be = CONFIGURATION_PROFILE.to_be_bytes();
    let response = [
        profile_be[0],
        profile_be[1],
        CONFIGURATION_MAJOR,
        CONFIGURATION_MINOR,
        CONFIGURATION_PATCH,
        CONFIGURATION_FLAGS,
    ];
    DispatchOutcome::Reply(ApduReply::success(ImmediateResponse::Configuration(
        response,
    )))
}

fn handle_verify_public_key(
    p1: u8,
    p2: u8,
    data: &[u8],
    deriver: &mut impl PublicKeyDeriver,
) -> DispatchOutcome {
    // "`verify public key` always requires on-device confirmation; P1 `00`
    // is invalid." Only P1 `01` is defined.
    if p1 != 0x01 || p2 != 0x00 {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidP1P2));
    }
    let Ok(path) = decode_path(data) else {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    let Some(public_key) = deriver.derive(path) else {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InternalFailure));
    };
    DispatchOutcome::ReviewPublicKey { path, public_key }
}

fn handle_reset_signing(
    session: &mut SigningSession,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> DispatchOutcome {
    if p1 != 0x00 || p2 != 0x00 {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidP1P2));
    }
    if !data.is_empty() {
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    session.reset();
    DispatchOutcome::Reply(ApduReply::success(ImmediateResponse::Empty))
}

fn handle_sign_transaction(
    session: &mut SigningSession,
    p1: u8,
    p2: u8,
    data: &[u8],
    deriver: &mut impl PublicKeyDeriver,
    policy: &ClearSigningPolicy,
) -> DispatchOutcome {
    if p2 != 0x00 {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidP1P2));
    }

    match p1 {
        sign_p1::FIRST => handle_first(session, data),
        sign_p1::CONTINUE => handle_continue(session, data),
        sign_p1::LAST => handle_last(session, data, deriver, policy),
        _ => {
            session.wipe();
            DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidP1P2))
        }
    }
}

fn handle_first(session: &mut SigningSession, data: &[u8]) -> DispatchOutcome {
    if !session.is_idle() {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidState));
    }
    if data.len() < FIRST_MIN_DATA_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    if data.len() > FIRST_MAX_DATA_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    }

    let Some(total_length_bytes) = data.get(0..4) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    let Ok(total_length_array) = <[u8; 4]>::try_from(total_length_bytes) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    let total_length = u32::from_be_bytes(total_length_array);
    let Ok(total_length_usize) = usize::try_from(total_length) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    };
    if total_length == 0 || total_length_usize > MAX_FRAME_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    }

    let Some(path_bytes) = data.get(4..4 + PATH_ENCODED_LEN) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    let Ok(path) = decode_path(path_bytes) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };

    let Some(chunk) = data.get(4 + PATH_ENCODED_LEN..) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    // `chunk` is non-empty and at most `MAX_CHUNK_LEN` by the FIRST_MIN/MAX
    // data-length bounds already checked above. `SIGNING.md` never lets a
    // signing sequence finish on FIRST: only LAST's success response
    // carries the signature, and LAST is "valid only while collecting", so
    // FIRST can never itself deliver the complete declared total. Reject
    // that here (implied multi-chunk rule) rather than leaving a
    // fully-received session that no legal LAST call could ever complete.
    if total_length_usize == chunk.len() {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }

    session.declared_total = total_length;
    session.path = Some(path);
    session.state = SessionState::Collecting;
    if let Err(status) = session.append_chunk(chunk) {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(status));
    }

    DispatchOutcome::Reply(ApduReply::success(ImmediateResponse::Empty))
}

fn handle_continue(session: &mut SigningSession, data: &[u8]) -> DispatchOutcome {
    if session.state != SessionState::Collecting {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidState));
    }
    if data.is_empty() {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    if data.len() > MAX_CHUNK_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    }
    let Some(remaining) = session.declared_total.checked_sub(session.received_len) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InternalFailure));
    };
    // Same implied multi-chunk rule as `handle_first`: only LAST may
    // deliver the chunk that completes the declared total, so a CONTINUE
    // that would exactly finish it is rejected rather than silently
    // accepted with no legal way to reach LAST afterward.
    if usize::try_from(remaining).ok() == Some(data.len()) {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    if let Err(status) = session.append_chunk(data) {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(status));
    }
    DispatchOutcome::Reply(ApduReply::success(ImmediateResponse::Empty))
}

fn handle_last(
    session: &mut SigningSession,
    data: &[u8],
    deriver: &mut impl PublicKeyDeriver,
    policy: &ClearSigningPolicy,
) -> DispatchOutcome {
    if session.state != SessionState::Collecting {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidState));
    }
    if data.is_empty() {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }
    if data.len() > MAX_CHUNK_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    }
    if let Err(status) = session.append_chunk(data) {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(status));
    }
    if session.received_len != session.declared_total {
        // "premature LAST": fewer bytes than declared were ever delivered.
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }

    let Some(framed) = session.buffer.get(..session.buffered_len) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InternalFailure));
    };

    let Ok(frame) = decode_signature_frame(framed) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };
    if frame.payload.len() > MAX_TRANSACTION_PAYLOAD_LEN {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::ProfileBoundExceeded));
    }
    let Ok(transaction) = decode_transaction_signable(frame.payload) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };

    // "Before rendering any review screen, LAST must derive the 32-byte
    // public key from the path supplied on FIRST ... and compare it
    // byte-for-byte against the parsed Transaction v1 `sender` field; on
    // any mismatch LAST returns `6A80` and wipes ... without displaying
    // any review page." `session.path()` is the exact path captured on
    // FIRST, never a value this function or its caller could substitute.
    let Some(path) = session.path() else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InternalFailure));
    };
    let Some(derived_public_key) = deriver.derive(path) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InternalFailure));
    };
    if transaction.sender.as_bytes() != &derived_public_key {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    }

    let Ok(review) = build_review(&frame, &transaction, policy) else {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidData));
    };

    session.state = SessionState::AwaitingApproval;
    DispatchOutcome::ReviewTransaction(review)
}

/// Dispatches one APDU command against `session`.
///
/// `deriver` is the caller-supplied key-derivation callback (see the module
/// documentation and [`PublicKeyDeriver`]). This function — never the
/// caller — chooses which path is passed to it: for `verify public key`,
/// the exact path just decoded from `command.data`; for `sign
/// transaction`'s `LAST` chunk, the exact path captured on `FIRST`
/// (`session.path()`). It is not called for every other command/state, and
/// a `None` result fails closed with [`StatusWord::InternalFailure`],
/// wiping any live signing state.
pub fn dispatch(
    session: &mut SigningSession,
    command: ApduCommand<'_>,
    deriver: &mut impl PublicKeyDeriver,
    policy: &ClearSigningPolicy,
) -> DispatchOutcome {
    if command.cla != CLA {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::UnsupportedCla));
    }
    let known_command_conflicts_with_session: bool = match command.ins {
        ins::GET_CONFIGURATION | ins::VERIFY_PUBLIC_KEY => !session.is_idle(),
        ins::SIGN_TRANSACTION => session.state == SessionState::AwaitingApproval,
        _ => false,
    };
    if known_command_conflicts_with_session {
        session.wipe();
        return DispatchOutcome::Reply(ApduReply::failure(StatusWord::InvalidState));
    }

    let outcome = match command.ins {
        ins::GET_CONFIGURATION => handle_get_configuration(command.p1, command.p2, command.data),
        ins::VERIFY_PUBLIC_KEY => {
            handle_verify_public_key(command.p1, command.p2, command.data, deriver)
        }
        ins::SIGN_TRANSACTION => handle_sign_transaction(
            session,
            command.p1,
            command.p2,
            command.data,
            deriver,
            policy,
        ),
        ins::RESET_SIGNING => handle_reset_signing(session, command.p1, command.p2, command.data),
        _ => DispatchOutcome::Reply(ApduReply::failure(StatusWord::UnsupportedIns)),
    };
    if matches!(
        outcome,
        DispatchOutcome::Reply(ApduReply {
            status: StatusWord::UserRejected
                | StatusWord::InvalidState
                | StatusWord::InvalidData
                | StatusWord::ProfileBoundExceeded
                | StatusWord::InvalidP1P2
                | StatusWord::UnsupportedIns
                | StatusWord::UnsupportedCla
                | StatusWord::InternalFailure,
            ..
        })
    ) {
        session.wipe();
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::{
        ins, ApduCommand, DispatchOutcome, PublicKeyDeriver, SessionState, SigningSession,
        StatusWord,
    };
    use crate::path::{decode_path, DerivationPath};
    use crate::policy::DEVNET_ASSET_TRANSFER_POLICY;

    struct RecordingDeriver {
        result: Option<[u8; 32]>,
        calls: usize,
        last_path: Option<DerivationPath>,
    }

    impl RecordingDeriver {
        const fn new(result: Option<[u8; 32]>) -> Self {
            Self {
                result,
                calls: 0,
                last_path: None,
            }
        }
    }

    impl PublicKeyDeriver for RecordingDeriver {
        fn derive(&mut self, path: DerivationPath) -> Option<[u8; 32]> {
            self.calls += 1;
            self.last_path = Some(path);
            self.result
        }
    }

    fn encoded_path(account: u32) -> [u8; 21] {
        let components: [u32; 5] = [44, 21_333, account, 0, 0];
        let mut encoded: [u8; 21] = [0_u8; 21];
        encoded[0] = 5;
        for (index, component) in components.into_iter().enumerate() {
            let start: usize = 1 + index * 4;
            encoded[start..start + 4].copy_from_slice(&(component | 0x8000_0000).to_be_bytes());
        }
        encoded
    }

    #[test]
    #[allow(clippy::panic)]
    fn verify_public_key_calls_deriver_with_exact_decoded_path() {
        let mut session: SigningSession = SigningSession::new();
        let mut deriver: RecordingDeriver = RecordingDeriver::new(Some([9_u8; 32]));
        let path_bytes: [u8; 21] = encoded_path(11);

        let outcome: DispatchOutcome = super::dispatch(
            &mut session,
            ApduCommand {
                cla: super::CLA,
                ins: ins::VERIFY_PUBLIC_KEY,
                p1: 0x01,
                p2: 0x00,
                data: &path_bytes,
            },
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        );

        assert_eq!(deriver.calls, 1);
        let expected_path: DerivationPath = match decode_path(&path_bytes) {
            Ok(path) => path,
            Err(error) => panic!("valid test path must decode: {error:?}"),
        };
        assert_eq!(deriver.last_path, Some(expected_path));
        assert!(matches!(
            outcome,
            DispatchOutcome::ReviewPublicKey { path, public_key }
                if path == expected_path && public_key == [9_u8; 32]
        ));
    }

    #[test]
    fn verify_public_key_derivation_failure_fails_closed() {
        let mut session: SigningSession = SigningSession::new();
        let mut deriver: RecordingDeriver = RecordingDeriver::new(None);
        let path_bytes: [u8; 21] = encoded_path(11);

        let outcome: DispatchOutcome = super::dispatch(
            &mut session,
            ApduCommand {
                cla: super::CLA,
                ins: ins::VERIFY_PUBLIC_KEY,
                p1: 0x01,
                p2: 0x00,
                data: &path_bytes,
            },
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        );

        assert_eq!(deriver.calls, 1);
        assert_eq!(
            outcome,
            DispatchOutcome::Reply(super::ApduReply::failure(StatusWord::InternalFailure))
        );
        assert!(session.is_idle());
    }

    #[test]
    fn wipe_zeroes_used_bytes_and_clears_all_metadata() {
        let encoded_path: [u8; 21] = [
            5, 0x80, 0, 0, 44, 0x80, 0, 0x53, 0x55, 0x80, 0, 0, 7, 0x80, 0, 0, 0, 0x80, 0, 0, 0,
        ];
        let mut session: SigningSession = SigningSession::new();
        session.state = SessionState::Collecting;
        session.buffer[..4].copy_from_slice(&[1, 2, 3, 4]);
        session.buffered_len = 4;
        session.declared_total = 4;
        session.received_len = 4;
        session.path = decode_path(&encoded_path).ok();

        session.wipe();

        assert!(session.buffer.iter().all(|byte| *byte == 0));
        assert!(session.is_idle());
        assert_eq!(session.buffered_len, 0);
        assert_eq!(session.declared_total, 0);
        assert_eq!(session.received_len, 0);
        assert_eq!(session.path, None);
    }
}
