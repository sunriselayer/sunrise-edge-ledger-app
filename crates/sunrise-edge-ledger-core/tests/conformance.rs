#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Cross-repository fixture and adversarial APDU conformance tests.

use sunrise_edge_ledger_core::apdu::{
    dispatch, ins, sign_p1, ApduCommand, ApduReply, DispatchOutcome, ImmediateResponse,
    PublicKeyDeriver, SigningSession, StatusWord, MAX_CHUNK_LEN, MAX_TRANSACTION_PAYLOAD_LEN,
};
use sunrise_edge_ledger_core::canonical::{decode_canonical_frame, CanonicalError};
use sunrise_edge_ledger_core::frame::{decode_signature_frame, FrameError};
use sunrise_edge_ledger_core::path::{decode_path, DerivationPath, PathError, PATH_ENCODED_LEN};
use sunrise_edge_ledger_core::policy::{PolicyError, DEVNET_ASSET_TRANSFER_POLICY};
use sunrise_edge_ledger_core::review::{build_review, ReviewError};
use sunrise_edge_ledger_core::transaction::{decode_transaction_signable, TransactionError};

/// A [`PublicKeyDeriver`] that always returns `key` and records the exact
/// path it was called with, so tests can prove `dispatch` derives from the
/// path it validated rather than trusting an arbitrary caller-supplied key.
struct FixedDeriver {
    key: [u8; 32],
    calls: usize,
    last_path: Option<DerivationPath>,
}

impl FixedDeriver {
    const fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            calls: 0,
            last_path: None,
        }
    }
}

impl PublicKeyDeriver for FixedDeriver {
    fn derive(&mut self, path: DerivationPath) -> Option<[u8; 32]> {
        self.calls += 1;
        self.last_path = Some(path);
        Some(self.key)
    }
}

/// A [`PublicKeyDeriver`] that always fails, for fail-closed tests.
struct FailingDeriver {
    calls: usize,
}

impl FailingDeriver {
    const fn new() -> Self {
        Self { calls: 0 }
    }
}

impl PublicKeyDeriver for FailingDeriver {
    fn derive(&mut self, _path: DerivationPath) -> Option<[u8; 32]> {
        self.calls += 1;
        None
    }
}

/// The exact 32 pinned display lines from the source workspace's
/// `crates/signing-view/tests/fixtures.rs`, commit `1dd4d2d`
/// (`RECOGNIZED_TRANSFER_LINES`), copied verbatim as fixture evidence. This
/// crate builds no such line-oriented view itself (see `review.rs`); the
/// renderer below is test-only, exists solely to compare every pinned fact
/// against this crate's typed [`ClearSigningReview`] fields, and must never
/// be promoted into non-test, allocation-using production code.
const RECOGNIZED_TRANSFER_LINES: &[&str] = &[
    "chain_id=sunrise-local-devnet",
    "protocol_version=3",
    "epoch=0",
    "message_type=transaction-v1",
    "scheme=ed25519",
    "sender=0101010101010101010101010101010101010101010101010101010101010101",
    "nonce=1",
    "module_id=0d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7",
    "module_version=3",
    "module_digest=sha2-256:01534128f12eb4cf469bfa29677bbced1344879de2870315847cbb7faec21619",
    "entrypoint=transfer",
    "amount=1000000",
    "gas_limit=1000",
    "manifest_count=3",
    "access[0].mode=write",
    "access[0].object_id=1111111111111111111111111111111111111111111111111111111111111111",
    "access[0].version=1",
    "access[0].digest=sha2-256:1212121212121212121212121212121212121212121212121212121212121212",
    "access[1].mode=write",
    "access[1].object_id=2121212121212121212121212121212121212121212121212121212121212121",
    "access[1].version=2",
    "access[1].digest=sha2-256:2222222222222222222222222222222222222222222222222222222222222222",
    "access[2].mode=write",
    "access[2].object_id=3131313131313131313131313131313131313131313131313131313131313131",
    "access[2].version=3",
    "access[2].digest=sha2-256:3232323232323232323232323232323232323232323232323232323232323232",
    "fee_payment=present",
    "fee_asset=ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8",
    "fee_max=1001",
    "fee_object_id=1111111111111111111111111111111111111111111111111111111111111111",
    "fee_object_version=1",
    "fee_object_digest=sha2-256:1212121212121212121212121212121212121212121212121212121212121212",
];

/// Test-only renderer over this crate's typed [`ClearSigningReview`],
/// producing the same `field=value` lines as the source workspace's
/// `signing-view::build_clear_signing_view`, so a plain `==` against
/// [`RECOGNIZED_TRANSFER_LINES`] exercises every pinned display fact in
/// order. Every value comes from a typed field or a production `Display`/
/// `label` impl already used by non-test code; this function adds no new
/// formatting logic of its own to trust.
fn render_review_lines(
    review: &sunrise_edge_ledger_core::review::ClearSigningReview,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::with_capacity(32);
    lines.push(format!("chain_id={}", review.chain_id.as_str()));
    lines.push(format!("protocol_version={}", review.protocol_version));
    lines.push(format!("epoch={}", review.epoch));
    lines.push(format!("message_type={}", review.message_type.as_str()));
    lines.push(format!("scheme={}", review.scheme.label()));
    lines.push(format!("sender={}", review.sender));
    lines.push(format!("nonce={}", review.nonce));
    lines.push(format!("module_id={}", review.module_id));
    lines.push(format!("module_version={}", review.module_version));
    lines.push(format!("module_digest={}", review.module_digest));
    lines.push(format!("entrypoint={}", review.entrypoint.as_str()));
    lines.push(format!("{}={}", review.amount_label, review.amount));
    lines.push(format!("gas_limit={}", review.gas_limit));
    lines.push(format!("manifest_count={}", review.access_entries.len()));
    for (index, line) in review.access_lines().enumerate() {
        lines.push(format!("access[{index}].mode={}", line.mode.label()));
        lines.push(format!("access[{index}].object_id={}", line.object_id));
        lines.push(format!("access[{index}].version={}", line.version));
        lines.push(format!("access[{index}].digest={}", line.digest));
    }
    let fee = review
        .fee
        .expect("recognized-transfer fixture always carries a fee");
    lines.push("fee_payment=present".to_string());
    lines.push(format!("fee_asset={}", fee.asset_id));
    lines.push(format!("fee_max={}", fee.max_fee));
    lines.push(format!("fee_object_id={}", fee.fee_object_id));
    lines.push(format!("fee_object_version={}", fee.fee_object_version));
    lines.push(format!("fee_object_digest={}", fee.fee_object_digest));
    lines
}

const FIXTURE_HEX: &str = include_str!("fixtures/recognized_transfer.hex");

fn fixture() -> Vec<u8> {
    hex::decode(FIXTURE_HEX.trim()).expect("committed fixture must be valid hexadecimal")
}

// --- Small, test-only canonical frame rebuild helpers -----------------
//
// These assemble the exact wire shape `canonical.rs` decodes (magic,
// little-endian type_id/version/field_count, then strictly-increasing
// `(field_id, len, bytes)` entries) from scratch, so adversarial tests can
// construct a specific, minimal frame for exactly the branch under test
// instead of mutating fixed offsets inside the committed fixture hex (which
// breaks silently the moment an earlier field's length changes).

fn canonical_field(field_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(&field_id.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload fits u32")
            .to_le_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

fn canonical_frame(type_id: u16, version: u16, fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"SNRE");
    out.extend_from_slice(&type_id.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(
        &u16::try_from(fields.len())
            .expect("test field count fits u16")
            .to_le_bytes(),
    );
    for (field_id, payload) in fields {
        out.extend_from_slice(&canonical_field(*field_id, payload));
    }
    out
}

fn digest32_bytes(algorithm_id: u16, bytes: [u8; 32]) -> Vec<u8> {
    canonical_frame(
        0x0103,
        1,
        &[
            (1, algorithm_id.to_le_bytes().to_vec()),
            (2, bytes.to_vec()),
        ],
    )
}

fn object_id_bytes(bytes: [u8; 32]) -> Vec<u8> {
    canonical_frame(0x4001, 1, &[(1, bytes.to_vec())])
}

fn object_ref_bytes(
    id: [u8; 32],
    version: u64,
    digest_algorithm_id: u16,
    digest: [u8; 32],
) -> Vec<u8> {
    canonical_frame(
        0x4004,
        1,
        &[
            (1, object_id_bytes(id)),
            (2, version.to_le_bytes().to_vec()),
            (3, digest32_bytes(digest_algorithm_id, digest)),
        ],
    )
}

fn access_mode_bytes(mode: u8) -> Vec<u8> {
    canonical_frame(0x4006, 1, &[(1, vec![mode])])
}

fn access_entry_bytes(object_ref: Vec<u8>, mode: u8) -> Vec<u8> {
    canonical_frame(0x5001, 1, &[(1, object_ref), (2, access_mode_bytes(mode))])
}

fn access_manifest_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut fields: Vec<(u16, Vec<u8>)> = Vec::with_capacity(entries.len() + 1);
    fields.push((
        1,
        u32::try_from(entries.len())
            .expect("test entry count fits u32")
            .to_le_bytes()
            .to_vec(),
    ));
    for (index, entry) in entries.iter().enumerate() {
        let field_id: u16 = u16::try_from(index + 2).expect("test entry index fits a field id");
        fields.push((field_id, entry.clone()));
    }
    canonical_frame(0x5002, 1, &fields)
}

fn asset_id_bytes(bytes: [u8; 32]) -> Vec<u8> {
    canonical_frame(0x7001, 1, &[(1, bytes.to_vec())])
}

fn fee_payment_bytes(asset: [u8; 32], max_fee: u64, fee_object: Vec<u8>) -> Vec<u8> {
    canonical_frame(
        0x7002,
        1,
        &[
            (1, asset_id_bytes(asset)),
            (2, max_fee.to_le_bytes().to_vec()),
            (3, fee_object),
        ],
    )
}

fn amount_args_bytes(type_id: u16, version: u16, field_id: u16, amount: u64) -> Vec<u8> {
    canonical_frame(
        type_id,
        version,
        &[(field_id, amount.to_le_bytes().to_vec())],
    )
}

// --- The pinned devnet transfer policy's exact values ------------------
//
// `ClearSigningPolicy`'s fields are private (see `policy.rs`); these are
// copied as data from `DEVNET_ASSET_TRANSFER_POLICY`, exactly like
// `wrong_module_digest_is_a_typed_policy_rejection` already does for the
// digest bytes, so builder-based tests can construct a transaction that
// matches the policy everywhere except the one field under test.

const POLICY_CHAIN_ID: &str = "sunrise-local-devnet";
const POLICY_PROTOCOL_VERSION: u32 = 3;
const POLICY_EPOCH: u64 = 0;
const POLICY_MODULE_ID: [u8; 32] = [
    0x0D, 0x5D, 0xD1, 0x0A, 0xEC, 0x2C, 0x31, 0x5B, 0x1D, 0xC5, 0x64, 0xC6, 0x94, 0x43, 0x9E, 0x46,
    0xBA, 0xC4, 0xB6, 0x14, 0x26, 0xD2, 0x2E, 0x0D, 0x7D, 0xDB, 0x76, 0x4C, 0x49, 0x19, 0x7F, 0xE7,
];
const POLICY_MODULE_VERSION: u64 = 3;
const POLICY_MODULE_DIGEST_ALGORITHM: u16 = 0x0001; // Sha2_256
const POLICY_MODULE_DIGEST: [u8; 32] = [
    0x01, 0x53, 0x41, 0x28, 0xF1, 0x2E, 0xB4, 0xCF, 0x46, 0x9B, 0xFA, 0x29, 0x67, 0x7B, 0xBC, 0xED,
    0x13, 0x44, 0x87, 0x9D, 0xE2, 0x87, 0x03, 0x15, 0x84, 0x7C, 0xBB, 0x7F, 0xAE, 0xC2, 0x16, 0x19,
];
const POLICY_ENTRYPOINT: &str = "transfer";
const POLICY_ARGS_TYPE_ID: u16 = 0xF002;
const POLICY_ARGS_VERSION: u16 = 1;
const POLICY_ARGS_FIELD_ID: u16 = 1;
const POLICY_FEE_ASSET_ID: [u8; 32] = [
    0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47, 0xBC, 0x11,
    0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B, 0x43, 0x3E, 0xA8,
];

/// A builder for a synthetic, policy-recognized `TransactionSignable`,
/// matching `DEVNET_ASSET_TRANSFER_POLICY` in every field. Tests mutate
/// exactly one field before calling [`TxFields::build`] so a failure can
/// only be attributed to that field.
#[derive(Clone)]
struct TxFields {
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    sender: [u8; 32],
    nonce: u64,
    access_entries: Vec<Vec<u8>>,
    module_ref: Vec<u8>,
    entrypoint: String,
    args: Vec<u8>,
    gas_limit: u64,
    fee_payment: Option<Vec<u8>>,
}

impl TxFields {
    fn recognized() -> Self {
        let source_ref: Vec<u8> = object_ref_bytes(
            [0x11_u8; 32],
            1,
            POLICY_MODULE_DIGEST_ALGORITHM,
            [0x12_u8; 32],
        );
        let dest_ref: Vec<u8> = object_ref_bytes(
            [0x21_u8; 32],
            2,
            POLICY_MODULE_DIGEST_ALGORITHM,
            [0x22_u8; 32],
        );
        let treasury_ref: Vec<u8> = object_ref_bytes(
            [0x31_u8; 32],
            3,
            POLICY_MODULE_DIGEST_ALGORITHM,
            [0x32_u8; 32],
        );

        let access_entries: Vec<Vec<u8>> = vec![
            access_entry_bytes(source_ref.clone(), 2),
            access_entry_bytes(dest_ref, 2),
            access_entry_bytes(treasury_ref, 2),
        ];

        let module_ref: Vec<u8> = object_ref_bytes(
            POLICY_MODULE_ID,
            POLICY_MODULE_VERSION,
            POLICY_MODULE_DIGEST_ALGORITHM,
            POLICY_MODULE_DIGEST,
        );

        Self {
            chain_id: POLICY_CHAIN_ID.to_string(),
            protocol_version: POLICY_PROTOCOL_VERSION,
            epoch: POLICY_EPOCH,
            sender: [1_u8; 32],
            nonce: 1,
            access_entries,
            module_ref,
            entrypoint: POLICY_ENTRYPOINT.to_string(),
            args: amount_args_bytes(
                POLICY_ARGS_TYPE_ID,
                POLICY_ARGS_VERSION,
                POLICY_ARGS_FIELD_ID,
                1_000_000,
            ),
            gas_limit: 1_000,
            fee_payment: Some(fee_payment_bytes(POLICY_FEE_ASSET_ID, 1_001, source_ref)),
        }
    }

    fn build_with_extra(&self, extra: Option<(u16, Vec<u8>)>) -> Vec<u8> {
        let mut fields: Vec<(u16, Vec<u8>)> = vec![
            (1, self.chain_id.as_bytes().to_vec()),
            (2, self.protocol_version.to_le_bytes().to_vec()),
            (3, self.epoch.to_le_bytes().to_vec()),
            (4, self.sender.to_vec()),
            (5, self.nonce.to_le_bytes().to_vec()),
            (6, access_manifest_bytes(&self.access_entries)),
            (7, self.module_ref.clone()),
            (8, self.entrypoint.as_bytes().to_vec()),
            (9, self.args.clone()),
            (10, self.gas_limit.to_le_bytes().to_vec()),
        ];
        if let Some(fee) = &self.fee_payment {
            fields.push((11, fee.clone()));
        }
        if let Some(extra_field) = extra {
            fields.push(extra_field);
        }
        canonical_frame(0x6001, 1, &fields)
    }

    fn build(&self) -> Vec<u8> {
        self.build_with_extra(None)
    }
}

/// A builder for the outer `SignatureFrame` wrapping a `TxFields` payload,
/// matching the same pinned chain/protocol/epoch by default.
#[derive(Clone)]
struct FrameFields {
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    message_type: String,
    scheme: u16,
    payload: Vec<u8>,
}

impl FrameFields {
    fn wrapping(payload: Vec<u8>) -> Self {
        Self {
            chain_id: POLICY_CHAIN_ID.to_string(),
            protocol_version: POLICY_PROTOCOL_VERSION,
            epoch: POLICY_EPOCH,
            message_type: "transaction-v1".to_string(),
            scheme: 1, // Ed25519
            payload,
        }
    }

    fn build(&self) -> Vec<u8> {
        canonical_frame(
            0x2001,
            1,
            &[
                (1, self.chain_id.as_bytes().to_vec()),
                (2, self.protocol_version.to_le_bytes().to_vec()),
                (3, self.epoch.to_le_bytes().to_vec()),
                (4, self.message_type.as_bytes().to_vec()),
                (5, self.scheme.to_le_bytes().to_vec()),
                (6, self.payload.clone()),
            ],
        )
    }
}

fn provisional_path(account: u32) -> [u8; PATH_ENCODED_LEN] {
    let components: [u32; 5] = [44, 21_333, account, 0, 0];
    let mut encoded: [u8; PATH_ENCODED_LEN] = [0_u8; PATH_ENCODED_LEN];
    encoded[0] = 5;
    for (index, component) in components.into_iter().enumerate() {
        let start: usize = 1 + index * 4;
        encoded[start..start + 4].copy_from_slice(&(component | 0x8000_0000).to_be_bytes());
    }
    encoded
}

fn command(ins_byte: u8, p1: u8, data: &[u8]) -> ApduCommand<'_> {
    ApduCommand {
        cla: 0xE0,
        ins: ins_byte,
        p1,
        p2: 0,
        data,
    }
}

fn reply_status(outcome: &DispatchOutcome) -> StatusWord {
    match outcome {
        DispatchOutcome::Reply(ApduReply { status, .. }) => *status,
        DispatchOutcome::ReviewPublicKey { .. } | DispatchOutcome::ReviewTransaction(_) => {
            panic!("expected an immediate reply")
        }
    }
}

fn begin_data(total_length: usize, chunk: &[u8]) -> Vec<u8> {
    let total: u32 = u32::try_from(total_length).expect("test length fits u32");
    let mut data: Vec<u8> = Vec::with_capacity(4 + PATH_ENCODED_LEN + chunk.len());
    data.extend_from_slice(&total.to_be_bytes());
    data.extend_from_slice(&provisional_path(7));
    data.extend_from_slice(chunk);
    data
}

fn dispatch_complete_frame(
    frame: &[u8],
    deriver: &mut impl PublicKeyDeriver,
) -> (SigningSession, DispatchOutcome) {
    assert!(frame.len() > MAX_CHUNK_LEN * 2);
    let mut session: SigningSession = SigningSession::new();
    let first: Vec<u8> = begin_data(frame.len(), &frame[..MAX_CHUNK_LEN]);
    let first_outcome: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
        deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&first_outcome), StatusWord::Success);

    let mut offset: usize = MAX_CHUNK_LEN;
    while frame.len() - offset > MAX_CHUNK_LEN {
        let next: usize = offset + MAX_CHUNK_LEN;
        let outcome: DispatchOutcome = dispatch(
            &mut session,
            command(
                ins::SIGN_TRANSACTION,
                sign_p1::CONTINUE,
                &frame[offset..next],
            ),
            deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        );
        assert_eq!(reply_status(&outcome), StatusWord::Success);
        offset = next;
    }
    let outcome: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::LAST, &frame[offset..]),
        deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    (session, outcome)
}

fn replace_first(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let offset: usize = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("test fixture contains mutation target");
    bytes[offset..offset + needle.len()].copy_from_slice(replacement);
}

#[test]
fn stable_source_fixture_decodes_to_the_exact_review() {
    let bytes: Vec<u8> = fixture();
    let frame = decode_signature_frame(&bytes).expect("stable outer frame");
    let transaction = decode_transaction_signable(frame.payload).expect("stable transaction");
    let review = build_review(&frame, &transaction, &DEVNET_ASSET_TRANSFER_POLICY)
        .expect("recognized transfer review");

    assert_eq!(frame.chain_id.as_str(), "sunrise-local-devnet");
    assert_eq!(frame.protocol_version, 3);
    assert_eq!(frame.epoch, 0);
    assert_eq!(frame.message_type.as_str(), "transaction-v1");
    assert_eq!(transaction.sender.as_bytes(), &[1_u8; 32]);
    assert_eq!(review.amount, 1_000_000);
    assert_eq!(review.amount_label, "amount");
    assert_eq!(review.gas_limit, 1_000);
    assert_eq!(review.access_entries.len(), 3);
    assert_eq!(review.fee.expect("fixture has fee").max_fee, 1_001);

    // All 32 pinned display facts, in order, cross-checked against the
    // source workspace's own fixture lines (see `RECOGNIZED_TRANSFER_LINES`
    // above): scheme, nonce, module id/version/digest, entrypoint, amount
    // label/value, gas, manifest count, all three access mode/object/
    // version/digest groups in order, and every fee field.
    let rendered: Vec<String> = render_review_lines(&review);
    let rendered_refs: Vec<&str> = rendered.iter().map(String::as_str).collect();
    assert_eq!(rendered_refs, RECOGNIZED_TRANSFER_LINES);
}

#[test]
fn full_apdu_sequence_preserves_exact_frame_until_review_finishes() {
    let bytes: Vec<u8> = fixture();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let (mut session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    let DispatchOutcome::ReviewTransaction(review) = outcome else {
        panic!("valid LAST must request transaction review");
    };
    assert_eq!(review.amount, 1_000_000);
    assert_eq!(session.pending_frame(), Some(bytes.as_slice()));
    assert_eq!(session.path().expect("pending path").account(), 7);
    assert_eq!(deriver.last_path.expect("deriver was called").account(), 7);

    session.finish_review();
    assert!(session.is_idle());
    assert_eq!(session.pending_frame(), None);
    assert_eq!(session.path(), None);
}

#[test]
fn last_chunk_derives_from_the_exact_first_chunk_path() {
    let bytes: Vec<u8> = fixture();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let (_, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    assert!(matches!(outcome, DispatchOutcome::ReviewTransaction(_)));
    // `begin_data` always encodes account 7 (see `provisional_path(7)`);
    // this proves LAST derived from that exact captured path, not from an
    // arbitrary value the test happened to also pass as the "sender".
    assert_eq!(deriver.calls, 1);
    assert_eq!(deriver.last_path.expect("deriver was called").account(), 7);
}

#[test]
fn last_chunk_derivation_failure_fails_closed_and_wipes() {
    let bytes: Vec<u8> = fixture();
    let mut deriver: FailingDeriver = FailingDeriver::new();
    let (session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    assert_eq!(deriver.calls, 1);
    assert_eq!(reply_status(&outcome), StatusWord::InternalFailure);
    assert!(session.is_idle());
    assert_eq!(session.pending_frame(), None);
    assert_eq!(session.path(), None);
}

#[test]
fn sender_mismatch_rejects_before_a_review_outcome_and_wipes() {
    let bytes: Vec<u8> = fixture();
    let mut deriver: FixedDeriver = FixedDeriver::new([2_u8; 32]);
    let (session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    assert_eq!(reply_status(&outcome), StatusWord::InvalidData);
    assert!(session.is_idle());
    assert_eq!(session.pending_frame(), None);
    assert_eq!(session.path(), None);
}

#[test]
fn duplicate_object_id_is_rejected_by_the_independent_decoder() {
    let mut bytes: Vec<u8> = fixture();
    replace_first(&mut bytes, &[0x21_u8; 32], &[0x11_u8; 32]);
    let frame = decode_signature_frame(&bytes).expect("outer frame remains canonical");
    let error = decode_transaction_signable(frame.payload).expect_err("duplicate must fail");
    assert!(matches!(error, TransactionError::DuplicateObjectId(_)));
}

#[test]
fn wrong_module_digest_is_a_typed_policy_rejection() {
    let mut bytes: Vec<u8> = fixture();
    let digest: [u8; 32] = [
        0x01, 0x53, 0x41, 0x28, 0xF1, 0x2E, 0xB4, 0xCF, 0x46, 0x9B, 0xFA, 0x29, 0x67, 0x7B, 0xBC,
        0xED, 0x13, 0x44, 0x87, 0x9D, 0xE2, 0x87, 0x03, 0x15, 0x84, 0x7C, 0xBB, 0x7F, 0xAE, 0xC2,
        0x16, 0x19,
    ];
    let mut changed: [u8; 32] = digest;
    changed[31] ^= 1;
    replace_first(&mut bytes, &digest, &changed);
    let frame = decode_signature_frame(&bytes).expect("outer frame remains canonical");
    let transaction =
        decode_transaction_signable(frame.payload).expect("transaction remains valid");
    let error = build_review(&frame, &transaction, &DEVNET_ASSET_TRANSFER_POLICY)
        .expect_err("wrong digest must fail policy");
    assert_eq!(error, ReviewError::Policy(PolicyError::ModuleDigest));
}

#[test]
fn configuration_and_public_key_commands_do_not_claim_ui_completion() {
    let mut session: SigningSession = SigningSession::new();
    let mut deriver: FixedDeriver = FixedDeriver::new([9_u8; 32]);
    let configuration: DispatchOutcome = dispatch(
        &mut session,
        command(ins::GET_CONFIGURATION, 0, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        configuration,
        DispatchOutcome::Reply(ApduReply {
            status: StatusWord::Success,
            response: ImmediateResponse::Configuration([0, 1, 0, 1, 0, 0]),
        })
    );

    let path: [u8; PATH_ENCODED_LEN] = provisional_path(3);
    let public_key: DispatchOutcome = dispatch(
        &mut session,
        command(ins::VERIFY_PUBLIC_KEY, 1, &path),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert!(matches!(
        public_key,
        DispatchOutcome::ReviewPublicKey {
            path: validated,
            public_key: reviewed_key,
        } if validated.account() == 3 && reviewed_key == [9_u8; 32]
    ));
    assert_eq!(deriver.last_path.expect("deriver was called").account(), 3);

    let invalid_configuration: DispatchOutcome = dispatch(
        &mut session,
        command(ins::GET_CONFIGURATION, 0, &[0]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        reply_status(&invalid_configuration),
        StatusWord::InvalidData
    );

    let invalid_reset: DispatchOutcome = dispatch(
        &mut session,
        command(ins::RESET_SIGNING, 0, &[0]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&invalid_reset), StatusWord::InvalidData);
}

#[test]
fn first_command_size_and_total_bounds_fail_closed() {
    let mut session: SigningSession = SigningSession::new();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let exact: Vec<u8> = begin_data(231, &[7_u8; MAX_CHUNK_LEN]);
    assert_eq!(exact.len(), 255);
    let accepted: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &exact),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&accepted), StatusWord::Success);

    let wrong_cla: DispatchOutcome = dispatch(
        &mut session,
        ApduCommand {
            cla: 0xE1,
            ins: ins::GET_CONFIGURATION,
            p1: 0,
            p2: 0,
            data: &[],
        },
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&wrong_cla), StatusWord::UnsupportedCla);
    assert!(session.is_idle());

    let too_large_first: Vec<u8> = begin_data(231, &[7_u8; MAX_CHUNK_LEN + 1]);
    assert_eq!(too_large_first.len(), 256);
    let rejected: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &too_large_first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&rejected), StatusWord::ProfileBoundExceeded);
    assert!(session.is_idle());

    let above_profile: Vec<u8> = begin_data(4097, &[1_u8]);
    let rejected_total: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &above_profile),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        reply_status(&rejected_total),
        StatusWord::ProfileBoundExceeded
    );
    assert!(session.is_idle());

    let exceeds_declared: Vec<u8> = begin_data(229, &[7_u8; MAX_CHUNK_LEN]);
    let rejected_chunk: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &exceeds_declared),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        reply_status(&rejected_chunk),
        StatusWord::ProfileBoundExceeded
    );
    assert!(session.is_idle());
}

#[test]
fn path_and_canonical_mutations_fail_closed() {
    let mut path: [u8; PATH_ENCODED_LEN] = provisional_path(0);
    path[9] &= 0x7F;
    assert!(decode_path(&path).is_err());

    let mut invalid_magic: Vec<u8> = fixture();
    invalid_magic[0] ^= 1;
    assert!(decode_signature_frame(&invalid_magic).is_err());

    let mut trailing: Vec<u8> = fixture();
    trailing.push(0);
    assert!(decode_signature_frame(&trailing).is_err());

    let duplicate_fields: [u8; 22] = [
        b'S', b'N', b'R', b'E', 1, 0, 1, 0, 2, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    ];
    assert_eq!(
        decode_canonical_frame(&duplicate_fields),
        Err(CanonicalError::NonCanonicalFieldOrder)
    );
}

#[test]
fn premature_last_and_any_failed_command_wipe_collection() {
    let mut session: SigningSession = SigningSession::new();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let first: Vec<u8> = begin_data(2, &[1_u8]);
    let accepted: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&accepted), StatusWord::Success);

    let premature: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::LAST, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&premature), StatusWord::InvalidData);
    assert!(session.is_idle());

    let restarted: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&restarted), StatusWord::Success);
    let unsupported: DispatchOutcome = dispatch(
        &mut session,
        command(0xFF, 0, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&unsupported), StatusWord::UnsupportedIns);
    assert!(session.is_idle());
}

fn decode_review_error(frame_fields: &FrameFields) -> ReviewError {
    let bytes: Vec<u8> = frame_fields.build();
    let frame = decode_signature_frame(&bytes).expect("synthetic outer frame must decode");
    let transaction =
        decode_transaction_signable(frame.payload).expect("synthetic transaction must decode");
    build_review(&frame, &transaction, &DEVNET_ASSET_TRANSFER_POLICY)
        .expect_err("mutated transaction must not be reviewable")
}

#[allow(clippy::needless_pass_by_value)]
fn assert_policy_error(tx: TxFields, expected: PolicyError) {
    let bytes: Vec<u8> = tx.build();
    let transaction =
        decode_transaction_signable(&bytes).expect("synthetic transaction must decode");
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&transaction),
        Err(expected)
    );
}

#[test]
fn transaction_rejects_signature_field_and_enforces_scalar_bounds() {
    let recognized: TxFields = TxFields::recognized();
    let with_signature: Vec<u8> = recognized.build_with_extra(Some((12, vec![0_u8; 64])));
    assert_eq!(
        decode_transaction_signable(&with_signature),
        Err(TransactionError::Canonical(
            CanonicalError::UnexpectedField(12)
        ))
    );

    let mut exact_chain: TxFields = recognized.clone();
    exact_chain.chain_id = "c".repeat(64);
    assert!(decode_transaction_signable(&exact_chain.build()).is_ok());
    exact_chain.chain_id.push('c');
    assert!(matches!(
        decode_transaction_signable(&exact_chain.build()),
        Err(TransactionError::ChainId(_))
    ));

    let mut exact_entrypoint: TxFields = recognized.clone();
    exact_entrypoint.entrypoint = "e".repeat(64);
    assert!(decode_transaction_signable(&exact_entrypoint.build()).is_ok());
    exact_entrypoint.entrypoint.push('e');
    assert!(matches!(
        decode_transaction_signable(&exact_entrypoint.build()),
        Err(TransactionError::Entrypoint(_))
    ));

    let mut exact_args: TxFields = recognized.clone();
    exact_args.args = vec![0_u8; 40];
    assert!(decode_transaction_signable(&exact_args.build()).is_ok());
    exact_args.args.push(0);
    assert!(matches!(
        decode_transaction_signable(&exact_args.build()),
        Err(TransactionError::Args(_))
    ));
}

#[test]
fn frame_enforces_text_scheme_and_payload_bounds() {
    let recognized: TxFields = TxFields::recognized();
    let mut fields: FrameFields = FrameFields::wrapping(recognized.build());

    fields.chain_id = "c".repeat(64);
    assert!(decode_signature_frame(&fields.build()).is_ok());
    fields.chain_id.push('c');
    assert!(matches!(
        decode_signature_frame(&fields.build()),
        Err(FrameError::ChainId(_))
    ));

    fields = FrameFields::wrapping(TxFields::recognized().build());
    fields.message_type = "m".repeat(32);
    assert!(decode_signature_frame(&fields.build()).is_ok());
    fields.message_type.push('m');
    assert!(matches!(
        decode_signature_frame(&fields.build()),
        Err(FrameError::MessageType(_))
    ));

    fields = FrameFields::wrapping(vec![0_u8; MAX_TRANSACTION_PAYLOAD_LEN]);
    let exact_payload: Vec<u8> = fields.build();
    assert_eq!(
        decode_signature_frame(&exact_payload)
            .expect("3072-byte payload is an outer-frame boundary success")
            .payload
            .len(),
        MAX_TRANSACTION_PAYLOAD_LEN
    );
    fields.payload.push(0);
    let oversized_payload: Vec<u8> = fields.build();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let (session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&oversized_payload, &mut deriver);
    assert_eq!(reply_status(&outcome), StatusWord::ProfileBoundExceeded);
    assert!(session.is_idle());

    fields = FrameFields::wrapping(TxFields::recognized().build());
    fields.scheme = 0xFFFF;
    assert_eq!(
        decode_signature_frame(&fields.build()),
        Err(FrameError::UnknownSignatureScheme(0xFFFF))
    );
}

#[test]
fn access_manifest_enforces_exact_eight_entry_decode_bound() {
    let mut tx: TxFields = TxFields::recognized();
    tx.access_entries.clear();
    for index in 0_u8..8_u8 {
        let object_ref: Vec<u8> = object_ref_bytes(
            [index.saturating_add(1); 32],
            u64::from(index),
            POLICY_MODULE_DIGEST_ALGORITHM,
            [index.saturating_add(17); 32],
        );
        tx.access_entries.push(access_entry_bytes(object_ref, 2));
    }
    assert_eq!(
        decode_transaction_signable(&tx.build())
            .expect("eight access entries are allowed")
            .access_manifest
            .len(),
        8
    );

    let ninth_ref: Vec<u8> =
        object_ref_bytes([9_u8; 32], 9, POLICY_MODULE_DIGEST_ALGORITHM, [25_u8; 32]);
    tx.access_entries.push(access_entry_bytes(ninth_ref, 2));
    assert_eq!(
        decode_transaction_signable(&tx.build()),
        Err(TransactionError::AccessManifestShape)
    );
}

#[test]
fn review_rejects_unsupported_profile_and_each_context_mismatch() {
    let recognized: TxFields = TxFields::recognized();

    let mut frame_fields: FrameFields = FrameFields::wrapping(recognized.build());
    frame_fields.message_type = "transaction-v2".to_string();
    assert_eq!(
        decode_review_error(&frame_fields),
        ReviewError::UnsupportedMessageType
    );

    frame_fields = FrameFields::wrapping(TxFields::recognized().build());
    frame_fields.scheme = 2;
    assert_eq!(
        decode_review_error(&frame_fields),
        ReviewError::UnsupportedSignatureScheme
    );

    frame_fields = FrameFields::wrapping(TxFields::recognized().build());
    frame_fields.chain_id = "another-chain".to_string();
    assert_eq!(
        decode_review_error(&frame_fields),
        ReviewError::SignedContextMismatch
    );
    frame_fields = FrameFields::wrapping(TxFields::recognized().build());
    frame_fields.protocol_version = POLICY_PROTOCOL_VERSION + 1;
    assert_eq!(
        decode_review_error(&frame_fields),
        ReviewError::SignedContextMismatch
    );
    frame_fields = FrameFields::wrapping(TxFields::recognized().build());
    frame_fields.epoch = POLICY_EPOCH + 1;
    assert_eq!(
        decode_review_error(&frame_fields),
        ReviewError::SignedContextMismatch
    );
}

#[test]
fn policy_rejects_every_module_and_argument_deviation() {
    let mut tx: TxFields = TxFields::recognized();
    tx.chain_id = "another-chain".to_string();
    assert_policy_error(tx, PolicyError::ChainId);

    tx = TxFields::recognized();
    tx.protocol_version += 1;
    assert_policy_error(tx, PolicyError::ProtocolVersion);
    tx = TxFields::recognized();
    tx.epoch += 1;
    assert_policy_error(tx, PolicyError::Epoch);

    tx = TxFields::recognized();
    tx.module_ref = object_ref_bytes(
        [0xEE_u8; 32],
        POLICY_MODULE_VERSION,
        POLICY_MODULE_DIGEST_ALGORITHM,
        POLICY_MODULE_DIGEST,
    );
    assert_policy_error(tx, PolicyError::ModuleId);
    tx = TxFields::recognized();
    tx.module_ref = object_ref_bytes(
        POLICY_MODULE_ID,
        POLICY_MODULE_VERSION + 1,
        POLICY_MODULE_DIGEST_ALGORITHM,
        POLICY_MODULE_DIGEST,
    );
    assert_policy_error(tx, PolicyError::ModuleVersion);
    tx = TxFields::recognized();
    tx.module_ref = object_ref_bytes(
        POLICY_MODULE_ID,
        POLICY_MODULE_VERSION,
        2,
        POLICY_MODULE_DIGEST,
    );
    assert_policy_error(tx, PolicyError::ModuleDigestAlgorithm);
    tx = TxFields::recognized();
    tx.module_ref = object_ref_bytes(
        POLICY_MODULE_ID,
        POLICY_MODULE_VERSION,
        POLICY_MODULE_DIGEST_ALGORITHM,
        [0xEE_u8; 32],
    );
    assert_policy_error(tx, PolicyError::ModuleDigest);
    tx = TxFields::recognized();
    tx.entrypoint = "mint".to_string();
    assert_policy_error(tx, PolicyError::Entrypoint);

    tx = TxFields::recognized();
    tx.args = amount_args_bytes(0xF003, POLICY_ARGS_VERSION, POLICY_ARGS_FIELD_ID, 1);
    assert_policy_error(tx, PolicyError::ArgumentsTypeId(0xF003));
    tx = TxFields::recognized();
    tx.args = amount_args_bytes(POLICY_ARGS_TYPE_ID, 2, POLICY_ARGS_FIELD_ID, 1);
    assert_policy_error(tx, PolicyError::ArgumentsVersion(2));
    tx = TxFields::recognized();
    tx.args = amount_args_bytes(POLICY_ARGS_TYPE_ID, POLICY_ARGS_VERSION, 2, 1);
    assert_policy_error(tx, PolicyError::ArgumentsShape);
    tx = TxFields::recognized();
    tx.args = vec![0_u8; 1];
    assert_policy_error(tx, PolicyError::ArgumentsEncoding);
    tx = TxFields::recognized();
    tx.args = amount_args_bytes(
        POLICY_ARGS_TYPE_ID,
        POLICY_ARGS_VERSION,
        POLICY_ARGS_FIELD_ID,
        0,
    );
    assert_policy_error(tx, PolicyError::ZeroAmount);
}

#[test]
fn policy_rejects_every_access_and_fee_deviation() {
    let mut tx: TxFields = TxFields::recognized();
    tx.access_entries.pop();
    assert_policy_error(tx, PolicyError::AccessShape);

    tx = TxFields::recognized();
    let source_ref: Vec<u8> = object_ref_bytes(
        [0x11_u8; 32],
        1,
        POLICY_MODULE_DIGEST_ALGORITHM,
        [0x12_u8; 32],
    );
    tx.access_entries[0] = access_entry_bytes(source_ref.clone(), 1);
    assert_policy_error(tx, PolicyError::AccessShape);

    tx = TxFields::recognized();
    tx.fee_payment = None;
    assert_policy_error(tx, PolicyError::FeeRequired);
    tx = TxFields::recognized();
    let wrong_ref: Vec<u8> = object_ref_bytes(
        [0x41_u8; 32],
        4,
        POLICY_MODULE_DIGEST_ALGORITHM,
        [0x42_u8; 32],
    );
    tx.fee_payment = Some(fee_payment_bytes(POLICY_FEE_ASSET_ID, 1_001, wrong_ref));
    assert_policy_error(tx, PolicyError::FeeObjectMismatch);
    tx = TxFields::recognized();
    tx.fee_payment = Some(fee_payment_bytes([0xEE_u8; 32], 1_001, source_ref));
    assert_policy_error(tx, PolicyError::FeeAsset);
}

#[test]
fn apdu_rejects_invalid_parameters_and_illegal_state_transitions() {
    let mut session: SigningSession = SigningSession::new();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let path: [u8; PATH_ENCODED_LEN] = provisional_path(0);

    for (ins_byte, p1, p2, data) in [
        (ins::GET_CONFIGURATION, 1_u8, 0_u8, [].as_slice()),
        (ins::GET_CONFIGURATION, 0_u8, 1_u8, [].as_slice()),
        (ins::VERIFY_PUBLIC_KEY, 0_u8, 0_u8, path.as_slice()),
        (ins::VERIFY_PUBLIC_KEY, 1_u8, 1_u8, path.as_slice()),
        (ins::RESET_SIGNING, 1_u8, 0_u8, [].as_slice()),
        (ins::SIGN_TRANSACTION, sign_p1::FIRST, 1_u8, path.as_slice()),
        (ins::SIGN_TRANSACTION, 0xFF, 0_u8, path.as_slice()),
    ] {
        let outcome: DispatchOutcome = dispatch(
            &mut session,
            ApduCommand {
                cla: 0xE0,
                ins: ins_byte,
                p1,
                p2,
                data,
            },
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        );
        assert_eq!(reply_status(&outcome), StatusWord::InvalidP1P2);
        assert!(session.is_idle());
    }

    for p1 in [sign_p1::CONTINUE, sign_p1::LAST] {
        let outcome: DispatchOutcome = dispatch(
            &mut session,
            command(ins::SIGN_TRANSACTION, p1, &[1]),
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        );
        assert_eq!(reply_status(&outcome), StatusWord::InvalidState);
        assert!(session.is_idle());
    }

    let first: Vec<u8> = begin_data(3, &[1]);
    let accepted: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&accepted), StatusWord::Success);
    let second_first: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&second_first), StatusWord::InvalidState);
    assert!(session.is_idle());
}

#[test]
fn apdu_chunk_bounds_reset_and_implied_last_rule_wipe_state() {
    let mut session: SigningSession = SigningSession::new();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);

    let zero_total: Vec<u8> = begin_data(0, &[1]);
    let outcome: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &zero_total),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&outcome), StatusWord::ProfileBoundExceeded);

    let exact_on_first: Vec<u8> = begin_data(1, &[1]);
    let outcome: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &exact_on_first),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&outcome), StatusWord::InvalidData);

    let first: Vec<u8> = begin_data(232, &[1_u8; MAX_CHUNK_LEN]);
    assert_eq!(
        reply_status(&dispatch(
            &mut session,
            command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )),
        StatusWord::Success
    );
    let empty_continue: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::CONTINUE, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&empty_continue), StatusWord::InvalidData);
    assert!(session.is_idle());

    assert_eq!(
        reply_status(&dispatch(
            &mut session,
            command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )),
        StatusWord::Success
    );
    let oversized_continue: DispatchOutcome = dispatch(
        &mut session,
        command(
            ins::SIGN_TRANSACTION,
            sign_p1::CONTINUE,
            &[2_u8; MAX_CHUNK_LEN + 1],
        ),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        reply_status(&oversized_continue),
        StatusWord::ProfileBoundExceeded
    );
    assert!(session.is_idle());

    assert_eq!(
        reply_status(&dispatch(
            &mut session,
            command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )),
        StatusWord::Success
    );
    let completes_on_continue: DispatchOutcome = dispatch(
        &mut session,
        command(ins::SIGN_TRANSACTION, sign_p1::CONTINUE, &[2_u8; 2]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(
        reply_status(&completes_on_continue),
        StatusWord::InvalidData
    );
    assert!(session.is_idle());

    assert_eq!(
        reply_status(&dispatch(
            &mut session,
            command(ins::SIGN_TRANSACTION, sign_p1::FIRST, &first),
            &mut deriver,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )),
        StatusWord::Success
    );
    let reset: DispatchOutcome = dispatch(
        &mut session,
        command(ins::RESET_SIGNING, 0, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&reset), StatusWord::Success);
    assert!(session.is_idle());
}

#[test]
fn apdu_accepts_exact_complete_frame_bound_before_strict_decode() {
    let bytes: Vec<u8> = vec![0_u8; 4096];
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let (session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    assert_eq!(reply_status(&outcome), StatusWord::InvalidData);
    assert!(session.is_idle());
    assert_eq!(deriver.calls, 0);
}

#[test]
fn derivation_path_rejects_every_non_profile_shape() {
    let valid: [u8; PATH_ENCODED_LEN] = provisional_path(7);
    assert_eq!(
        decode_path(&valid)
            .expect("profile path must decode")
            .account(),
        7
    );
    assert_eq!(
        decode_path(&valid[..PATH_ENCODED_LEN - 1]),
        Err(PathError::WrongLength {
            actual: PATH_ENCODED_LEN - 1,
        })
    );

    let mut changed: [u8; PATH_ENCODED_LEN] = valid;
    changed[0] = 4;
    assert_eq!(
        decode_path(&changed),
        Err(PathError::WrongDepth { actual: 4 })
    );

    changed = valid;
    changed[1] &= 0x7F;
    assert_eq!(
        decode_path(&changed),
        Err(PathError::NotHardened { index: 0 })
    );

    changed = valid;
    changed[1..5].copy_from_slice(&(0x8000_0000_u32 + 45).to_be_bytes());
    assert_eq!(decode_path(&changed), Err(PathError::WrongPurpose));
    changed = valid;
    changed[5..9].copy_from_slice(&(0x8000_0000_u32 + 21_334).to_be_bytes());
    assert_eq!(decode_path(&changed), Err(PathError::WrongCoinType));
    changed = valid;
    changed[13..17].copy_from_slice(&(0x8000_0000_u32 + 1).to_be_bytes());
    assert_eq!(decode_path(&changed), Err(PathError::WrongChange));
    changed = valid;
    changed[17..21].copy_from_slice(&(0x8000_0000_u32 + 1).to_be_bytes());
    assert_eq!(decode_path(&changed), Err(PathError::WrongAddressIndex));
}

#[test]
fn stray_apdu_while_awaiting_approval_fails_closed_and_wipes() {
    let bytes: Vec<u8> = fixture();
    let mut deriver: FixedDeriver = FixedDeriver::new([1_u8; 32]);
    let (mut session, outcome): (SigningSession, DispatchOutcome) =
        dispatch_complete_frame(&bytes, &mut deriver);
    assert!(matches!(outcome, DispatchOutcome::ReviewTransaction(_)));
    assert_eq!(session.pending_frame(), Some(bytes.as_slice()));

    let stray: DispatchOutcome = dispatch(
        &mut session,
        command(ins::GET_CONFIGURATION, 0, &[]),
        &mut deriver,
        &DEVNET_ASSET_TRANSFER_POLICY,
    );
    assert_eq!(reply_status(&stray), StatusWord::InvalidState);
    assert!(session.is_idle());
    assert_eq!(session.pending_frame(), None);
    assert_eq!(session.path(), None);
}
