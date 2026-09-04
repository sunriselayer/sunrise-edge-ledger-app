#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Conformance tests for the 32 clear-signing review facts.

use hex::decode;
use sunrise_edge_ledger_app::review_ui::{
    format_review_facts, BoundedFactStr, ReviewFormatError, MAX_FACT_LEN,
};
use sunrise_edge_ledger_core::frame::decode_signature_frame;
use sunrise_edge_ledger_core::policy::DEVNET_ASSET_TRANSFER_POLICY;
use sunrise_edge_ledger_core::review::build_review;
use sunrise_edge_ledger_core::transaction::decode_transaction_signable;
use sunrise_edge_ledger_core::types::AccessManifest;

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

const FIXTURE_HEX: &str =
    include_str!("../../../crates/sunrise-edge-ledger-core/tests/fixtures/recognized_transfer.hex");

#[test]
fn format_review_facts_matches_all_32_pinned_facts() {
    let raw = decode(FIXTURE_HEX.trim()).expect("valid fixture hex");
    let frame = decode_signature_frame(&raw).expect("valid frame");
    let tx = decode_transaction_signable(frame.payload).expect("valid tx");
    let review = build_review(&frame, &tx, &DEVNET_ASSET_TRANSFER_POLICY).expect("valid review");

    let facts = format_review_facts(&review).expect("recognized review formats exactly");
    assert_eq!(facts.len(), 32);

    for (i, fact) in facts.iter().enumerate() {
        assert!(
            fact.value.as_str().expect("fact is ASCII").len() <= MAX_FACT_LEN,
            "fact {} exceeds max length: {}",
            fact.name,
            fact.value.as_str().expect("fact is ASCII").len()
        );
        let line = format!(
            "{}={}",
            fact.name,
            fact.value.as_str().expect("fact is ASCII")
        );
        assert_eq!(line, RECOGNIZED_TRANSFER_LINES[i], "mismatch at index {i}");
    }
}

#[test]
fn formatter_rejects_missing_fee_and_wrong_access_count() {
    let raw = decode(FIXTURE_HEX.trim()).expect("valid fixture hex");
    let frame = decode_signature_frame(&raw).expect("valid frame");
    let tx = decode_transaction_signable(frame.payload).expect("valid tx");
    let review = build_review(&frame, &tx, &DEVNET_ASSET_TRANSFER_POLICY).expect("valid review");

    let mut missing_fee = review;
    missing_fee.fee = None;
    assert_eq!(
        format_review_facts(&missing_fee),
        Err(ReviewFormatError::MissingFee)
    );

    let mut wrong_access_count = review;
    wrong_access_count.access_entries = AccessManifest::default();
    assert_eq!(
        format_review_facts(&wrong_access_count),
        Err(ReviewFormatError::WrongAccessCount)
    );
}

#[test]
fn bounded_fact_strings_reject_instead_of_truncating() {
    let overlong = "x".repeat(MAX_FACT_LEN + 1);
    assert_eq!(
        BoundedFactStr::try_from_str(&overlong),
        Err(ReviewFormatError::ValueTooLong)
    );
    assert_eq!(
        BoundedFactStr::try_from_str("sunrise-☃"),
        Err(ReviewFormatError::NonAscii)
    );
    assert_eq!(
        BoundedFactStr::try_from_hex(&[0_u8; MAX_FACT_LEN / 2 + 1]),
        Err(ReviewFormatError::ValueTooLong)
    );
}
