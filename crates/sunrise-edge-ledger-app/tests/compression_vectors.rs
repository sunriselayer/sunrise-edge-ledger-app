#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Deterministic host test vectors for exactly-once RFC 8032 Ed25519 public key compression.

use hex::decode;
use sunrise_edge_ledger_app::compression::{compress_ed25519_point, CompressionError};

fn decode_65(hex_str: &str) -> [u8; 65] {
    let bytes = decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), 65);
    let mut out = [0u8; 65];
    out.copy_from_slice(&bytes);
    out
}

fn decode_32(hex_str: &str) -> [u8; 32] {
    let bytes = decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn basepoint_compression_matches_rfc8032() {
    // Basepoint B:
    // X = 216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a (even, sign bit 0)
    // Y = 6666666666666666666666666666666666666666666666666666666666666658
    let raw = decode_65(
        "04216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a\
         6666666666666666666666666666666666666666666666666666666666666658",
    );
    let expected = decode_32("5866666666666666666666666666666666666666666666666666666666666666");
    let result = compress_ed25519_point(&raw).expect("valid basepoint compression");
    assert_eq!(result, expected);
}

#[test]
fn negated_basepoint_sets_compressed_sign_bit() {
    // Negated Basepoint -B:
    // X = 5e96c92c3291ac013f5b1dce022923a396d3389f6ada584d36a9d29f70da2ad3 (odd, sign bit 1)
    // Y = 6666666666666666666666666666666666666666666666666666666666666658
    // Compressed Y has most-significant byte 0x66 | 0x80 = 0xE6
    let raw = decode_65(
        "045e96c92c3291ac013f5b1dce022923a396d3389f6ada584d36a9d29f70da2ad3\
         6666666666666666666666666666666666666666666666666666666666666658",
    );
    let expected = decode_32("58666666666666666666666666666666666666666666666666666666666666e6");
    let result = compress_ed25519_point(&raw).expect("valid negated basepoint compression");
    assert_eq!(result, expected);
}

#[test]
fn rfc8032_vector_1_compression_matches() {
    // RFC 8032 Section 7.1 Test Vector 1:
    // X = 55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce (even, sign 0)
    // Y = 1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7
    let raw = decode_65(
        "0455d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce\
         1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7",
    );
    let expected = decode_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let result = compress_ed25519_point(&raw).expect("vector 1 compression");
    assert_eq!(result, expected);
}

#[test]
fn rfc8032_vector_2_compression_matches() {
    // RFC 8032 Section 7.1 Test Vector 2:
    // X = 74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae (even, sign 0)
    // Y = 0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d
    let raw = decode_65(
        "0474ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae\
         0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d",
    );
    let expected = decode_32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let result = compress_ed25519_point(&raw).expect("vector 2 compression");
    assert_eq!(result, expected);
}

#[test]
fn rfc8032_vector_3_compression_matches() {
    // RFC 8032 Section 7.1 Test Vector 3:
    // X = 61213aa2dc9d68833f65d1b48dcf859818236f1734e3e9b945a9ff5486cdbd02 (even, sign 0)
    // Y = 258090481591eb5dac0333ba13ed160858f03002d07ea48da3a118628ecd51fc
    let raw = decode_65(
        "0461213aa2dc9d68833f65d1b48dcf859818236f1734e3e9b945a9ff5486cdbd02\
         258090481591eb5dac0333ba13ed160858f03002d07ea48da3a118628ecd51fc",
    );
    let expected = decode_32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let result = compress_ed25519_point(&raw).expect("vector 3 compression");
    assert_eq!(result, expected);
}

#[test]
fn invalid_point_header_fails_closed() {
    let mut raw = decode_65(
        "04216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a\
         6666666666666666666666666666666666666666666666666666666666666658",
    );
    for bad_header in [0x00, 0x01, 0x02, 0x03, 0x05, 0xFF] {
        raw[0] = bad_header;
        assert_eq!(
            compress_ed25519_point(&raw),
            Err(CompressionError::InvalidPointHeader(bad_header))
        );
    }
}

#[test]
fn field_overflow_fails_closed() {
    // Y coordinate equal to or exceeding 2^255 - 19 is an invalid field element.
    let mut raw = [0u8; 65];
    raw[0] = 0x04;
    // Set Y in big-endian to 2^255 - 19 = [0x7f, 0xff, ..., 0xff, 0xed]
    raw[33] = 0x7F;
    raw[34..64].fill(0xFF);
    raw[64] = 0xED;
    assert_eq!(
        compress_ed25519_point(&raw),
        Err(CompressionError::FieldOverflow)
    );

    // High bit set in Y big-endian (e.g. 0x80 in most-significant byte raw[33])
    raw[33] = 0x80;
    assert_eq!(
        compress_ed25519_point(&raw),
        Err(CompressionError::FieldOverflow)
    );
}
