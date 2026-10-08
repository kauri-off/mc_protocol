//! Tests for zlib packet compression.

use mc_protocol::compression::{compress_zlib, compress_zlib_level, decompress_zlib};
use mc_protocol::packet::UncompressedPacket;

// ---------------------------------------------------------------------------
// compress_zlib / decompress_zlib
// ---------------------------------------------------------------------------

#[test]
fn compress_then_decompress_round_trip() {
    let original = b"Hello, Minecraft Protocol!";
    let compressed = compress_zlib(original).unwrap();
    let decompressed = decompress_zlib(&compressed).unwrap();
    assert_eq!(decompressed, original);
}

#[test]
fn compress_empty_input() {
    let compressed = compress_zlib(&[]).unwrap();
    let decompressed = decompress_zlib(&compressed).unwrap();
    assert_eq!(decompressed, &[] as &[u8]);
}

#[test]
fn compressed_data_smaller_for_repetitive_input() {
    let data: Vec<u8> = vec![0xAA; 1000];
    let compressed = compress_zlib(&data).unwrap();
    assert!(
        compressed.len() < data.len(),
        "Compressed size {} should be smaller than original {}",
        compressed.len(),
        data.len()
    );
}

#[test]
fn compress_level_0_no_compression() {
    let data = b"Some test data";
    let no_compress = compress_zlib_level(data, 0).unwrap();
    let default_compress = compress_zlib(data).unwrap();
    // Both should decompress to the same thing
    assert_eq!(decompress_zlib(&no_compress).unwrap(), data);
    assert_eq!(decompress_zlib(&default_compress).unwrap(), data);
}

#[test]
fn decompress_invalid_data_returns_error() {
    let garbage = b"this is not valid zlib data at all xyz";
    let result = decompress_zlib(garbage);
    assert!(result.is_err(), "Expected error for invalid zlib data");
}

// ---------------------------------------------------------------------------
// Packet-level compression
// ---------------------------------------------------------------------------

#[test]
fn packet_below_threshold_not_compressed() {
    let up = UncompressedPacket::new(0x00, vec![0x01, 0x02, 0x03]);
    let threshold = Some(256); // payload is well below 256 bytes

    let raw = up.to_raw_packet_compressed(threshold).unwrap();

    // Decompress and verify we get back the same packet
    let decoded = raw.uncompress(threshold).unwrap();
    assert_eq!(decoded.packet_id, 0x00);
    assert_eq!(decoded.payload, &[0x01, 0x02, 0x03]);
}

#[test]
fn packet_above_threshold_is_compressed() {
    // Build a payload large enough to exceed the threshold
    let payload = vec![0u8; 512];
    let up = UncompressedPacket::new(0x26, payload.clone());
    let threshold = Some(256);

    let raw = up.to_raw_packet_compressed(threshold).unwrap();
    let decoded = raw.uncompress(threshold).unwrap();

    assert_eq!(decoded.packet_id, 0x26);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn packet_no_threshold_no_compression() {
    let up = UncompressedPacket::new(0x10, vec![1, 2, 3, 4, 5]);
    let raw = up.to_raw_packet_compressed(None).unwrap();
    let decoded = raw.uncompress(None).unwrap();

    assert_eq!(decoded.packet_id, 0x10);
    assert_eq!(decoded.payload, &[1, 2, 3, 4, 5]);
}

#[test]
fn uncompress_negative_data_length_is_rejected() {
    use mc_protocol::packet::RawPacket;
    use mc_protocol::ser::Serialize;
    use mc_protocol::varint::VarInt;

    // Frame whose data_length field is negative
    let mut data = Vec::new();
    VarInt(-1).serialize(&mut data).unwrap();
    data.extend_from_slice(&[0x00]);

    let raw = RawPacket::new(data);
    assert!(raw.uncompress(Some(256)).is_err());
}

#[test]
fn uncompress_mismatched_data_length_is_rejected() {
    use mc_protocol::packet::RawPacket;
    use mc_protocol::ser::Serialize;
    use mc_protocol::varint::VarInt;

    // Compress a 512-byte inner packet but declare data_length = 10.
    // The zip-bomb guard must refuse to inflate past the declared size.
    let mut inner = Vec::new();
    VarInt(0x26).serialize(&mut inner).unwrap();
    inner.extend_from_slice(&[0u8; 512]);
    let compressed = compress_zlib(&inner).unwrap();

    let mut data = Vec::new();
    VarInt(10).serialize(&mut data).unwrap();
    data.extend_from_slice(&compressed);

    let raw = RawPacket::new(data);
    assert!(raw.uncompress(Some(256)).is_err());
}

#[test]
fn negative_threshold_disables_compression_framing() {
    let up = UncompressedPacket::new(0x10, vec![0u8; 512]);
    let raw = up.to_raw_packet_compressed(Some(-1)).unwrap();
    assert_eq!(raw.data, up.to_raw_packet().unwrap().data);
    let decoded = raw.uncompress(Some(-1)).unwrap();
    assert_eq!(decoded.payload, up.payload);
}

#[test]
fn packet_inflating_past_frame_limit_round_trips() {
    use mc_protocol::packet::MAX_PACKET_LENGTH;

    let up = UncompressedPacket::new(0x27, vec![0u8; MAX_PACKET_LENGTH * 2]);
    let raw = up.to_raw_packet_compressed(Some(256)).unwrap();
    assert!(raw.data.len() <= MAX_PACKET_LENGTH);
    let decoded = raw.uncompress(Some(256)).unwrap();
    assert_eq!(decoded.payload.len(), up.payload.len());
}

#[test]
fn packet_above_uncompressed_limit_is_rejected() {
    use mc_protocol::packet::{MAX_UNCOMPRESSED_LENGTH, PacketError};

    let up = UncompressedPacket::new(0x27, vec![0u8; MAX_UNCOMPRESSED_LENGTH]);
    let err = up.to_raw_packet_compressed(Some(256)).unwrap_err();
    assert!(matches!(err, PacketError::InvalidLength(_)));
}

#[test]
fn compress_level_out_of_range_is_clamped() {
    let data = b"clamped level test data";
    // Level 99 must behave like level 9 rather than panicking or erroring
    let compressed = compress_zlib_level(data, 99).unwrap();
    assert_eq!(decompress_zlib(&compressed).unwrap(), data);
}

#[test]
fn decompress_zlib_limited_allows_exact_size() {
    use mc_protocol::compression::decompress_zlib_limited;

    let data = b"exactly sized payload";
    let compressed = compress_zlib(data).unwrap();
    let out = decompress_zlib_limited(&compressed, data.len()).unwrap();
    assert_eq!(out, data);
}

#[test]
fn decompress_zlib_limited_rejects_oversize() {
    use mc_protocol::compression::decompress_zlib_limited;

    let data = vec![0xAA; 4096];
    let compressed = compress_zlib(&data).unwrap();
    assert!(decompress_zlib_limited(&compressed, 100).is_err());
}

#[test]
fn large_packet_round_trip_preserves_exact_content() {
    // Simulate a chunk data packet with lots of bytes
    let payload: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
    let up = UncompressedPacket::new(0x25, payload.clone());
    let threshold = Some(256);

    let raw = up.to_raw_packet_compressed(threshold).unwrap();
    let decoded = raw.uncompress(threshold).unwrap();

    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.payload.len(), 2000);
}
