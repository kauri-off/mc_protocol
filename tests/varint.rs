//! Tests for VarInt encoding and decoding.
//!
//! Reference values taken directly from the Minecraft Java Edition protocol
//! data types documentation.

use minecraft_protocol::ser::{Deserialize, Serialize};
use minecraft_protocol::varint::VarInt;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helper: round-trip a VarInt through encode -> decode
// ---------------------------------------------------------------------------
fn round_trip(value: i32) -> i32 {
    let mut buf = Vec::new();
    VarInt(value).serialize(&mut buf).unwrap();
    VarInt::deserialize(&mut Cursor::new(&buf)).unwrap().0
}

// ---------------------------------------------------------------------------
// Sample values from the protocol spec
// ---------------------------------------------------------------------------

#[test]
fn varint_zero() {
    let mut buf = Vec::new();
    VarInt(0).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
    assert_eq!(round_trip(0), 0);
}

#[test]
fn varint_one() {
    let mut buf = Vec::new();
    VarInt(1).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x01]);
    assert_eq!(round_trip(1), 1);
}

#[test]
fn varint_two() {
    let mut buf = Vec::new();
    VarInt(2).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x02]);
    assert_eq!(round_trip(2), 2);
}

#[test]
fn varint_127() {
    let mut buf = Vec::new();
    VarInt(127).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x7f]);
    assert_eq!(round_trip(127), 127);
}

#[test]
fn varint_128() {
    let mut buf = Vec::new();
    VarInt(128).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x80, 0x01]);
    assert_eq!(round_trip(128), 128);
}

#[test]
fn varint_255() {
    let mut buf = Vec::new();
    VarInt(255).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0x01]);
    assert_eq!(round_trip(255), 255);
}

#[test]
fn varint_25565() {
    let mut buf = Vec::new();
    VarInt(25565).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xdd, 0xc7, 0x01]);
    assert_eq!(round_trip(25565), 25565);
}

#[test]
fn varint_2097151() {
    let mut buf = Vec::new();
    VarInt(2097151).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0x7f]);
    assert_eq!(round_trip(2097151), 2097151);
}

#[test]
fn varint_max_positive() {
    let mut buf = Vec::new();
    VarInt(2147483647).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0xff, 0xff, 0x07]);
    assert_eq!(round_trip(2147483647), 2147483647);
}

#[test]
fn varint_negative_one() {
    let mut buf = Vec::new();
    VarInt(-1).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert_eq!(round_trip(-1), -1);
}

#[test]
fn varint_min_negative() {
    let mut buf = Vec::new();
    VarInt(-2147483648).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x80, 0x80, 0x80, 0x80, 0x08]);
    assert_eq!(round_trip(-2147483648), -2147483648);
}

// ---------------------------------------------------------------------------
// Length checks
// ---------------------------------------------------------------------------

#[test]
fn varint_negative_uses_5_bytes() {
    let mut buf = Vec::new();
    VarInt(-1).serialize(&mut buf).unwrap();
    assert_eq!(buf.len(), 5);
}

#[test]
fn varint_encoded_len() {
    assert_eq!(VarInt(0).encoded_len(), 1);
    assert_eq!(VarInt(127).encoded_len(), 1);
    assert_eq!(VarInt(128).encoded_len(), 2);
    assert_eq!(VarInt(2097151).encoded_len(), 3);
    assert_eq!(VarInt(2147483647).encoded_len(), 5);
    assert_eq!(VarInt(-1).encoded_len(), 5);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn varint_too_long_returns_error() {
    // Six bytes with continuation bits set — should fail on position >= 32
    let data: &[u8] = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    let result = VarInt::deserialize(&mut Cursor::new(data));
    assert!(result.is_err(), "Expected error for too-long VarInt");
}

#[test]
fn varint_eof_returns_error() {
    let data: &[u8] = &[];
    let result = VarInt::deserialize(&mut Cursor::new(data));
    assert!(result.is_err(), "Expected error for empty input");
}

// ---------------------------------------------------------------------------
// Consecutive reads from a stream
// ---------------------------------------------------------------------------

#[test]
fn varint_multiple_reads_from_stream() {
    let mut buf = Vec::new();
    VarInt(1).serialize(&mut buf).unwrap();
    VarInt(300).serialize(&mut buf).unwrap();
    VarInt(-1).serialize(&mut buf).unwrap();

    let mut cursor = Cursor::new(&buf);
    assert_eq!(VarInt::deserialize(&mut cursor).unwrap().0, 1);
    assert_eq!(VarInt::deserialize(&mut cursor).unwrap().0, 300);
    assert_eq!(VarInt::deserialize(&mut cursor).unwrap().0, -1);
}

// ---------------------------------------------------------------------------
// From/Into conversions
// ---------------------------------------------------------------------------

#[test]
fn varint_from_i32() {
    let v: VarInt = VarInt::from(42);
    assert_eq!(v.0, 42);
}

#[test]
fn varint_into_i32() {
    let i: i32 = VarInt(99).into();
    assert_eq!(i, 99);
}

// ---------------------------------------------------------------------------
// Async tests
// ---------------------------------------------------------------------------

#[cfg(feature = "async")]
mod async_tests {
    use minecraft_protocol::varint::VarInt;

    #[tokio::test]
    async fn varint_async_round_trip() {
        let values = [0, 1, 127, 128, 255, 25565, 2097151, 2147483647, -1, -2147483648];
        for &v in &values {
            let mut buf = Vec::new();
            VarInt(v).write_async(&mut buf).await.unwrap();
            let decoded = VarInt::read_async(&mut std::io::Cursor::new(&buf)).await.unwrap();
            assert_eq!(decoded.0, v, "Async round-trip failed for {}", v);
        }
    }
}
