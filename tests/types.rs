//! Tests for primitive and complex type serialization/deserialization.

use mc_protocol::ser::{Deserialize, RawBytes, Serialize};
use std::io::Cursor;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Boolean
// ---------------------------------------------------------------------------

#[test]
fn bool_true_encodes_as_0x01() {
    let mut buf = Vec::new();
    true.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x01]);
}

#[test]
fn bool_false_encodes_as_0x00() {
    let mut buf = Vec::new();
    false.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
}

#[test]
fn bool_round_trip() {
    for &v in &[true, false] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        let decoded = bool::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, v);
    }
}

#[test]
fn bool_nonzero_byte_is_true() {
    let decoded = bool::deserialize(&mut Cursor::new(&[0xFF])).unwrap();
    assert!(decoded);
    let decoded = bool::deserialize(&mut Cursor::new(&[0x7F])).unwrap();
    assert!(decoded);
}

// ---------------------------------------------------------------------------
// Integer primitives (big-endian)
// ---------------------------------------------------------------------------

#[test]
fn u8_round_trip() {
    for v in [0u8, 1, 127, 255] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        assert_eq!(u8::deserialize(&mut Cursor::new(&buf)).unwrap(), v);
    }
}

#[test]
fn u16_is_big_endian() {
    let mut buf = Vec::new();
    (0x1234u16).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x12, 0x34]);
    assert_eq!(u16::deserialize(&mut Cursor::new(&buf)).unwrap(), 0x1234);
}

#[test]
fn i32_round_trip() {
    for v in [0i32, 1, -1, i32::MAX, i32::MIN] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        assert_eq!(i32::deserialize(&mut Cursor::new(&buf)).unwrap(), v);
    }
}

#[test]
fn i64_round_trip() {
    for v in [0i64, 1, -1, i64::MAX, i64::MIN] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        assert_eq!(i64::deserialize(&mut Cursor::new(&buf)).unwrap(), v);
    }
}

#[test]
fn f32_round_trip() {
    for v in [0.0f32, 1.0, -1.0, f32::MAX, f32::MIN_POSITIVE] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        let decoded = f32::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert!((decoded - v).abs() < f32::EPSILON || decoded == v);
    }
}

#[test]
fn f64_round_trip() {
    for v in [0.0f64, 1.0, -1.0, std::f64::consts::PI] {
        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();
        let decoded = f64::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert!((decoded - v).abs() < f64::EPSILON || decoded == v);
    }
}

// ---------------------------------------------------------------------------
// String
// ---------------------------------------------------------------------------

#[test]
fn string_empty() {
    let mut buf = Vec::new();
    "".to_string().serialize(&mut buf).unwrap();
    // VarInt(0) followed by zero bytes
    assert_eq!(buf, &[0x00]);
    let decoded = String::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, "");
}

#[test]
fn string_hello_world() {
    let s = "Hello, World!".to_string();
    let mut buf = Vec::new();
    s.serialize(&mut buf).unwrap();
    let decoded = String::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn string_unicode() {
    let s = "Minecraft is great! Echt super!".to_string();
    let mut buf = Vec::new();
    s.serialize(&mut buf).unwrap();
    let decoded = String::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn string_with_emoji_counts_as_two_utf16_units() {
    // U+1F600 (grinning face) takes 2 UTF-16 code units
    let s = "\u{1F600}".to_string();
    let mut buf = Vec::new();
    // Should serialize fine — 1 character but 2 code units
    s.serialize(&mut buf).unwrap();
    let decoded = String::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn string_over_max_utf16_length_fails_to_serialize() {
    use mc_protocol::ser::{SerializationError, serialize_string_with_max};

    let s = "ab";
    let mut buf = Vec::new();
    let err = serialize_string_with_max(s, &mut buf, 1).unwrap_err();
    assert!(matches!(err, SerializationError::StringTooLong { .. }));
}

#[test]
fn string_negative_length_prefix_is_rejected() {
    use mc_protocol::varint::VarInt;

    // VarInt(-1) as the byte-length prefix
    let mut buf = Vec::new();
    VarInt(-1).serialize(&mut buf).unwrap();
    let result = String::deserialize(&mut Cursor::new(&buf));
    assert!(result.is_err(), "negative string length must be rejected");
}

#[test]
fn string_huge_declared_length_is_rejected_before_allocating() {
    use mc_protocol::varint::VarInt;

    // Declares i32::MAX bytes but provides none. Must fail fast on the
    // length check rather than attempting a 2 GiB allocation.
    let mut buf = Vec::new();
    VarInt(i32::MAX).serialize(&mut buf).unwrap();
    let result = String::deserialize(&mut Cursor::new(&buf));
    assert!(result.is_err(), "oversized string length must be rejected");
}

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

#[test]
fn uuid_round_trip() {
    let id = Uuid::new_v4();
    let mut buf = Vec::new();
    id.serialize(&mut buf).unwrap();
    assert_eq!(buf.len(), 16);
    let decoded = Uuid::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, id);
}

#[test]
fn uuid_nil_round_trip() {
    let id = Uuid::nil();
    let mut buf = Vec::new();
    id.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0u8; 16]);
    let decoded = Uuid::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, id);
}

// ---------------------------------------------------------------------------
// Option<T>
// ---------------------------------------------------------------------------

#[test]
fn option_some_round_trip() {
    let v: Option<i32> = Some(42);
    let mut buf = Vec::new();
    v.serialize(&mut buf).unwrap();
    let decoded = Option::<i32>::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, v);
    // First byte is presence flag 0x01
    assert_eq!(buf[0], 0x01);
}

#[test]
fn option_none_round_trip() {
    let v: Option<i32> = None;
    let mut buf = Vec::new();
    v.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
    let decoded = Option::<i32>::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, None);
}

// ---------------------------------------------------------------------------
// Vec<T>  (prefixed array)
// ---------------------------------------------------------------------------

#[test]
fn vec_empty_has_varint_zero() {
    let v: Vec<i32> = Vec::new();
    let mut buf = Vec::new();
    v.serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
    let decoded = Vec::<i32>::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn vec_i32_round_trip() {
    let v = vec![1i32, 2, 3, 1000, -1];
    let mut buf = Vec::new();
    v.serialize(&mut buf).unwrap();
    let decoded = Vec::<i32>::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn vec_string_round_trip() {
    let v = vec!["Hello".to_string(), "World".to_string()];
    let mut buf = Vec::new();
    v.serialize(&mut buf).unwrap();
    let decoded = Vec::<String>::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn vec_negative_length_prefix_is_rejected() {
    use mc_protocol::ser::SerializationError;
    use mc_protocol::varint::VarInt;

    let mut buf = Vec::new();
    VarInt(-5).serialize(&mut buf).unwrap();
    let err = Vec::<u8>::deserialize(&mut Cursor::new(&buf)).unwrap_err();
    assert!(matches!(err, SerializationError::InvalidLength(-5)));
}

#[test]
fn vec_huge_declared_length_fails_without_huge_allocation() {
    use mc_protocol::varint::VarInt;

    // Declares i32::MAX elements but provides none — must error on the
    // missing data, not pre-allocate gigabytes of capacity.
    let mut buf = Vec::new();
    VarInt(i32::MAX).serialize(&mut buf).unwrap();
    let result = Vec::<u64>::deserialize(&mut Cursor::new(&buf));
    assert!(result.is_err());
}

#[test]
fn vec_of_zero_sized_elements_rejects_huge_length() {
    use mc_protocol::varint::VarInt;

    #[derive(mc_protocol::Packet, Debug)]
    struct Empty {}

    let mut buf = Vec::new();
    VarInt(i32::MAX).serialize(&mut buf).unwrap();
    let err = Vec::<Empty>::deserialize(&mut Cursor::new(&buf)).unwrap_err();
    assert!(matches!(
        err,
        mc_protocol::ser::SerializationError::InvalidLength(_)
    ));
}

// ---------------------------------------------------------------------------
// RawBytes
// ---------------------------------------------------------------------------

#[test]
fn raw_bytes_serialize_no_prefix() {
    let rb = RawBytes(vec![0x01, 0x02, 0x03]);
    let mut buf = Vec::new();
    rb.serialize(&mut buf).unwrap();
    // No length prefix — raw bytes verbatim
    assert_eq!(buf, &[0x01, 0x02, 0x03]);
}

#[test]
fn raw_bytes_read_exact() {
    let data = &[0xAA, 0xBB, 0xCC, 0xDD];
    let rb = RawBytes::read_exact(&mut Cursor::new(data), 4).unwrap();
    assert_eq!(rb.0, data);
}
