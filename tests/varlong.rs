//! Tests for VarLong encoding and decoding.
//!
//! Reference values taken from the Minecraft Java Edition protocol documentation.

use minecraft_protocol::ser::{Deserialize, Serialize};
use minecraft_protocol::varint::VarLong;
use std::io::Cursor;

fn round_trip(value: i64) -> i64 {
    let mut buf = Vec::new();
    VarLong(value).serialize(&mut buf).unwrap();
    VarLong::deserialize(&mut Cursor::new(&buf)).unwrap().0
}

#[test]
fn varlong_zero() {
    let mut buf = Vec::new();
    VarLong(0).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x00]);
    assert_eq!(round_trip(0), 0);
}

#[test]
fn varlong_one() {
    let mut buf = Vec::new();
    VarLong(1).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x01]);
    assert_eq!(round_trip(1), 1);
}

#[test]
fn varlong_127() {
    let mut buf = Vec::new();
    VarLong(127).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x7f]);
    assert_eq!(round_trip(127), 127);
}

#[test]
fn varlong_128() {
    let mut buf = Vec::new();
    VarLong(128).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0x80, 0x01]);
    assert_eq!(round_trip(128), 128);
}

#[test]
fn varlong_2147483647() {
    let mut buf = Vec::new();
    VarLong(2147483647).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0xff, 0xff, 0x07]);
    assert_eq!(round_trip(2147483647), 2147483647);
}

#[test]
fn varlong_max_positive() {
    let mut buf = Vec::new();
    VarLong(9223372036854775807).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert_eq!(round_trip(9223372036854775807), 9223372036854775807);
}

#[test]
fn varlong_negative_one() {
    let mut buf = Vec::new();
    VarLong(-1).serialize(&mut buf).unwrap();
    assert_eq!(buf, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    assert_eq!(round_trip(-1), -1);
}

#[test]
fn varlong_min_negative() {
    let mut buf = Vec::new();
    VarLong(-9223372036854775808).serialize(&mut buf).unwrap();
    assert_eq!(
        buf,
        &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]
    );
    assert_eq!(round_trip(-9223372036854775808), -9223372036854775808);
}

#[test]
fn varlong_negative_uses_10_bytes() {
    let mut buf = Vec::new();
    VarLong(-1).serialize(&mut buf).unwrap();
    assert_eq!(buf.len(), 10);
}

#[test]
fn varlong_too_long_returns_error() {
    // 11 bytes with continuation bits — should error
    let data: &[u8] = &[0x80; 11];
    let result = VarLong::deserialize(&mut Cursor::new(data));
    assert!(result.is_err());
}

#[test]
fn varlong_encoded_len() {
    assert_eq!(VarLong(0).encoded_len(), 1);
    assert_eq!(VarLong(127).encoded_len(), 1);
    assert_eq!(VarLong(128).encoded_len(), 2);
    assert_eq!(VarLong(9223372036854775807).encoded_len(), 9);
    assert_eq!(VarLong(-1).encoded_len(), 10);
}
