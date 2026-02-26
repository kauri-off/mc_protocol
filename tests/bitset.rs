//! Tests for BitSet and FixedBitSet.

use minecraft_protocol::ser::{Deserialize, Serialize};
use minecraft_protocol::types::{BitSet, FixedBitSet};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// BitSet
// ---------------------------------------------------------------------------

#[test]
fn bitset_empty_encodes_to_varint_zero() {
    let bs = BitSet::new();
    let mut buf = Vec::new();
    bs.serialize(&mut buf).unwrap();
    // VarInt(0) — no longs follow
    assert_eq!(buf, &[0x00]);
}

#[test]
fn bitset_empty_round_trip() {
    let bs = BitSet::new();
    let mut buf = Vec::new();
    bs.serialize(&mut buf).unwrap();
    let decoded = BitSet::deserialize(&mut Cursor::new(&buf)).unwrap();
    assert!(decoded.data.is_empty());
}

#[test]
fn bitset_set_and_get_single_bit() {
    let mut bs = BitSet::new();
    bs.set(0);
    assert!(bs.get(0));
    assert!(!bs.get(1));
}

#[test]
fn bitset_set_and_get_bit_63() {
    let mut bs = BitSet::new();
    bs.set(63);
    assert!(bs.get(63));
    assert!(!bs.get(62));
}

#[test]
fn bitset_set_and_get_bit_64_crosses_long_boundary() {
    let mut bs = BitSet::new();
    bs.set(64);
    assert!(bs.get(64));
    assert!(!bs.get(63));
    assert_eq!(bs.data.len(), 2);
}

#[test]
fn bitset_clear_bit() {
    let mut bs = BitSet::new();
    bs.set(5);
    assert!(bs.get(5));
    bs.clear(5);
    assert!(!bs.get(5));
}

#[test]
fn bitset_round_trip_with_bits() {
    let mut bs = BitSet::new();
    bs.set(0);
    bs.set(7);
    bs.set(63);
    bs.set(64);
    bs.set(127);

    let mut buf = Vec::new();
    bs.serialize(&mut buf).unwrap();
    let decoded = BitSet::deserialize(&mut Cursor::new(&buf)).unwrap();

    assert!(decoded.get(0));
    assert!(decoded.get(7));
    assert!(decoded.get(63));
    assert!(decoded.get(64));
    assert!(decoded.get(127));
    assert!(!decoded.get(1));
    assert!(!decoded.get(8));
}

#[test]
fn bitset_get_out_of_range_returns_false() {
    let bs = BitSet::new();
    assert!(!bs.get(1000));
}

// ---------------------------------------------------------------------------
// FixedBitSet
// ---------------------------------------------------------------------------

#[test]
fn fixed_bitset_new_is_zeroed() {
    let fbs = FixedBitSet::new(16);
    for i in 0..16 {
        assert!(!fbs.get(i), "Bit {} should be 0", i);
    }
}

#[test]
fn fixed_bitset_byte_count() {
    assert_eq!(FixedBitSet::new(8).data.len(), 1);
    assert_eq!(FixedBitSet::new(9).data.len(), 2);
    assert_eq!(FixedBitSet::new(16).data.len(), 2);
    assert_eq!(FixedBitSet::new(17).data.len(), 3);
    assert_eq!(FixedBitSet::new(1).data.len(), 1);
}

#[test]
fn fixed_bitset_set_and_get() {
    let mut fbs = FixedBitSet::new(24);
    fbs.set(0);
    fbs.set(7);
    fbs.set(8);
    fbs.set(23);

    assert!(fbs.get(0));
    assert!(fbs.get(7));
    assert!(fbs.get(8));
    assert!(fbs.get(23));
    assert!(!fbs.get(1));
    assert!(!fbs.get(9));
    assert!(!fbs.get(22));
}

#[test]
fn fixed_bitset_clear() {
    let mut fbs = FixedBitSet::new(8);
    fbs.set(3);
    assert!(fbs.get(3));
    fbs.clear(3);
    assert!(!fbs.get(3));
}

#[test]
fn fixed_bitset_serialize_deserialize_fixed() {
    let mut fbs = FixedBitSet::new(16);
    fbs.set(0);
    fbs.set(15);

    let mut buf = Vec::new();
    fbs.serialize_fixed(&mut buf).unwrap();
    assert_eq!(buf.len(), 2); // ceil(16/8) = 2 bytes

    let decoded = FixedBitSet::deserialize_fixed(&mut Cursor::new(&buf), 16).unwrap();
    assert!(decoded.get(0));
    assert!(decoded.get(15));
    assert!(!decoded.get(1));
}

#[test]
fn fixed_bitset_bit_ordering_matches_spec() {
    // i-th bit is set when (Data[i/8] & (1 << (i%8))) != 0
    let mut fbs = FixedBitSet::new(8);
    fbs.set(0); // bit 0 of byte 0 — LSB
    fbs.set(7); // bit 7 of byte 0 — MSB

    assert_eq!(fbs.data[0], 0b1000_0001);
}
