//! Tests for bulk, allocation-light I/O paths.

use std::io::Cursor;

use mc_protocol::packet::RawPacket;
use mc_protocol::ser::{ByteArray, Deserialize, Serialize};
use mc_protocol::varint::{VarInt, VarLong};

#[test]
fn byte_array_is_wire_compatible_with_vec_u8() {
    let bytes: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let mut from_vec = Vec::new();
    bytes.serialize(&mut from_vec).unwrap();
    let mut from_array = Vec::new();
    ByteArray(bytes.clone()).serialize(&mut from_array).unwrap();
    assert_eq!(from_vec, from_array);
    assert_eq!(
        ByteArray::deserialize(&mut Cursor::new(&from_vec))
            .unwrap()
            .0,
        bytes
    );
}

#[test]
fn byte_array_rejects_truncated_and_lying_prefix() {
    let mut buf = Vec::new();
    VarInt(1_000_000).write_sync(&mut buf).unwrap();
    buf.extend_from_slice(&[1, 2, 3]);
    assert!(ByteArray::deserialize(&mut Cursor::new(&buf)).is_err());

    let mut buf = Vec::new();
    VarInt(-1).write_sync(&mut buf).unwrap();
    assert!(ByteArray::deserialize(&mut Cursor::new(&buf)).is_err());
}

#[test]
fn encode_matches_byte_length() {
    for v in [0, 1, 127, 128, 300, i32::MAX, -1, i32::MIN] {
        let (buf, len) = VarInt(v).encode();
        assert_eq!(len, VarInt(v).encoded_len());
        assert_eq!(VarInt::read_sync(&mut &buf[..len]).unwrap().0, v);
    }
    for v in [0, 1, i64::MAX, -1, i64::MIN] {
        let (buf, len) = VarLong(v).encode();
        assert_eq!(len, VarLong(v).encoded_len());
        assert_eq!(VarLong::read_sync(&mut &buf[..len]).unwrap().0, v);
    }
}

#[test]
fn read_sync_rejects_truncated_frame() {
    let mut buf = Vec::new();
    VarInt(10).write_sync(&mut buf).unwrap();
    buf.extend_from_slice(&[0; 4]);
    assert!(RawPacket::read_sync(&mut Cursor::new(&buf)).is_err());
}

#[cfg(feature = "async")]
#[tokio::test]
async fn read_async_reads_exact_frames_and_rejects_truncation() {
    let first = RawPacket::new(vec![1; 70_000]);
    let second = RawPacket::new(vec![2; 3]);
    let mut buf = Vec::new();
    first.write_sync(&mut buf).unwrap();
    second.write_sync(&mut buf).unwrap();

    let mut reader = &buf[..];
    assert_eq!(
        RawPacket::read_async(&mut reader).await.unwrap().data,
        first.data
    );
    assert_eq!(
        RawPacket::read_async(&mut reader).await.unwrap().data,
        second.data
    );

    let mut truncated = &buf[..buf.len() - 1];
    RawPacket::read_async(&mut truncated).await.unwrap();
    assert!(RawPacket::read_async(&mut truncated).await.is_err());
}
