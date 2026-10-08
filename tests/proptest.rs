//! Property-based tests: round-trips and no panics on arbitrary input.

use mc_protocol::packet::{RawPacket, UncompressedPacket};
use mc_protocol::ser::{Deserialize, Serialize};
use mc_protocol::varint::{VarInt, VarLong};
use proptest::prelude::*;
use std::io::Cursor;

#[derive(mc_protocol::Packet, Debug, Clone, PartialEq)]
#[packet(0x2A)]
struct Sample {
    id: VarInt,
    big: VarLong,
    name: String,
    flags: Vec<bool>,
    extra: Option<i64>,
    pos: f64,
}

fn round_trip<T: Serialize + Deserialize>(value: &T) -> T {
    let mut buf = Vec::new();
    value.serialize(&mut buf).unwrap();
    let mut cursor = Cursor::new(&buf);
    let decoded = T::deserialize(&mut cursor).unwrap();
    assert_eq!(cursor.position() as usize, buf.len());
    decoded
}

fn sample() -> impl Strategy<Value = Sample> {
    (
        any::<i32>(),
        any::<i64>(),
        ".{0,64}",
        proptest::collection::vec(any::<bool>(), 0..32),
        any::<Option<i64>>(),
        any::<f64>().prop_filter("NaN != NaN", |f| !f.is_nan()),
    )
        .prop_map(|(id, big, name, flags, extra, pos)| Sample {
            id: VarInt(id),
            big: VarLong(big),
            name,
            flags,
            extra,
            pos,
        })
}

proptest! {
    #[test]
    fn varint_round_trips(v in any::<i32>()) {
        let mut buf = Vec::new();
        VarInt(v).serialize(&mut buf).unwrap();
        prop_assert_eq!(buf.len(), VarInt(v).encoded_len());
        prop_assert_eq!(round_trip(&VarInt(v)), VarInt(v));
    }

    #[test]
    fn varlong_round_trips(v in any::<i64>()) {
        let mut buf = Vec::new();
        VarLong(v).serialize(&mut buf).unwrap();
        prop_assert_eq!(buf.len(), VarLong(v).encoded_len());
        prop_assert_eq!(round_trip(&VarLong(v)), VarLong(v));
    }

    #[test]
    fn string_round_trips(s in ".{0,256}") {
        prop_assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn derived_packet_round_trips(p in sample()) {
        prop_assert_eq!(round_trip(&p), p.clone());

        let up = UncompressedPacket::from_packet(&p).unwrap();
        let mut wire = Vec::new();
        up.write_sync(&mut wire).unwrap();
        let raw = RawPacket::read_sync(&mut Cursor::new(&wire)).unwrap();
        let decoded = raw.as_uncompressed().unwrap();
        prop_assert_eq!(decoded.packet_id, Sample::PACKET_ID);
        prop_assert_eq!(decoded.deserialize_payload::<Sample>().unwrap(), p);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = RawPacket::read_sync(&mut Cursor::new(&bytes));
        let _ = Sample::deserialize(&mut Cursor::new(&bytes));
        let _ = Vec::<String>::deserialize(&mut Cursor::new(&bytes));
        let raw = RawPacket::new(bytes);
        let _ = raw.as_uncompressed();
        let _ = raw.uncompress(Some(256));
    }
}

#[cfg(feature = "compression")]
proptest! {
    #[test]
    fn compressed_packet_round_trips(
        id in any::<i32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        threshold in -1i32..1024,
    ) {
        let up = UncompressedPacket::new(id, payload);
        let raw = up.to_raw_packet_compressed(Some(threshold)).unwrap();
        let decoded = raw.uncompress(Some(threshold)).unwrap();
        prop_assert_eq!(decoded.packet_id, id);
        prop_assert_eq!(decoded.payload, up.payload);
    }
}
