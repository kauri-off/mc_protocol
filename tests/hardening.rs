//! Regression tests for hostile input and I/O failure handling.

use mc_protocol::Packet;
use mc_protocol::packet::{PacketError, RawPacket, UncompressedPacket};
use mc_protocol::ser::{Deserialize, MAX_VEC_NESTING, SerializationError};
use mc_protocol::varint::VarInt;
use std::io::{self, Cursor};

#[derive(Packet, Debug)]
struct Node {
    children: Vec<Node>,
}

#[derive(Packet, Debug)]
struct Sparse {
    items: Vec<Option<String>>,
}

#[derive(Packet, Debug, PartialEq)]
struct Generic<W, R> {
    a: W,
    b: R,
}

const BASE: u8 = 0x10;

#[derive(Packet, Debug)]
#[packet(BASE + 1)]
struct ComputedId {
    x: u8,
}

fn nested(depth: usize) -> Vec<u8> {
    let mut wire = vec![1u8; depth];
    wire.push(0);
    wire
}

#[test]
fn hostile_nesting_is_rejected_on_a_small_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let err = Node::deserialize(&mut Cursor::new(nested(2_000_000))).unwrap_err();
            assert!(
                matches!(err, SerializationError::Io(e) if e.kind() == io::ErrorKind::InvalidData)
            );
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn nesting_limit_and_state_reset() {
    let limit = MAX_VEC_NESTING as usize;
    Node::deserialize(&mut Cursor::new(nested(limit - 1))).unwrap();
    Node::deserialize(&mut Cursor::new(nested(limit))).unwrap_err();
    Node::deserialize(&mut Cursor::new(nested(limit - 1))).unwrap();
}

#[test]
fn memory_amplification_is_rejected_before_decoding() {
    let mut wire = Vec::new();
    VarInt(8_000_000).write_sync(&mut wire).unwrap();
    wire.resize(wire.len() + 8_000_000, 0);
    let err = Sparse::deserialize(&mut Cursor::new(wire)).unwrap_err();
    assert!(matches!(err, SerializationError::InvalidLength(8_000_000)));
}

#[test]
fn budget_is_shared_by_nested_vecs() {
    let mut wire = Vec::new();
    VarInt(16).write_sync(&mut wire).unwrap();
    for _ in 0..16 {
        VarInt(200_000).write_sync(&mut wire).unwrap();
        wire.resize(wire.len() + 200_000, 0);
    }
    assert!(Vec::<Vec<Option<String>>>::deserialize(&mut Cursor::new(wire)).is_err());
}

#[test]
fn frame_prefix_wider_than_three_bytes_is_rejected() {
    let frame = [0x81u8, 0x80, 0x80, 0x00, 0x05];
    let err = RawPacket::read_sync(&mut Cursor::new(&frame)).unwrap_err();
    assert!(matches!(err, PacketError::InvalidLength(1)));

    let canonical = [0x01u8, 0x05];
    assert_eq!(
        RawPacket::read_sync(&mut Cursor::new(&canonical))
            .unwrap()
            .data,
        [5]
    );
}

#[test]
fn truncated_large_frame_fails_with_eof() {
    let err = RawPacket::read_sync(&mut Cursor::new(&[0xffu8, 0xff, 0x7f, 1, 2])).unwrap_err();
    assert!(matches!(err, PacketError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof));
}

#[test]
fn derive_accepts_w_and_r_generics() {
    let value = Generic {
        a: 7u8,
        b: VarInt(300),
    };
    let mut wire = Vec::new();
    mc_protocol::ser::Serialize::serialize(&value, &mut wire).unwrap();
    assert_eq!(
        Generic::<u8, VarInt>::deserialize(&mut Cursor::new(wire)).unwrap(),
        value
    );
}

#[test]
fn derive_parenthesizes_id_expression() {
    assert_eq!(ComputedId::PACKET_ID, 0x11);
    assert_eq!(ComputedId { x: 0 }.x, 0);
}

#[cfg(not(feature = "compression"))]
#[test]
fn active_threshold_errors_without_compression_feature() {
    let packet = UncompressedPacket::new(1, vec![2]);
    assert!(packet.to_raw_packet_compressed(Some(256)).is_err());
    assert!(packet.to_raw_packet_compressed(None).is_ok());
    let raw = RawPacket::new(vec![0, 1, 2]);
    assert!(raw.uncompress(Some(256)).is_err());
    assert!(raw.clone().into_uncompressed(Some(256)).is_err());
    assert_eq!(raw.uncompress(Some(-1)).unwrap().packet_id, 0);
}

#[cfg(feature = "compression")]
mod compressed {
    use super::*;
    use mc_protocol::compression::{compress_zlib, decompress_zlib_limited};

    fn frame(data_length: i32, body: &[u8]) -> RawPacket {
        let mut data = Vec::new();
        VarInt(data_length).write_sync(&mut data).unwrap();
        data.extend_from_slice(body);
        RawPacket::new(data)
    }

    #[test]
    fn declared_length_below_threshold_is_rejected() {
        let raw = frame(3, &compress_zlib(&[1, 2, 3]).unwrap());
        assert!(matches!(
            raw.uncompress(Some(256)),
            Err(PacketError::InvalidLength(3))
        ));
        assert!(matches!(
            raw.clone().into_uncompressed(Some(256)),
            Err(PacketError::InvalidLength(3))
        ));
        assert_eq!(raw.uncompress(Some(3)).unwrap().payload, [2, 3]);
    }

    #[test]
    fn trailing_bytes_after_zlib_stream_are_rejected() {
        let mut body = compress_zlib(&[1, 2, 3]).unwrap();
        decompress_zlib_limited(&body, 3).unwrap();
        body.push(0);
        decompress_zlib_limited(&body, 3).unwrap_err();
    }

    #[test]
    fn realistic_compressed_packet_still_round_trips() {
        let packet = UncompressedPacket::new(9, vec![0; 4096]);
        let raw = packet.to_raw_packet_compressed(Some(256)).unwrap();
        assert_eq!(raw.uncompress(Some(256)).unwrap().payload.len(), 4096);
    }
}

#[cfg(feature = "encryption")]
mod encrypted {
    use super::*;
    use mc_protocol::encryption::{Cfb8Decryptor, Cfb8WriteHalf};
    use std::io::Write;

    const KEY: [u8; 16] = [7; 16];

    #[derive(Default)]
    struct Flaky {
        out: Vec<u8>,
        failures: usize,
    }

    impl Write for Flaky {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.failures > 0 {
                self.failures -= 1;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = data.len().min(3);
            self.out.extend_from_slice(&data[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn plaintext(out: &[u8]) -> Vec<u8> {
        Cfb8Decryptor::new(&KEY).unwrap().decrypt(out).unwrap()
    }

    #[test]
    fn would_block_keeps_cipher_and_stream_in_sync() {
        let inner = Flaky {
            failures: 1,
            ..Default::default()
        };
        let mut writer = Cfb8WriteHalf::new(inner, &KEY).unwrap();
        writer.write_all(b"hello ").unwrap();
        writer.write_all(b"world").unwrap();
        writer.flush().unwrap();
        assert_eq!(plaintext(&writer.into_inner().out), b"hello world");
    }

    #[test]
    fn failed_drain_consumes_nothing_on_retry() {
        let inner = Flaky {
            failures: 2,
            ..Default::default()
        };
        let mut writer = Cfb8WriteHalf::new(inner, &KEY).unwrap();
        assert_eq!(writer.write(b"one").unwrap(), 3);
        assert!(writer.write(b"two").is_err());
        assert_eq!(writer.write(b"two").unwrap(), 3);
        writer.flush().unwrap();
        assert_eq!(plaintext(&writer.into_inner().out), b"onetwo");
    }
}
