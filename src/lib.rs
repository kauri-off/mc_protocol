//! # mc_protocol
//!
//! Rust implementation of the Minecraft Java Edition network protocol primitives:
//! serialization, packet framing, encryption, and compression.
//!
//! ## Feature flags
//!
//! | Feature | Description | Default |
//! |---------|-------------|---------|
//! | `async` | Async I/O via Tokio | yes |
//! | `encryption` | AES-128-CFB8 encryption via OpenSSL | no |
//! | `compression` | Zlib packet compression via flate2 | yes |
//!
//! To opt in to the `encryption` feature:
//!
//! ```toml
//! [dependencies]
//! mc_protocol = { version = "2.1.0", features = ["encryption"] }
//! ```
//!
//! To disable all default features:
//!
//! ```toml
//! [dependencies]
//! mc_protocol = { version = "2.1.0", default-features = false }
//! ```
//!
//! ## Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`prelude`] | Re-exports of the most commonly used types and traits |
//! | [`varint`] | [`VarInt`](varint::VarInt) and [`VarLong`](varint::VarLong) |
//! | [`ser`] | [`Serialize`](ser::Serialize) and [`Deserialize`](ser::Deserialize) traits, all primitive impls, [`RawBytes`](ser::RawBytes) |
//! | [`packet`] | [`RawPacket`](packet::RawPacket) and [`UncompressedPacket`](packet::UncompressedPacket) framing |
//! | [`compression`] | Zlib helpers — requires `compression` feature |
//! | [`encryption`] | AES-128-CFB8 types — requires `encryption` feature |
//! | [`num`] | [`Integer`](num::Integer) trait for big-endian fixed-width primitives |
//!
//! ## Quick start
//!
//! ```rust
//! use mc_protocol::varint::VarInt;
//! use mc_protocol::ser::{Serialize, Deserialize};
//! use std::io::Cursor;
//!
//! let mut buf = Vec::new();
//! VarInt(300).serialize(&mut buf).unwrap();
//!
//! let v = VarInt::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v.0, 300);
//! ```
//!
//! ## Derive macro
//!
//! `#[derive(Packet)]` generates [`Serialize`](ser::Serialize), [`Deserialize`](ser::Deserialize),
//! and [`PacketId`](packet::PacketId) for a struct, plus an associated `PACKET_ID: i32` constant.
//! The `#[packet(ID)]` attribute is required and sets the numeric packet ID.
//!
//! ```rust
//! use mc_protocol::{Packet, varint::VarInt};
//!
//! #[derive(Packet, Debug)]
//! #[packet(0x00)]
//! struct Handshake {
//!     protocol_version: VarInt,
//!     server_address: String,
//!     server_port: u16,
//!     next_state: VarInt,
//! }
//!
//! assert_eq!(Handshake::PACKET_ID, 0x00);
//! ```
//!
//! ## Serialization
//!
//! All primitive types implement [`Serialize`](ser::Serialize) and [`Deserialize`](ser::Deserialize).
//! Supported types out of the box: `bool`, `i8`–`i128`, `u8`–`u128`, `f32`, `f64`,
//! [`VarInt`](varint::VarInt), [`VarLong`](varint::VarLong), `String`, `Uuid`,
//! `Option<T>` (boolean presence flag), `Vec<T>` (VarInt-prefixed), and
//! [`RawBytes`](ser::RawBytes) (no-prefix byte slice).
//!
//! All fixed-width integers are big-endian; VarInt/VarLong use little-endian 7-bit groups.
//!
//! ```rust
//! use mc_protocol::ser::{Serialize, Deserialize};
//! use mc_protocol::varint::VarInt;
//! use std::io::Cursor;
//!
//! // VarInt(300) encodes to two bytes
//! let mut buf = Vec::new();
//! VarInt(300).serialize(&mut buf).unwrap();
//! assert_eq!(buf, &[0xac, 0x02]);
//!
//! // Option<T> — prefixed with a boolean presence byte
//! let mut buf = Vec::new();
//! Some(42u32).serialize(&mut buf).unwrap();
//! let v = Option::<u32>::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v, Some(42));
//!
//! // Vec<T> — prefixed with a VarInt element count
//! let mut buf = Vec::new();
//! vec![1u8, 2u8, 3u8].serialize(&mut buf).unwrap();
//! let v = Vec::<u8>::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v, &[1, 2, 3]);
//! ```
//!
//! ## Packet framing
//!
//! The protocol wraps every packet in a length-prefixed frame.
//! [`RawPacket`](packet::RawPacket) is the on-wire frame (length VarInt + data).
//! [`UncompressedPacket`](packet::UncompressedPacket) is the decoded form (packet ID + payload bytes).
//!
//! ### Sync
//!
//! ```rust,no_run
//! use mc_protocol::packet::{RawPacket, UncompressedPacket};
//! use std::net::TcpStream;
//!
//! let mut stream = TcpStream::connect("127.0.0.1:25565").unwrap();
//!
//! // Read an incoming packet
//! let raw = RawPacket::read_sync(&mut stream).unwrap();
//! let packet = raw.as_uncompressed().unwrap();
//! println!("id=0x{:02X} payload_len={}", packet.packet_id, packet.payload.len());
//!
//! // Write a packet
//! let up = UncompressedPacket::new(0x00, vec![0x00]);
//! up.write_sync(&mut stream).unwrap();
//! ```
//!
//! ### Async (requires `async` feature)
//!
//! ```rust,no_run
//! use mc_protocol::packet::{RawPacket, UncompressedPacket};
//! use tokio::net::TcpStream;
//!
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut stream = TcpStream::connect("127.0.0.1:25565").await?;
//!
//! let raw = RawPacket::read_async(&mut stream).await?;
//! let packet = raw.as_uncompressed()?;
//!
//! let up = UncompressedPacket::new(0x00, vec![0x00]);
//! up.write_async(&mut stream).await?;
//! # Ok(()) }
//! ```
//!
//! ## Compression (requires `compression` feature)
//!
//! After a `Set Compression` packet, frames carry a `data_length` field.
//! Packets below the threshold are sent as-is (`data_length = 0`);
//! larger packets are zlib-compressed.
//!
//! ```rust
//! use mc_protocol::packet::UncompressedPacket;
//!
//! let up = UncompressedPacket::new(0x26, vec![0u8; 512]);
//! let threshold = Some(256);
//!
//! let raw = up.to_raw_packet_compressed(threshold).unwrap();
//! let decoded = raw.uncompress(threshold).unwrap();
//! assert_eq!(decoded.packet_id, 0x26);
//! ```
//!
//! ## Encryption (requires `encryption` feature)
//!
//! After a successful login handshake, both sides encrypt every byte with
//! AES-128-CFB8 using the negotiated shared secret as both the key and the IV.
//!
//! ### Sync wrappers
//!
//! ```rust,no_run
//! use mc_protocol::encryption::{Cfb8Encryptor, Cfb8Decryptor};
//!
//! let key: [u8; 16] = [0u8; 16]; // replace with negotiated shared secret
//! let mut enc = Cfb8Encryptor::new(&key).unwrap();
//! let mut dec = Cfb8Decryptor::new(&key).unwrap();
//!
//! let ciphertext = enc.encrypt(b"packet data").unwrap();
//! let plaintext = dec.decrypt(&ciphertext).unwrap();
//! assert_eq!(plaintext, b"packet data");
//! ```
//!
//! For transparent stream encryption, wrap a `Read`/`Write` with
//! [`Cfb8ReadHalf`](encryption::Cfb8ReadHalf) and [`Cfb8WriteHalf`](encryption::Cfb8WriteHalf).
//!
//! ### Async stream (requires `async` + `encryption` features)
//!
//! ```rust,no_run
//! use mc_protocol::encryption::Cfb8Stream;
//! use tokio::net::TcpStream;
//!
//! # #[tokio::main] async fn main() -> std::io::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:25565").await?;
//! let key: [u8; 16] = [0u8; 16];
//!
//! let mut encrypted = Cfb8Stream::new_from_tcp(stream, &key)?;
//! // All I/O through `encrypted` is transparently encrypted/decrypted
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use mc_protocol_derive::*;

pub mod num;
pub mod packet;
pub mod prelude;
pub mod ser;
pub mod varint;

#[cfg(feature = "encryption")]
pub mod encryption;

#[cfg(feature = "compression")]
pub mod compression;
