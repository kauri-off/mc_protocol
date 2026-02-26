//! # minecraft_protocol
//!
//! A complete, well-tested Rust implementation of the Minecraft Java Edition
//! network protocol data types, packet framing, encryption, and compression.
//!
//! ## Feature flags
//!
//! | Feature | Description | Default |
//! |---------|-------------|---------|
//! | `async` | Async I/O via Tokio | yes |
//! | `encryption` | AES-128-CFB8 encryption via OpenSSL | yes |
//! | `compression` | Zlib packet compression via flate2 | yes |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use minecraft_protocol::varint::VarInt;
//! use minecraft_protocol::types::Position;
//! use minecraft_protocol::ser::{Serialize, Deserialize};
//! use std::io::Cursor;
//!
//! // Encode a VarInt
//! let mut buf = Vec::new();
//! VarInt(300).serialize(&mut buf).unwrap();
//!
//! // Decode it back
//! let v = VarInt::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v.0, 300);
//!
//! // Encode a block Position
//! let pos = Position { x: 18357644, y: 831, z: -20882616 };
//! let mut buf = Vec::new();
//! pos.serialize(&mut buf).unwrap();
//! let decoded = Position::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(decoded, pos);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use minecraft_protocol_derive::*;

pub mod ser;
pub mod varint;
pub mod types;
pub mod packet;
pub mod num;

#[cfg(feature = "encryption")]
pub mod encryption;

#[cfg(feature = "compression")]
pub mod compression;
