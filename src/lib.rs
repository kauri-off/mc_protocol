//! # minecraft_protocol
//!
//! Rust implementation of the Minecraft Java Edition network protocol primitives:
//! serialization, packet framing, encryption, and compression.
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
//! ```rust
//! use minecraft_protocol::varint::VarInt;
//! use minecraft_protocol::ser::{Serialize, Deserialize};
//! use std::io::Cursor;
//!
//! let mut buf = Vec::new();
//! VarInt(300).serialize(&mut buf).unwrap();
//!
//! let v = VarInt::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v.0, 300);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use minecraft_protocol_derive::*;

pub mod ser;
pub mod varint;
pub mod packet;
pub mod num;

#[cfg(feature = "encryption")]
pub mod encryption;

#[cfg(feature = "compression")]
pub mod compression;
