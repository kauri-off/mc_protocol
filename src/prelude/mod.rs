//! Convenient re-exports for everyday use of `mc_protocol`.
//!
//! Importing the prelude brings the most commonly used types, traits, and the
//! derive macro into scope with a single `use` statement, avoiding repetitive
//! per-module imports in protocol implementation crates.
//!
//! # Usage
//!
//! ```rust
//! use mc_protocol::prelude::*;
//! ```
//!
//! This gives you:
//!
//! - [`Serialize`] and [`Deserialize`] traits for encoding/decoding protocol fields
//! - [`SerializationError`] for serialization error handling
//! - [`VarInt`] and [`VarLong`] — variable-length integer types used throughout the protocol
//! - [`RawPacket`] and [`UncompressedPacket`] for packet framing
//! - [`PacketId`] trait and [`PacketError`] for packet I/O
//! - `#[derive(Packet)]` macro for automatic struct serialization
//!
//! Feature-gated items are re-exported only when the relevant feature is enabled.
//! Enable `compression` to get the zlib helpers, and `encryption` for the
//! AES-128-CFB8 types.

// --- Core serialization ---
pub use crate::ser::{Deserialize, Serialize, SerializationError};

// --- Variable-length integers ---
pub use crate::varint::{VarInt, VarLong};

// --- Packet framing ---
pub use crate::packet::{PacketError, PacketId, RawPacket, UncompressedPacket};

// --- Derive macro ---
pub use mc_protocol_derive::Packet;

// --- Compression helpers (requires `compression` feature) ---
#[cfg(feature = "compression")]
pub use crate::compression::{
    compress_zlib, compress_zlib_level, decompress_zlib, CompressionError,
};

// --- Sync encryption (requires `encryption` feature) ---
#[cfg(feature = "encryption")]
pub use crate::encryption::{Cfb8Decryptor, Cfb8Encryptor, Cfb8ReadHalf, Cfb8WriteHalf};

// --- Async encryption (requires `async` + `encryption` features) ---
#[cfg(all(feature = "async", feature = "encryption"))]
pub use crate::encryption::{AsyncCfb8ReadHalf, AsyncCfb8WriteHalf, Cfb8Stream};
