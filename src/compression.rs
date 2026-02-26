//! Zlib packet compression as used in the Minecraft Java Edition protocol.
//!
//! After the server sends a `Set Compression` packet, all subsequent packets
//! are framed with a compression header. Packets whose uncompressed size is
//! below the threshold are sent uncompressed (with `data_length = 0`);
//! larger packets are deflated with zlib.
//!
//! # Example
//!
//! ```rust
//! use minecraft_protocol::compression::{compress_zlib, decompress_zlib};
//!
//! let data = b"Hello, Minecraft!";
//! let compressed = compress_zlib(data).unwrap();
//! let decompressed = decompress_zlib(&compressed).unwrap();
//! assert_eq!(&decompressed, data);
//! ```

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};
use thiserror::Error;

/// Errors that can occur during compression or decompression.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// An I/O error during the compression or decompression process.
    #[error("Compression I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CompressionError> for crate::packet::PacketError {
    fn from(e: CompressionError) -> Self {
        crate::packet::PacketError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

/// Compress `data` using zlib deflate at the default compression level.
///
/// Returns the compressed bytes.
pub fn compress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Compress `data` using zlib deflate at a specific compression level (0–9).
pub fn compress_zlib_level(data: &[u8], level: u32) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Decompress zlib-deflated `data`.
///
/// Returns the original uncompressed bytes.
pub fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}
