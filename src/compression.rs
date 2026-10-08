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
//! use mc_protocol::compression::{compress_zlib, decompress_zlib};
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
        // Preserve the source error chain instead of flattening to a string.
        crate::packet::PacketError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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

/// Compress `data` using zlib deflate at a specific compression level.
///
/// Valid levels are 0 (no compression) through 9 (best compression);
/// values above 9 are clamped to 9.
pub fn compress_zlib_level(data: &[u8], level: u32) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level.min(9)));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Decompress zlib-deflated `data`.
///
/// Returns the original uncompressed bytes. The output size is unbounded;
/// when the expected size is known (e.g. from a packet's `data_length`
/// field), prefer [`decompress_zlib_limited`].
pub fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

/// Decompress zlib-deflated `data`, refusing to inflate beyond `limit` bytes.
///
/// Returns an error of kind `InvalidData` if the decompressed output would
/// exceed `limit` — this guards against zip bombs, where a tiny compressed
/// input expands to a huge output.
pub fn decompress_zlib_limited(data: &[u8], limit: usize) -> Result<Vec<u8>, CompressionError> {
    // Read at most limit + 1 bytes: anything past `limit` means the input lied.
    let mut decoder = ZlibDecoder::new(data).take(limit as u64 + 1);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(CompressionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decompressed size exceeds declared limit of {limit} bytes"),
        )));
    }
    Ok(output)
}
