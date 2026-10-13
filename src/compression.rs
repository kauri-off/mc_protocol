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

use flate2::{
    Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status,
    bufread::ZlibDecoder, write::ZlibEncoder,
};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use thiserror::Error;

/// Upper bound on the output buffer reserved up front, before any data is inflated.
const MAX_PREALLOC: usize = 16 * 1024 * 1024;

thread_local! {
    // Deflate/inflate state is large and costly to initialise, so reuse it per thread.
    static DEFLATE: RefCell<Compress> = RefCell::new(Compress::new(Compression::default(), true));
    static INFLATE: RefCell<Decompress> = RefCell::new(Decompress::new(true));
}

fn invalid_data(msg: impl Into<String>) -> CompressionError {
    CompressionError::Io(io::Error::new(io::ErrorKind::InvalidData, msg.into()))
}

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
    DEFLATE.with_borrow_mut(|deflate| {
        deflate.reset();
        let mut output = Vec::with_capacity(data.len() / 2 + 64);
        loop {
            let consumed = deflate.total_in() as usize;
            let status = deflate
                .compress_vec(&data[consumed..], &mut output, FlushCompress::Finish)
                .map_err(|e| invalid_data(e.to_string()))?;
            if status == Status::StreamEnd {
                return Ok(output);
            }
            output.reserve(output.capacity().max(64));
        }
    })
}

/// Compress `data` using zlib deflate at a specific compression level.
///
/// Valid levels are 0 (no compression) through 9 (best compression);
/// values above 9 are clamped to 9.
pub fn compress_zlib_level(data: &[u8], level: u32) -> Result<Vec<u8>, CompressionError> {
    let mut encoder = ZlibEncoder::new(
        Vec::with_capacity(data.len() / 2 + 64),
        Compression::new(level.min(9)),
    );
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
    // Room for limit + 1 bytes: producing more than `limit` means the input lied.
    let max_len = limit.saturating_add(1);
    INFLATE.with_borrow_mut(|inflate| {
        inflate.reset(true);
        let mut output = Vec::with_capacity(max_len.min(MAX_PREALLOC));
        loop {
            let (consumed, produced) = (inflate.total_in(), inflate.total_out());
            let status = inflate
                .decompress_vec(
                    &data[consumed as usize..],
                    &mut output,
                    FlushDecompress::Finish,
                )
                .map_err(|e| invalid_data(e.to_string()))?;
            if output.len() > limit {
                return Err(invalid_data(format!(
                    "decompressed size exceeds declared limit of {limit} bytes"
                )));
            }
            if status == Status::StreamEnd {
                return Ok(output);
            }
            if output.len() == output.capacity() {
                output.reserve(output.len().max(64).min(max_len - output.len()));
            } else if (consumed, produced) == (inflate.total_in(), inflate.total_out()) {
                return Err(CompressionError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    })
}
