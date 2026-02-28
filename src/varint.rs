//! VarInt and VarLong types as defined in the Minecraft Java Edition protocol.
//!
//! These are variable-length, little-endian 7-bit group encodings of 32-bit
//! and 64-bit signed integers respectively. They are similar to Protocol
//! Buffer varints but use normal (not ZigZag) encoding, so negative values
//! always use the maximum number of bytes.
//!
//! # Encoding
//!
//! Each byte contributes 7 bits of value data. The most significant bit is a
//! *continuation flag*: if set, another byte follows. Groups are ordered from
//! least significant to most significant (little-endian groups).
//!
//! VarInts are at most **5 bytes**; VarLongs are at most **10 bytes**.
//!
//! # Examples
//!
//! ```
//! use mc_protocol::varint::{VarInt, VarLong};
//! use mc_protocol::ser::{Serialize, Deserialize};
//! use std::io::Cursor;
//!
//! let mut buf = Vec::new();
//! VarInt(300).serialize(&mut buf).unwrap();
//! assert_eq!(buf, &[0xac, 0x02]);
//!
//! let v = VarInt::deserialize(&mut Cursor::new(&buf)).unwrap();
//! assert_eq!(v.0, 300);
//!
//! // Negative values use maximum bytes
//! let mut buf = Vec::new();
//! VarInt(-1).serialize(&mut buf).unwrap();
//! assert_eq!(buf.len(), 5);
//! ```

use std::io::{self, Read, Write};
use thiserror::Error;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced when reading a malformed VarInt or VarLong.
#[derive(Debug, Error)]
pub enum VarIntError {
    /// The encoded value required more bytes than the protocol allows.
    #[error("VarInt exceeded maximum byte length")]
    TooLong,

    /// An underlying I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A length-encoded value was negative, which is not valid in this context.
    #[error("Negative value is not allowed in this context")]
    NegativeValue,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEGMENT_BITS: u8 = 0x7F;
const CONTINUE_BIT: u8 = 0x80;

// ---------------------------------------------------------------------------
// VarInt
// ---------------------------------------------------------------------------

/// A variable-length signed 32-bit integer as used in the Minecraft protocol.
///
/// Wraps an `i32`. Negative values use 5 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VarInt(pub i32);

impl VarInt {
    /// The minimum number of bytes needed to represent this value.
    pub fn encoded_len(&self) -> usize {
        let mut value = self.0 as u32;
        let mut count = 0;
        loop {
            count += 1;
            if value & !(SEGMENT_BITS as u32) == 0 {
                break;
            }
            value >>= 7;
        }
        count
    }

    // --- Synchronous I/O ---

    /// Decode a `VarInt` from a synchronous reader.
    pub fn read_sync<R: Read>(reader: &mut R) -> Result<Self, VarIntError> {
        let mut value: i32 = 0;
        let mut position: u32 = 0;

        loop {
            let mut byte_buf = [0u8; 1];
            if reader.read(&mut byte_buf)? == 0 {
                return Err(VarIntError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF reading VarInt",
                )));
            }

            let byte = byte_buf[0];
            value |= ((byte & SEGMENT_BITS) as i32) << position;

            if byte & CONTINUE_BIT == 0 {
                break;
            }

            position += 7;
            if position >= 32 {
                return Err(VarIntError::TooLong);
            }
        }

        Ok(VarInt(value))
    }

    /// Encode this `VarInt` into a synchronous writer.
    pub fn write_sync<W: Write>(&self, writer: &mut W) -> Result<(), VarIntError> {
        let mut value = self.0 as u32;
        loop {
            if value & !(SEGMENT_BITS as u32) == 0 {
                writer.write_all(&[value as u8])?;
                return Ok(());
            }
            writer.write_all(&[((value as u8) & SEGMENT_BITS) | CONTINUE_BIT])?;
            value >>= 7;
        }
    }

    // --- Async I/O ---

    /// Decode a `VarInt` from an async reader (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn read_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, VarIntError> {
        let mut value: i32 = 0;
        let mut position: u32 = 0;

        loop {
            let byte = reader.read_u8().await?;
            value |= ((byte & SEGMENT_BITS) as i32) << position;

            if byte & CONTINUE_BIT == 0 {
                break;
            }

            position += 7;
            if position >= 32 {
                return Err(VarIntError::TooLong);
            }
        }

        Ok(VarInt(value))
    }

    /// Encode this `VarInt` into an async writer (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), VarIntError> {
        let mut value = self.0 as u32;
        loop {
            if value & !(SEGMENT_BITS as u32) == 0 {
                writer.write_u8(value as u8).await?;
                return Ok(());
            }
            writer
                .write_u8(((value as u8) & SEGMENT_BITS) | CONTINUE_BIT)
                .await?;
            value >>= 7;
        }
    }
}

impl From<i32> for VarInt {
    fn from(v: i32) -> Self {
        VarInt(v)
    }
}

impl From<VarInt> for i32 {
    fn from(v: VarInt) -> i32 {
        v.0
    }
}

impl std::fmt::Display for VarInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// VarLong
// ---------------------------------------------------------------------------

/// A variable-length signed 64-bit integer as used in the Minecraft protocol.
///
/// Wraps an `i64`. Negative values use 10 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VarLong(pub i64);

impl VarLong {
    /// The minimum number of bytes needed to represent this value.
    pub fn encoded_len(&self) -> usize {
        let mut value = self.0 as u64;
        let mut count = 0;
        loop {
            count += 1;
            if value & !(SEGMENT_BITS as u64) == 0 {
                break;
            }
            value >>= 7;
        }
        count
    }

    // --- Synchronous I/O ---

    /// Decode a `VarLong` from a synchronous reader.
    pub fn read_sync<R: Read>(reader: &mut R) -> Result<Self, VarIntError> {
        let mut value: i64 = 0;
        let mut position: u32 = 0;

        loop {
            let mut byte_buf = [0u8; 1];
            if reader.read(&mut byte_buf)? == 0 {
                return Err(VarIntError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF reading VarLong",
                )));
            }

            let byte = byte_buf[0];
            value |= ((byte & SEGMENT_BITS) as i64) << position;

            if byte & CONTINUE_BIT == 0 {
                break;
            }

            position += 7;
            if position >= 64 {
                return Err(VarIntError::TooLong);
            }
        }

        Ok(VarLong(value))
    }

    /// Encode this `VarLong` into a synchronous writer.
    pub fn write_sync<W: Write>(&self, writer: &mut W) -> Result<(), VarIntError> {
        let mut value = self.0 as u64;
        loop {
            if value & !(SEGMENT_BITS as u64) == 0 {
                writer.write_all(&[value as u8])?;
                return Ok(());
            }
            writer.write_all(&[((value as u8) & SEGMENT_BITS) | CONTINUE_BIT])?;
            value >>= 7;
        }
    }

    // --- Async I/O ---

    /// Decode a `VarLong` from an async reader (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn read_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, VarIntError> {
        let mut value: i64 = 0;
        let mut position: u32 = 0;

        loop {
            let byte = reader.read_u8().await?;
            value |= ((byte & SEGMENT_BITS) as i64) << position;

            if byte & CONTINUE_BIT == 0 {
                break;
            }

            position += 7;
            if position >= 64 {
                return Err(VarIntError::TooLong);
            }
        }

        Ok(VarLong(value))
    }

    /// Encode this `VarLong` into an async writer (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), VarIntError> {
        let mut value = self.0 as u64;
        loop {
            if value & !(SEGMENT_BITS as u64) == 0 {
                writer.write_u8(value as u8).await?;
                return Ok(());
            }
            writer
                .write_u8(((value as u8) & SEGMENT_BITS) | CONTINUE_BIT)
                .await?;
            value >>= 7;
        }
    }
}

impl From<i64> for VarLong {
    fn from(v: i64) -> Self {
        VarLong(v)
    }
}

impl From<VarLong> for i64 {
    fn from(v: VarLong) -> i64 {
        v.0
    }
}

impl std::fmt::Display for VarLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
