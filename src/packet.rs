//! Packet framing for the Minecraft Java Edition protocol.
//!
//! The Minecraft protocol wraps every packet in a length-prefixed frame. In
//! unencrypted, uncompressed mode a packet looks like:
//!
//! ```text
//! VarInt(total_length)  VarInt(packet_id)  [payload bytes...]
//! ```
//!
//! When compression is enabled (after `Set Compression` packet) the frame
//! becomes:
//!
//! ```text
//! VarInt(frame_len)  VarInt(data_length)  [compressed_or_raw_data...]
//! ```
//!
//! where `data_length` is 0 when the inner payload was not compressed (below
//! the threshold), or the uncompressed length when it was.
//!
//! This module provides [`RawPacket`] (the on-wire frame), [`UncompressedPacket`]
//! (decoded packet_id + payload), and helper methods for both sync and async I/O.

use std::io::{self, Cursor, Read, Write};
use thiserror::Error;

use crate::ser::{Deserialize, SerializationError, Serialize};
use crate::varint::{VarInt, VarIntError};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during packet framing.
#[derive(Debug, Error)]
pub enum PacketError {
    /// A VarInt/VarLong could not be decoded.
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    /// An underlying I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A serialization error occurred while encoding/decoding a field.
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Packet length or data length was negative or otherwise invalid.
    #[error("Invalid packet length: {0}")]
    InvalidLength(i64),
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum size in bytes of a packet frame (and of an uncompressed packet body).
///
/// The protocol encodes the frame length as a VarInt of at most 3 bytes, so
/// the largest representable value is `2^21 - 1`. The vanilla client and
/// server both enforce this limit; [`RawPacket::read_sync`] /
/// [`RawPacket::read_async`] reject larger frames, which also prevents a
/// malicious length prefix from triggering a multi-gigabyte allocation.
pub const MAX_PACKET_LENGTH: usize = 2_097_151;

/// Maximum `data_length` of a compressed packet (vanilla limit, 2^23 bytes).
pub const MAX_UNCOMPRESSED_LENGTH: usize = 8_388_608;

#[cfg(feature = "compression")]
fn active_threshold(threshold: Option<i32>) -> Option<usize> {
    threshold.and_then(|t| usize::try_from(t).ok())
}

fn checked_read_len(len: VarInt) -> Result<usize, PacketError> {
    if len.0 < 0 || len.0 as usize > MAX_PACKET_LENGTH {
        return Err(PacketError::InvalidLength(len.0 as i64));
    }
    Ok(len.0 as usize)
}

/// Splits `[packet_id][payload]` in place, reusing the buffer for the payload.
fn split_packet_id(mut data: Vec<u8>, offset: usize) -> Result<UncompressedPacket, PacketError> {
    let mut cursor = Cursor::new(&data[offset..]);
    let packet_id = VarInt::read_sync(&mut cursor)?.0;
    let end = offset + cursor.position() as usize;
    data.drain(..end);
    Ok(UncompressedPacket {
        packet_id,
        payload: data,
    })
}

fn checked_frame_len(len: usize) -> Result<i32, PacketError> {
    if len > MAX_PACKET_LENGTH {
        return Err(PacketError::InvalidLength(len as i64));
    }
    Ok(len as i32)
}

// ---------------------------------------------------------------------------
// PacketId trait
// ---------------------------------------------------------------------------

/// A packet struct that has a known numeric ID.
pub trait PacketId {
    /// The numeric ID that identifies this packet on the wire.
    fn packet_id(&self) -> i32;
}

// ---------------------------------------------------------------------------
// RawPacket
// ---------------------------------------------------------------------------

/// A length-delimited on-wire packet frame.
///
/// `data` contains everything *after* the leading length VarInt: for an
/// uncompressed connection that is `[packet_id_varint][payload]`, and for a
/// compressed connection it is `[data_length_varint][compressed_or_raw_data]`.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// The raw frame data (not including the leading length VarInt).
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Create a `RawPacket` from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        RawPacket { data }
    }

    // --- Sync read/write ---

    /// Read a length-prefixed frame from a synchronous reader.
    ///
    /// Fails with [`PacketError::InvalidLength`] if the declared length is
    /// negative or exceeds [`MAX_PACKET_LENGTH`].
    ///
    /// The length prefix is read byte by byte, so wrap unbuffered sources such
    /// as sockets in a `BufReader`.
    pub fn read_sync<R: Read>(reader: &mut R) -> Result<Self, PacketError> {
        let len = checked_read_len(VarInt::read_sync(reader)?)?;
        let mut data = Vec::with_capacity(len);
        reader.take(len as u64).read_to_end(&mut data)?;
        if data.len() != len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        Ok(RawPacket { data })
    }

    /// Write this packet frame to a synchronous writer; rejects frames over [`MAX_PACKET_LENGTH`].
    pub fn write_sync<W: Write>(&self, writer: &mut W) -> Result<(), PacketError> {
        VarInt(checked_frame_len(self.data.len())?).write_sync(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    // --- Async read/write ---

    /// Read a length-prefixed frame from an async reader (requires `async` feature).
    ///
    /// Fails with [`PacketError::InvalidLength`] if the declared length is
    /// negative or exceeds [`MAX_PACKET_LENGTH`].
    ///
    /// The length prefix is read byte by byte, so wrap unbuffered sources such
    /// as sockets in a `tokio::io::BufReader`. Not cancellation safe: a frame
    /// interrupted midway is lost and the stream is left desynchronized.
    #[cfg(feature = "async")]
    pub async fn read_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, PacketError> {
        use bytes::BufMut;

        let len = checked_read_len(VarInt::read_async(reader).await?)?;
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let remaining = len - data.len();
            if reader.read_buf(&mut (&mut data).limit(remaining)).await? == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
        Ok(RawPacket { data })
    }

    /// Write this packet frame to an async writer; rejects frames over [`MAX_PACKET_LENGTH`].
    #[cfg(feature = "async")]
    pub async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), PacketError> {
        VarInt(checked_frame_len(self.data.len())?)
            .write_async(writer)
            .await?;
        writer.write_all(&self.data).await?;
        Ok(())
    }

    // --- Conversion helpers ---

    /// Interpret this frame as an uncompressed packet (no compression in effect).
    ///
    /// Fails with an I/O error (`UnexpectedEof`) if the frame is too short to
    /// contain a packet ID.
    pub fn as_uncompressed(&self) -> Result<UncompressedPacket, PacketError> {
        let mut cursor = Cursor::new(&self.data);
        let packet_id = VarInt::read_sync(&mut cursor)?;
        let pos = cursor.position() as usize;
        let payload = self.data[pos..].to_vec();
        Ok(UncompressedPacket {
            packet_id: packet_id.0,
            payload,
        })
    }

    /// Attempt to uncompress a compressed packet frame.
    ///
    /// When `threshold` is `None` or negative (vanilla's "compression
    /// disabled"), the frame is interpreted as uncompressed. Otherwise the
    /// first field is `data_length` (VarInt): if 0, the rest is uncompressed;
    /// otherwise it is the uncompressed length and the rest is zlib-deflated.
    ///
    /// Returns `Err` if decompression fails, if `data_length` is negative or
    /// exceeds [`MAX_UNCOMPRESSED_LENGTH`], or if the decompressed size does not
    /// match the declared `data_length` (zip-bomb guard).
    #[cfg(feature = "compression")]
    pub fn uncompress(&self, threshold: Option<i32>) -> Result<UncompressedPacket, PacketError> {
        use crate::compression::decompress_zlib_limited;

        if active_threshold(threshold).is_none() {
            return self.as_uncompressed();
        }

        let mut cursor = Cursor::new(&self.data);
        let data_length = VarInt::read_sync(&mut cursor)?;
        let compressed_start = cursor.position() as usize;

        if data_length.0 < 0 || data_length.0 as usize > MAX_UNCOMPRESSED_LENGTH {
            return Err(PacketError::InvalidLength(data_length.0 as i64));
        }

        if data_length.0 == 0 {
            // Not compressed — read packet_id and payload directly
            let packet_id = VarInt::read_sync(&mut cursor)?;
            let pos = cursor.position() as usize;
            let payload = self.data[pos..].to_vec();
            return Ok(UncompressedPacket {
                packet_id: packet_id.0,
                payload,
            });
        }

        // Compressed payload — never inflate past the declared size, and
        // require the declared size to be exact.
        let compressed_data = &self.data[compressed_start..];
        let uncompressed = decompress_zlib_limited(compressed_data, data_length.0 as usize)?;
        if uncompressed.len() != data_length.0 as usize {
            return Err(PacketError::InvalidLength(uncompressed.len() as i64));
        }
        split_packet_id(uncompressed, 0)
    }

    /// Like [`uncompress`](Self::uncompress), but consumes the frame so an
    /// uncompressed body is reused in place instead of copied.
    pub fn into_uncompressed(
        self,
        threshold: Option<i32>,
    ) -> Result<UncompressedPacket, PacketError> {
        #[cfg(feature = "compression")]
        if active_threshold(threshold).is_some() {
            let mut cursor = Cursor::new(&self.data);
            let data_length = VarInt::read_sync(&mut cursor)?.0;
            if data_length != 0 {
                return self.uncompress(threshold);
            }
            let offset = cursor.position() as usize;
            return split_packet_id(self.data, offset);
        }
        #[cfg(not(feature = "compression"))]
        let _ = threshold;
        split_packet_id(self.data, 0)
    }

    /// Interpret frame without feature-gating (no compression).
    #[cfg(not(feature = "compression"))]
    pub fn uncompress(&self, _threshold: Option<i32>) -> Result<UncompressedPacket, PacketError> {
        self.as_uncompressed()
    }
}

// ---------------------------------------------------------------------------
// UncompressedPacket
// ---------------------------------------------------------------------------

/// A decoded packet with a numeric ID and a raw payload byte slice.
///
/// The payload does *not* include the packet ID; it contains only the fields
/// of the specific packet type.
#[derive(Debug, Clone)]
pub struct UncompressedPacket {
    /// The numeric packet ID.
    pub packet_id: i32,
    /// The packet fields serialized according to the protocol.
    pub payload: Vec<u8>,
}

impl UncompressedPacket {
    /// Create a new `UncompressedPacket`.
    pub fn new(packet_id: i32, payload: Vec<u8>) -> Self {
        UncompressedPacket { packet_id, payload }
    }

    /// Deserialize the payload into a concrete packet type `T`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handshake: Handshake = packet.deserialize_payload()?;
    /// ```
    pub fn deserialize_payload<T: Deserialize>(&self) -> Result<T, PacketError> {
        let mut cursor = Cursor::new(&self.payload);
        Ok(T::deserialize(&mut cursor)?)
    }

    /// Encode into a `RawPacket` frame (no compression).
    pub fn to_raw_packet(&self) -> Result<RawPacket, PacketError> {
        let mut buf = Vec::new();
        VarInt(self.packet_id).write_sync(&mut buf)?;
        std::io::Write::write_all(&mut buf, &self.payload)?;
        Ok(RawPacket { data: buf })
    }

    /// Encode into a length-prefixed, possibly-compressed frame.
    ///
    /// When `threshold` is `None` or negative no compression framing is applied.
    /// When `Some(t)`, packets with an uncompressed length >= `t` are
    /// zlib-compressed.
    #[cfg(feature = "compression")]
    pub fn to_raw_packet_compressed(
        &self,
        threshold: Option<i32>,
    ) -> Result<RawPacket, PacketError> {
        use crate::compression::compress_zlib;

        let Some(t) = active_threshold(threshold) else {
            return self.to_raw_packet();
        };

        // Build the inner [packet_id][payload] data
        let mut inner = Vec::new();
        VarInt(self.packet_id).write_sync(&mut inner)?;
        inner.extend_from_slice(&self.payload);

        if inner.len() > MAX_UNCOMPRESSED_LENGTH {
            return Err(PacketError::InvalidLength(inner.len() as i64));
        }

        let mut frame = Vec::new();
        if inner.len() >= t {
            // Compress
            let compressed = compress_zlib(&inner)?;
            VarInt(inner.len() as i32).write_sync(&mut frame)?;
            frame.extend_from_slice(&compressed);
        } else {
            // Below threshold — send uncompressed with data_length = 0
            VarInt(0).write_sync(&mut frame)?;
            frame.extend_from_slice(&inner);
        }

        Ok(RawPacket { data: frame })
    }

    #[cfg(not(feature = "compression"))]
    /// Encode to raw packet (compression stub — feature not enabled).
    pub fn to_raw_packet_compressed(
        &self,
        _threshold: Option<i32>,
    ) -> Result<RawPacket, PacketError> {
        self.to_raw_packet()
    }

    /// Build an `UncompressedPacket` by serializing a packet struct that implements
    /// both [`PacketId`] and [`Serialize`].
    pub fn from_packet<P: PacketId + Serialize>(packet: &P) -> Result<Self, PacketError> {
        let mut payload = Vec::new();
        packet.serialize(&mut payload)?;
        Ok(UncompressedPacket {
            packet_id: packet.packet_id(),
            payload,
        })
    }

    /// Write this packet to a synchronous writer (uncompressed framing).
    pub fn write_sync<W: Write>(&self, writer: &mut W) -> Result<(), PacketError> {
        self.to_raw_packet()?.write_sync(writer)
    }

    /// Write this packet to an async writer (uncompressed framing).
    #[cfg(feature = "async")]
    pub async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), PacketError> {
        self.to_raw_packet()?.write_async(writer).await
    }
}
