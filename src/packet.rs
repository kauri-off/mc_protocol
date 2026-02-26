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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    pub fn read_sync<R: Read>(reader: &mut R) -> Result<Self, PacketError> {
        let len = VarInt::read_sync(reader)?;
        if len.0 < 0 {
            return Err(PacketError::InvalidLength(len.0 as i64));
        }
        let mut data = vec![0u8; len.0 as usize];
        reader.read_exact(&mut data)?;
        Ok(RawPacket { data })
    }

    /// Write this packet frame to a synchronous writer (length-prefixed).
    pub fn write_sync<W: Write>(&self, writer: &mut W) -> Result<(), PacketError> {
        VarInt(self.data.len() as i32).write_sync(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    // --- Async read/write ---

    /// Read a length-prefixed frame from an async reader (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn read_async<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self, PacketError> {
        let len = VarInt::read_async(reader).await?;
        if len.0 < 0 {
            return Err(PacketError::InvalidLength(len.0 as i64));
        }
        let mut data = vec![0u8; len.0 as usize];
        reader.read_exact(&mut data).await?;
        Ok(RawPacket { data })
    }

    /// Write this packet frame to an async writer (requires `async` feature).
    #[cfg(feature = "async")]
    pub async fn write_async<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), PacketError> {
        VarInt(self.data.len() as i32).write_async(writer).await?;
        writer.write_all(&self.data).await?;
        Ok(())
    }

    // --- Conversion helpers ---

    /// Interpret this frame as an uncompressed packet (no compression in effect).
    ///
    /// Returns `None` if the data is empty.
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
    /// When `threshold` is `None`, the connection uses no compression and the
    /// frame is interpreted as uncompressed. When `threshold` is `Some(_)` the
    /// first field is `data_length` (VarInt): if 0, the rest is uncompressed;
    /// otherwise it is the uncompressed length and the rest is zlib-deflated.
    ///
    /// Returns `Err` if decompression fails.
    #[cfg(feature = "compression")]
    pub fn uncompress(&self, threshold: Option<i32>) -> Result<UncompressedPacket, PacketError> {
        use crate::compression::decompress_zlib;

        if threshold.is_none() {
            return self.as_uncompressed();
        }

        let mut cursor = Cursor::new(&self.data);
        let data_length = VarInt::read_sync(&mut cursor)?;
        let compressed_start = cursor.position() as usize;

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

        // Compressed payload
        let compressed_data = &self.data[compressed_start..];
        let uncompressed = decompress_zlib(compressed_data)?;
        let mut inner = Cursor::new(&uncompressed);
        let packet_id = VarInt::read_sync(&mut inner)?;
        let pos = inner.position() as usize;
        let payload = uncompressed[pos..].to_vec();
        Ok(UncompressedPacket {
            packet_id: packet_id.0,
            payload,
        })
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
    /// When `threshold` is `None` no compression is applied. When `Some(t)`,
    /// packets with an uncompressed length >= `t` are zlib-compressed.
    #[cfg(feature = "compression")]
    pub fn to_raw_packet_compressed(
        &self,
        threshold: Option<i32>,
    ) -> Result<RawPacket, PacketError> {
        use crate::compression::compress_zlib;

        let Some(t) = threshold else {
            return self.to_raw_packet();
        };

        // Build the inner [packet_id][payload] data
        let mut inner = Vec::new();
        VarInt(self.packet_id).write_sync(&mut inner)?;
        inner.extend_from_slice(&self.payload);

        let mut frame = Vec::new();
        if inner.len() >= t as usize {
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
    pub async fn write_async<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), PacketError> {
        self.to_raw_packet()?.write_async(writer).await
    }
}
