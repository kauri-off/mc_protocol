//! Core serialization and deserialization traits used throughout the protocol.
//!
//! All protocol data is transmitted **big-endian** except for VarInt/VarLong,
//! which use little-endian groups of 7 bits.
//!
//! # Sync vs Async
//!
//! The [`Serialize`] and [`Deserialize`] traits work over any `std::io::Read` /
//! `std::io::Write`. For async usage, read into a `Vec<u8>` with Tokio and
//! then deserialize from a `std::io::Cursor`.

use std::{
    io::{self, Read, Write},
    string::FromUtf8Error,
};

use thiserror::Error;
use uuid::Uuid;

use crate::varint::{VarInt, VarIntError, VarLong};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during serialization or deserialization.
#[derive(Debug, Error)]
pub enum SerializationError {
    /// A VarInt or VarLong value exceeded the maximum allowed byte length.
    #[error("VarInt/VarLong error: {0}")]
    VarInt(#[from] VarIntError),

    /// An underlying I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A string contained invalid UTF-8 bytes.
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),

    /// A string exceeded the maximum allowed length in UTF-16 code units.
    #[error("String too long: {length} code units, maximum is {max}")]
    StringTooLong {
        /// Actual length in UTF-16 code units.
        length: usize,
        /// Maximum allowed length in UTF-16 code units.
        max: usize,
    },

    /// An enum discriminant was not valid.
    #[error("Invalid enum discriminant: {0}")]
    InvalidDiscriminant(i32),

    /// A packet had a negative or invalid length.
    #[error("Invalid length: {0}")]
    InvalidLength(i64),
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Types that can be serialized into a byte stream according to the Minecraft protocol.
pub trait Serialize {
    /// Encode `self` into `writer`.
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError>;
}

/// Types that can be deserialized from a byte stream according to the Minecraft protocol.
pub trait Deserialize: Sized {
    /// Decode an instance of `Self` from `reader`.
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError>;
}

// ---------------------------------------------------------------------------
// Primitive impls
// ---------------------------------------------------------------------------

/// Serialize a single big-endian byte primitive.
macro_rules! impl_primitive {
    ($t:ty) => {
        impl Serialize for $t {
            #[inline]
            fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
                writer.write_all(&self.to_be_bytes())?;
                Ok(())
            }
        }

        impl Deserialize for $t {
            #[inline]
            fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
                let mut buf = [0u8; std::mem::size_of::<$t>()];
                reader.read_exact(&mut buf)?;
                Ok(<$t>::from_be_bytes(buf))
            }
        }
    };
}

impl_primitive!(i8);
impl_primitive!(i16);
impl_primitive!(i32);
impl_primitive!(i64);
impl_primitive!(i128);
impl_primitive!(u8);
impl_primitive!(u16);
impl_primitive!(u32);
impl_primitive!(u64);
impl_primitive!(u128);
impl_primitive!(f32);
impl_primitive!(f64);

// ---------------------------------------------------------------------------
// Boolean
// ---------------------------------------------------------------------------

impl Serialize for bool {
    /// Encoded as `0x01` for `true`, `0x00` for `false`.
    #[inline]
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[if *self { 0x01 } else { 0x00 }])?;
        Ok(())
    }
}

impl Deserialize for bool {
    /// Any non-zero byte is `true`.
    #[inline]
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
}

// ---------------------------------------------------------------------------
// VarInt / VarLong
// ---------------------------------------------------------------------------

impl Serialize for VarInt {
    #[inline]
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.write_sync(writer)?;
        Ok(())
    }
}

impl Deserialize for VarInt {
    #[inline]
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        Ok(VarInt::read_sync(reader)?)
    }
}

impl Serialize for VarLong {
    #[inline]
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.write_sync(writer)?;
        Ok(())
    }
}

impl Deserialize for VarLong {
    #[inline]
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        Ok(VarLong::read_sync(reader)?)
    }
}

// ---------------------------------------------------------------------------
// String
// ---------------------------------------------------------------------------

/// Maximum allowed `String` length when no explicit limit is given (32767 UTF-16 code units).
pub const MAX_STRING_LENGTH: usize = 32767;

/// Encode a `&str` with a maximum UTF-16 length.
///
/// The format is: VarInt(byte_len) followed by UTF-8 bytes.
pub fn serialize_string_with_max<W: Write + Unpin>(
    s: &str,
    writer: &mut W,
    max_utf16: usize,
) -> Result<(), SerializationError> {
    let utf16_len = s.encode_utf16().count();
    if utf16_len > max_utf16 {
        return Err(SerializationError::StringTooLong {
            length: utf16_len,
            max: max_utf16,
        });
    }
    VarInt(s.len() as i32).write_sync(writer)?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

/// Decode a `String` enforcing a maximum UTF-16 length.
pub fn deserialize_string_with_max<R: Read + Unpin>(
    reader: &mut R,
    max_utf16: usize,
) -> Result<String, SerializationError> {
    let byte_len = VarInt::read_sync(reader)?.0 as usize;
    let mut buf = vec![0u8; byte_len];
    reader.read_exact(&mut buf)?;
    let s = String::from_utf8(buf)?;
    let utf16_len = s.encode_utf16().count();
    if utf16_len > max_utf16 {
        return Err(SerializationError::StringTooLong {
            length: utf16_len,
            max: max_utf16,
        });
    }
    Ok(s)
}

impl Serialize for String {
    /// Encoded as VarInt(byte_length) + UTF-8 bytes, max 32767 UTF-16 code units.
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        serialize_string_with_max(self, writer, MAX_STRING_LENGTH)
    }
}

impl Deserialize for String {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        deserialize_string_with_max(reader, MAX_STRING_LENGTH)
    }
}

impl Serialize for str {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        serialize_string_with_max(self, writer, MAX_STRING_LENGTH)
    }
}

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

impl Serialize for Uuid {
    /// Encoded as two big-endian u64 values (most significant bits first).
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(self.as_bytes())?;
        Ok(())
    }
}

impl Deserialize for Uuid {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf)?;
        Ok(Uuid::from_bytes(buf))
    }
}

// ---------------------------------------------------------------------------
// Option<T>  (prefixed optional — boolean presence flag + value)
// ---------------------------------------------------------------------------

impl<T: Serialize> Serialize for Option<T> {
    /// Encoded as Boolean(is_present) followed by T if present.
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            Some(v) => {
                true.serialize(writer)?;
                v.serialize(writer)?;
            }
            None => {
                false.serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let present = bool::deserialize(reader)?;
        if present {
            Ok(Some(T::deserialize(reader)?))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Vec<T>  (prefixed array — VarInt length + items)
// ---------------------------------------------------------------------------

impl<T: Serialize> Serialize for Vec<T> {
    /// Encoded as VarInt(length) followed by each element.
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        VarInt(self.len() as i32).write_sync(writer)?;
        for item in self {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let len = VarInt::read_sync(reader)?.0;
        if len < 0 {
            return Err(SerializationError::InvalidLength(len as i64));
        }
        let mut result = Vec::with_capacity(len as usize);
        for _ in 0..len {
            result.push(T::deserialize(reader)?);
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Raw byte array (no length prefix)
// ---------------------------------------------------------------------------

/// A newtype around `Vec<u8>` that serializes *without* a length prefix.
/// The length must be known from context.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawBytes(pub Vec<u8>);

impl RawBytes {
    /// Read exactly `n` bytes from `reader` into a `RawBytes`.
    pub fn read_exact<R: Read + Unpin>(reader: &mut R, n: usize) -> Result<Self, SerializationError> {
        let mut buf = vec![0u8; n];
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

impl Serialize for RawBytes {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}
