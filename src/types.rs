//! Complex protocol data types defined in the Minecraft Java Edition protocol.
//!
//! This module implements every composite data type from the protocol specification:
//!
//! - [`Position`] — packed 64-bit block coordinates (x: 26 bits, z: 26 bits, y: 12 bits)
//! - [`Angle`] — rotation in 1/256 steps of a full turn
//! - [`Identifier`] — namespaced resource key (e.g. `minecraft:stone`)
//! - [`BitSet`] — length-prefixed packed bit array
//! - [`FixedBitSet`] — fixed-length packed bit array
//! - [`Nbt`] — raw NBT byte blob
//! - [`FixedPoint5`] — legacy fixed-point with 5 fraction bits

use std::io::{Read, Write};

use crate::ser::{Deserialize, Serialize, SerializationError, deserialize_string_with_max, serialize_string_with_max};
use crate::varint::VarInt;

// ---------------------------------------------------------------------------
// Position
// ---------------------------------------------------------------------------

/// A packed 64-bit block position.
///
/// Encoding (big-endian 64-bit integer):
/// - bits 63..38: x (26 bits, signed)
/// - bits 37..12: z (26 bits, signed)
/// - bits 11..0 : y (12 bits, signed)
///
/// Valid ranges:
/// - x: -33554432 to 33554431
/// - z: -33554432 to 33554431  
/// - y: -2048 to 2047
///
/// # Example
///
/// ```
/// use minecraft_protocol::types::Position;
/// use minecraft_protocol::ser::{Serialize, Deserialize};
/// use std::io::Cursor;
///
/// let pos = Position { x: 18357644, y: 831, z: -20882616 };
/// let mut buf = Vec::new();
/// pos.serialize(&mut buf).unwrap();
/// let decoded = Position::deserialize(&mut Cursor::new(&buf)).unwrap();
/// assert_eq!(decoded, pos);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Position {
    /// X coordinate (-33554432 to 33554431).
    pub x: i32,
    /// Y coordinate (-2048 to 2047).
    pub y: i32,
    /// Z coordinate (-33554432 to 33554431).
    pub z: i32,
}

impl Position {
    /// Create a new `Position`.
    pub fn new(x: i32, y: i32, z: i32) -> Self {
        Self { x, y, z }
    }
}

impl Serialize for Position {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        let encoded: i64 = ((self.x as i64 & 0x3FF_FFFFi64) << 38)
            | ((self.z as i64 & 0x3FF_FFFFi64) << 12)
            | (self.y as i64 & 0xFFF);
        writer.write_all(&encoded.to_be_bytes())?;
        Ok(())
    }
}

impl Deserialize for Position {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let val = i64::from_be_bytes(buf);

        let mut x = (val >> 38) as i32;
        let mut y = (val << 52 >> 52) as i32;
        let mut z = (val << 26 >> 38) as i32;

        // Sign-extend manually for environments without arithmetic right shift
        if x >= 1 << 25 { x -= 1 << 26; }
        if y >= 1 << 11 { y -= 1 << 12; }
        if z >= 1 << 25 { z -= 1 << 26; }

        Ok(Position { x, y, z })
    }
}

// ---------------------------------------------------------------------------
// Angle
// ---------------------------------------------------------------------------

/// A rotation angle encoded as 1/256 steps of a full turn (0–255).
///
/// To convert to degrees: `angle_degrees = (value as f32) * 360.0 / 256.0`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Angle(pub u8);

impl Angle {
    /// Convert from degrees (0.0–360.0) to an `Angle`.
    pub fn from_degrees(degrees: f32) -> Self {
        Angle(((degrees * 256.0 / 360.0) as i32 & 0xFF) as u8)
    }

    /// Convert to degrees (0.0–360.0).
    pub fn to_degrees(self) -> f32 {
        self.0 as f32 * 360.0 / 256.0
    }
}

impl Serialize for Angle {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}

impl Deserialize for Angle {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(Angle(buf[0]))
    }
}

// ---------------------------------------------------------------------------
// Identifier
// ---------------------------------------------------------------------------

/// A Minecraft namespaced resource identifier (e.g. `minecraft:stone`).
///
/// Format: `namespace:value` where both parts use `[a-z0-9._-]`, and value
/// may also contain `/`. Maximum length is 32767 UTF-16 code units.
///
/// If no namespace is given, it defaults to `minecraft`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identifier(pub String);

impl Identifier {
    /// Create an identifier, defaulting to the `minecraft` namespace if none given.
    pub fn new(s: impl Into<String>) -> Self {
        let s = s.into();
        if s.contains(':') {
            Identifier(s)
        } else {
            Identifier(format!("minecraft:{}", s))
        }
    }

    /// The namespace portion of the identifier.
    pub fn namespace(&self) -> &str {
        self.0.split_once(':').map(|(ns, _)| ns).unwrap_or("minecraft")
    }

    /// The value (path) portion of the identifier.
    pub fn value(&self) -> &str {
        self.0.split_once(':').map(|(_, v)| v).unwrap_or(&self.0)
    }
}

impl Serialize for Identifier {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        serialize_string_with_max(&self.0, writer, 32767)
    }
}

impl Deserialize for Identifier {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let s = deserialize_string_with_max(reader, 32767)?;
        Ok(Identifier(s))
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// BitSet
// ---------------------------------------------------------------------------

/// A length-prefixed variable-size bit array.
///
/// Encoded as VarInt(num_longs) followed by that many `i64` values. The i-th
/// bit is set when `data[i / 64] & (1 << (i % 64)) != 0`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitSet {
    /// Raw long array backing the bit set.
    pub data: Vec<i64>,
}

impl BitSet {
    /// Create an empty `BitSet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a `BitSet` large enough to hold `n_bits` bits.
    pub fn with_capacity(n_bits: usize) -> Self {
        let n_longs = (n_bits + 63) / 64;
        BitSet { data: vec![0i64; n_longs] }
    }

    /// Test whether bit `i` is set.
    pub fn get(&self, i: usize) -> bool {
        let word = i / 64;
        let bit = i % 64;
        if word >= self.data.len() {
            return false;
        }
        (self.data[word] >> bit) & 1 == 1
    }

    /// Set bit `i`.
    pub fn set(&mut self, i: usize) {
        let word = i / 64;
        let bit = i % 64;
        while self.data.len() <= word {
            self.data.push(0);
        }
        self.data[word] |= 1i64 << bit;
    }

    /// Clear bit `i`.
    pub fn clear(&mut self, i: usize) {
        let word = i / 64;
        let bit = i % 64;
        if word < self.data.len() {
            self.data[word] &= !(1i64 << bit);
        }
    }
}

impl Serialize for BitSet {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        VarInt(self.data.len() as i32).write_sync(writer)?;
        for long in &self.data {
            writer.write_all(&long.to_be_bytes())?;
        }
        Ok(())
    }
}

impl Deserialize for BitSet {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let len = VarInt::read_sync(reader)?.0;
        if len < 0 {
            return Err(SerializationError::InvalidLength(len as i64));
        }
        let mut data = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            data.push(i64::from_be_bytes(buf));
        }
        Ok(BitSet { data })
    }
}

// ---------------------------------------------------------------------------
// FixedBitSet
// ---------------------------------------------------------------------------

/// A fixed-length bit array encoded as `ceil(n / 8)` bytes.
///
/// The i-th bit is set when `data[i / 8] & (1 << (i % 8)) != 0`.
/// Note: This uses byte indexing, unlike [`BitSet`] which uses longs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedBitSet {
    /// Total number of bits.
    pub n_bits: usize,
    /// Raw byte storage; length is `ceil(n_bits / 8)`.
    pub data: Vec<u8>,
}

impl FixedBitSet {
    /// Create a zero-filled `FixedBitSet` with `n_bits` bits.
    pub fn new(n_bits: usize) -> Self {
        let n_bytes = (n_bits + 7) / 8;
        FixedBitSet { n_bits, data: vec![0u8; n_bytes] }
    }

    /// Test whether bit `i` is set.
    pub fn get(&self, i: usize) -> bool {
        let byte = i / 8;
        let bit = i % 8;
        if byte >= self.data.len() {
            return false;
        }
        (self.data[byte] >> bit) & 1 == 1
    }

    /// Set bit `i`.
    pub fn set(&mut self, i: usize) {
        let byte = i / 8;
        let bit = i % 8;
        if byte < self.data.len() {
            self.data[byte] |= 1 << bit;
        }
    }

    /// Clear bit `i`.
    pub fn clear(&mut self, i: usize) {
        let byte = i / 8;
        let bit = i % 8;
        if byte < self.data.len() {
            self.data[byte] &= !(1 << bit);
        }
    }

    /// Serialize this bitset given the fixed `n_bits` is known from context.
    pub fn serialize_fixed<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    /// Deserialize a `FixedBitSet` of known size `n_bits` from `reader`.
    pub fn deserialize_fixed<R: Read + Unpin>(reader: &mut R, n_bits: usize) -> Result<Self, SerializationError> {
        let n_bytes = (n_bits + 7) / 8;
        let mut data = vec![0u8; n_bytes];
        reader.read_exact(&mut data)?;
        Ok(FixedBitSet { n_bits, data })
    }
}

// ---------------------------------------------------------------------------
// Nbt
// ---------------------------------------------------------------------------

/// Raw NBT data as an opaque byte blob.
///
/// The Minecraft protocol transfers NBT in its binary form. This type stores
/// the raw bytes so that callers can decode them with an NBT library of their
/// choice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Nbt(pub Vec<u8>);

impl Nbt {
    /// Create an `Nbt` value from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Nbt(bytes)
    }

    /// The raw bytes of this NBT value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// NBT serialization/deserialization without a length prefix is context-dependent.
// Callers should read the raw bytes themselves and construct an Nbt from them.

// ---------------------------------------------------------------------------
// Fixed-point number helpers
// ---------------------------------------------------------------------------

/// Convert a `f64` to a fixed-point integer with `n` fraction bits.
///
/// This is used in some legacy protocol fields.
pub fn to_fixed_point(value: f64, n: u32) -> i32 {
    (value * (1 << n) as f64) as i32
}

/// Convert a fixed-point integer with `n` fraction bits back to `f64`.
pub fn from_fixed_point(fixed: i32, n: u32) -> f64 {
    fixed as f64 / (1 << n) as f64
}

/// A legacy fixed-point value with 5 fraction bits, stored as an `i32`.
/// Used in some old protocol versions for entity coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixedPoint5(pub i32);

impl FixedPoint5 {
    /// Convert from a floating-point coordinate.
    pub fn from_f64(v: f64) -> Self {
        FixedPoint5(to_fixed_point(v, 5))
    }

    /// Convert back to a floating-point coordinate.
    pub fn to_f64(self) -> f64 {
        from_fixed_point(self.0, 5)
    }
}

impl Serialize for FixedPoint5 {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.0.to_be_bytes())?;
        Ok(())
    }
}

impl Deserialize for FixedPoint5 {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(FixedPoint5(i32::from_be_bytes(buf)))
    }
}

// ---------------------------------------------------------------------------
// TeleportFlags
// ---------------------------------------------------------------------------

/// Bit field specifying whether each axis of a teleportation is relative or absolute.
///
/// A set bit means the teleportation on the corresponding axis is relative.
///
/// Encoded as an `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeleportFlags(pub i32);

impl TeleportFlags {
    /// Relative X position.
    pub const RELATIVE_X: i32 = 0x0001;
    /// Relative Y position.
    pub const RELATIVE_Y: i32 = 0x0002;
    /// Relative Z position.
    pub const RELATIVE_Z: i32 = 0x0004;
    /// Relative yaw rotation.
    pub const RELATIVE_YAW: i32 = 0x0008;
    /// Relative pitch rotation.
    pub const RELATIVE_PITCH: i32 = 0x0010;
    /// Relative X velocity.
    pub const RELATIVE_VELOCITY_X: i32 = 0x0020;
    /// Relative Y velocity.
    pub const RELATIVE_VELOCITY_Y: i32 = 0x0040;
    /// Relative Z velocity.
    pub const RELATIVE_VELOCITY_Z: i32 = 0x0080;
    /// Rotate velocity according to rotation change before applying.
    pub const ROTATE_VELOCITY: i32 = 0x0100;

    /// Create `TeleportFlags` with all positions relative.
    pub fn all_relative() -> Self {
        TeleportFlags(
            Self::RELATIVE_X
                | Self::RELATIVE_Y
                | Self::RELATIVE_Z
                | Self::RELATIVE_YAW
                | Self::RELATIVE_PITCH,
        )
    }

    /// Test if a specific flag bit is set.
    pub fn is_set(&self, flag: i32) -> bool {
        self.0 & flag != 0
    }
}

impl Serialize for TeleportFlags {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.0.to_be_bytes())?;
        Ok(())
    }
}

impl Deserialize for TeleportFlags {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(TeleportFlags(i32::from_be_bytes(buf)))
    }
}

// ---------------------------------------------------------------------------
// SoundEvent
// ---------------------------------------------------------------------------

/// Parameters for a sound event, as defined in the protocol.
///
/// The sound name is an `Identifier`, and there is an optional fixed range
/// (if absent the volume is distance-dependent).
#[derive(Debug, Clone, PartialEq)]
pub struct SoundEvent {
    /// The identifier of the sound.
    pub name: Identifier,
    /// If `Some`, the sound has a fixed maximum range in blocks.
    /// If `None`, volume decreases with distance.
    pub fixed_range: Option<f32>,
}

impl Serialize for SoundEvent {
    fn serialize<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.name.serialize(writer)?;
        self.fixed_range.serialize(writer)?;
        Ok(())
    }
}

impl Deserialize for SoundEvent {
    fn deserialize<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError> {
        let name = Identifier::deserialize(reader)?;
        let fixed_range = Option::<f32>::deserialize(reader)?;
        Ok(SoundEvent { name, fixed_range })
    }
}
