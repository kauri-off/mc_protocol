# minecraft_protocol

A complete, production-quality Rust library for working with the Minecraft Java Edition network protocol.

## Features

- **Complete protocol data types** — every type from the spec: Boolean, Byte, Short, Int, Long,
  Float, Double, String, UUID, VarInt, VarLong, Position, Angle, Identifier, BitSet, FixedBitSet,
  TeleportFlags, SoundEvent, and more.
- **Packet framing** — length-prefixed read/write with both synchronous and async paths.
- **AES-128-CFB8 encryption** — sync and async stream wrappers for post-login traffic.
- **Zlib compression** — automatic compress/decompress with configurable threshold.
- **Derive macro** — `#[derive(Packet)]` generates `Serialize`, `Deserialize`, and `PacketId`
  for any struct with named fields.
- **Both sync and async** — all I/O operations have synchronous (`_sync`) and async (`_async`)
  variants via Tokio.
- **Comprehensive tests** — every type, every edge case, and all protocol sample values verified.

## Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `async` | Async I/O via Tokio | enabled |
| `encryption` | AES-128-CFB8 via OpenSSL | enabled |
| `compression` | Zlib via flate2 | enabled |

Disable any feature to reduce compile time and dependencies:

```toml
[dependencies]
minecraft_protocol = { version = "2.0", default-features = false }
```

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
minecraft_protocol = { git = "https://github.com/kauri-off/minecraft_protocol.git" }
```

### Derive macro

```rust
use minecraft_protocol::{Packet, varint::VarInt};

#[derive(Packet, Debug)]
#[packet(0x00)]
struct Handshake {
    protocol_version: VarInt,
    server_address: String,
    server_port: u16,
    next_state: VarInt,
}

// PACKET_ID const is generated automatically
assert_eq!(Handshake::PACKET_ID, 0x00);
```

### Serialization

```rust
use minecraft_protocol::ser::{Serialize, Deserialize};
use minecraft_protocol::varint::VarInt;
use std::io::Cursor;

let mut buf = Vec::new();
VarInt(300).serialize(&mut buf).unwrap();
// buf == [0xac, 0x02]

let v = VarInt::deserialize(&mut Cursor::new(&buf)).unwrap();
assert_eq!(v.0, 300);
```

### Block Position

```rust
use minecraft_protocol::types::Position;
use minecraft_protocol::ser::{Serialize, Deserialize};
use std::io::Cursor;

let pos = Position { x: 18357644, y: 831, z: -20882616 };
let mut buf = Vec::new();
pos.serialize(&mut buf).unwrap();

let decoded = Position::deserialize(&mut Cursor::new(&buf)).unwrap();
assert_eq!(decoded, pos);
```

### Packet framing (sync)

```rust
use minecraft_protocol::packet::{UncompressedPacket, RawPacket};
use std::net::TcpStream;

let mut stream = TcpStream::connect("127.0.0.1:25565")?;

// Read a packet
let raw = RawPacket::read_sync(&mut stream)?;
let packet = raw.as_uncompressed()?;
println!("Received packet 0x{:02X}", packet.packet_id);

// Write a packet
let up = UncompressedPacket::new(0x00, vec![0x00]);
up.write_sync(&mut stream)?;
```

### Packet framing (async)

```rust
use minecraft_protocol::packet::{UncompressedPacket, RawPacket};
use tokio::net::TcpStream;

let mut stream = TcpStream::connect("127.0.0.1:25565").await?;

let raw = RawPacket::read_async(&mut stream).await?;
let packet = raw.as_uncompressed()?;

let up = UncompressedPacket::new(0x00, vec![0x00]);
up.write_async(&mut stream).await?;
```

### Packet compression

```rust
use minecraft_protocol::packet::UncompressedPacket;

let up = UncompressedPacket::new(0x26, chunk_data_payload);
let threshold = Some(256);

// Encode (compresses if payload >= 256 bytes)
let raw = up.to_raw_packet_compressed(threshold)?;

// Decode (decompresses automatically)
let decoded = raw.uncompress(threshold)?;
```

### AES-128-CFB8 encryption (sync)

```rust
use minecraft_protocol::encryption::{Cfb8Encryptor, Cfb8Decryptor};

let key: [u8; 16] = shared_secret; // from login handshake
let mut encryptor = Cfb8Encryptor::new(&key)?;
let mut decryptor = Cfb8Decryptor::new(&key)?;

let ciphertext = encryptor.encrypt(b"packet data")?;
let plaintext = decryptor.decrypt(&ciphertext)?;
```

### AES-128-CFB8 encryption (async stream)

```rust
use minecraft_protocol::encryption::Cfb8Stream;
use tokio::net::TcpStream;

let stream = TcpStream::connect("127.0.0.1:25565").await?;
let key: [u8; 16] = shared_secret;

// After this, all I/O through `encrypted` is transparently encrypted
let mut encrypted = Cfb8Stream::new_from_tcp(stream, &key)?;

// Read and write as normal — encryption is handled automatically
```

## Protocol Types

| Minecraft Type | Rust Type | Notes |
|---------------|-----------|-------|
| Boolean | `bool` | 0x00 / 0x01 |
| Byte | `i8` | Signed 8-bit |
| Unsigned Byte | `u8` | Unsigned 8-bit |
| Short | `i16` | Big-endian |
| Unsigned Short | `u16` | Big-endian |
| Int | `i32` | Big-endian |
| Long | `i64` | Big-endian |
| Float | `f32` | IEEE 754 big-endian |
| Double | `f64` | IEEE 754 big-endian |
| String | `String` | VarInt(len) + UTF-8 |
| UUID | `uuid::Uuid` | 128-bit big-endian |
| VarInt | `varint::VarInt` | 1-5 bytes |
| VarLong | `varint::VarLong` | 1-10 bytes |
| Position | `types::Position` | Packed 64-bit |
| Angle | `types::Angle` | 1 byte, 1/256 turn |
| Identifier | `types::Identifier` | Namespaced key |
| BitSet | `types::BitSet` | VarInt + longs |
| Fixed BitSet (n) | `types::FixedBitSet` | ceil(n/8) bytes |
| Optional X | `Option<T>` | bool + optional T |
| Prefixed Array | `Vec<T>` | VarInt(len) + items |
| Teleport Flags | `types::TeleportFlags` | i32 bit field |
| Sound Event | `types::SoundEvent` | Identifier + Optional Float |

## Architecture

```
minecraft_protocol/
  src/
    lib.rs          # Module declarations, re-exports
    ser.rs          # Serialize / Deserialize traits and primitive impls
    varint.rs       # VarInt and VarLong (sync + async)
    types.rs        # Protocol-specific types (Position, Angle, BitSet, ...)
    num.rs          # Integer trait for big-endian primitives
    packet.rs       # Packet framing: RawPacket, UncompressedPacket
    encryption.rs   # AES-128-CFB8 (feature = "encryption")
    compression.rs  # Zlib (feature = "compression")
  minecraft_protocol_derive/
    src/lib.rs      # #[derive(Packet)] procedural macro
  tests/
    varint.rs       # VarInt tests with all protocol sample values
    varlong.rs      # VarLong tests with all protocol sample values
    types.rs        # Primitive and complex type round-trip tests
    position.rs     # Position, Angle, Identifier, TeleportFlags tests
    bitset.rs       # BitSet and FixedBitSet tests
    packet.rs       # Packet framing and derive macro tests
    encryption.rs   # CFB8 encryption tests (feature = "encryption")
    compression.rs  # Zlib compression tests (feature = "compression")
```

## VarInt Encoding Reference

From the Minecraft protocol documentation:

| Value | Hex bytes | Decimal bytes |
|-------|-----------|---------------|
| 0 | `00` | 0 |
| 1 | `01` | 1 |
| 127 | `7f` | 127 |
| 128 | `80 01` | 128 1 |
| 255 | `ff 01` | 255 1 |
| 25565 | `dd c7 01` | 221 199 1 |
| 2097151 | `ff ff 7f` | 255 255 127 |
| 2147483647 | `ff ff ff ff 07` | 255 255 255 255 7 |
| -1 | `ff ff ff ff 0f` | 255 255 255 255 15 |
| -2147483648 | `80 80 80 80 08` | 128 128 128 128 8 |

## Running Tests

```bash
# Run all tests with all features
cargo test --all-features

# Run tests for a specific module
cargo test --all-features --test varint
cargo test --all-features --test encryption

# Run without optional features
cargo test --no-default-features
```

## License

MIT
