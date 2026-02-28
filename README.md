# minecraft_protocol

Rust implementation of the Minecraft Java Edition network protocol primitives: serialization of basic types, packet framing, AES-128-CFB8 encryption, and Zlib compression.

## Features

- Serialize and deserialize all basic protocol types: booleans, integers, floats, strings, UUIDs, VarInt, VarLong, Option, Vec, and raw bytes.
- Packet framing with length-prefixed read/write, both sync and async.
- AES-128-CFB8 stream encryption (sync and async wrappers).
- Zlib packet compression with configurable threshold.
- `#[derive(Packet)]` macro to generate `Serialize`, `Deserialize`, and `PacketId` for packet structs.

## Installation

```toml
[dependencies]
minecraft_protocol = { git = "https://github.com/kauri-off/minecraft_protocol.git" }
```

To disable optional features:

```toml
[dependencies]
minecraft_protocol = { git = "https://github.com/kauri-off/minecraft_protocol.git", default-features = false }
```

## Feature Flags

| Feature       | Description              | Default |
| ------------- | ------------------------ | ------- |
| `async`       | Async I/O via Tokio      | enabled |
| `encryption`  | AES-128-CFB8 via OpenSSL | enabled |
| `compression` | Zlib via flate2          | enabled |

## Usage

### Derive macro

Define a packet struct and derive serialization automatically:

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

assert_eq!(Handshake::PACKET_ID, 0x00);
```

### Serialization

All basic types implement `Serialize` and `Deserialize`:

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

### Packet framing (sync)

```rust
use minecraft_protocol::packet::{UncompressedPacket, RawPacket};
use std::net::TcpStream;

let mut stream = TcpStream::connect("127.0.0.1:25565")?;

let raw = RawPacket::read_sync(&mut stream)?;
let packet = raw.as_uncompressed()?;
println!("Received packet 0x{:02X}", packet.packet_id);

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

### Compression

```rust
use minecraft_protocol::packet::UncompressedPacket;

let up = UncompressedPacket::new(0x26, payload);
let threshold = Some(256);

let raw = up.to_raw_packet_compressed(threshold)?;
let decoded = raw.uncompress(threshold)?;
```

### Encryption (sync)

```rust
use minecraft_protocol::encryption::{Cfb8Encryptor, Cfb8Decryptor};

let key: [u8; 16] = shared_secret;
let mut encryptor = Cfb8Encryptor::new(&key)?;
let mut decryptor = Cfb8Decryptor::new(&key)?;

let ciphertext = encryptor.encrypt(b"packet data")?;
let plaintext = decryptor.decrypt(&ciphertext)?;
```

### Encryption (async stream)

```rust
use minecraft_protocol::encryption::Cfb8Stream;
use tokio::net::TcpStream;

let stream = TcpStream::connect("127.0.0.1:25565").await?;
let key: [u8; 16] = shared_secret;

let mut encrypted = Cfb8Stream::new_from_tcp(stream, &key)?;
// All I/O through `encrypted` is transparently encrypted
```

## License

MIT
