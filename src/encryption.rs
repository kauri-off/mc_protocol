//! AES-128-CFB8 stream encryption as used by the Minecraft Java Edition protocol.
//!
//! After a successful login handshake, both sides agree on a 16-byte shared
//! secret. From that point on, every byte sent and received is encrypted with
//! AES-128 in CFB8 mode using the shared secret as both the key and the IV.
//!
//! # Example (sync)
//!
//! ```rust,no_run
//! use std::net::TcpStream;
//! use mc_protocol::encryption::{Cfb8Encryptor, Cfb8Decryptor};
//!
//! let key = [0u8; 16]; // replace with actual shared secret
//! let mut stream = TcpStream::connect("127.0.0.1:25565").unwrap();
//!
//! let mut encryptor = Cfb8Encryptor::new(&key).unwrap();
//! let mut decryptor = Cfb8Decryptor::new(&key).unwrap();
//!
//! // Encrypt data before writing
//! let plaintext = b"hello";
//! let ciphertext = encryptor.encrypt(plaintext).unwrap();
//! ```
//!
//! # Example (async)
//!
//! ```rust,no_run
//! use tokio::net::TcpStream;
//! use mc_protocol::encryption::Cfb8Stream;
//!
//! # #[tokio::main] async fn main() -> std::io::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:25565").await?;
//! let key = [0u8; 16];
//! let encrypted = Cfb8Stream::new_from_tcp(stream, &key)?;
//! # Ok(()) }
//! ```

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read, Write};

#[cfg(feature = "async")]
use {
    std::pin::Pin,
    std::task::{Context, Poll},
    tokio::io::{AsyncRead, AsyncWrite, ReadBuf},
    tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    tokio::net::TcpStream,
};

// ---------------------------------------------------------------------------
// Low-level encryptor / decryptor
// ---------------------------------------------------------------------------

/// Stateful AES-128-CFB8 encryptor.
pub struct Cfb8Encryptor {
    crypter: Crypter,
}

impl Cfb8Encryptor {
    /// Create a new encryptor with the given 16-byte key.
    /// The IV is the same as the key, as required by Minecraft.
    pub fn new(key: &[u8; 16]) -> io::Result<Self> {
        let mut crypter = Crypter::new(Cipher::aes_128_cfb8(), Mode::Encrypt, key, Some(key))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        crypter.pad(false);
        Ok(Self { crypter })
    }

    /// Encrypt a slice of plaintext bytes, returning the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = vec![0u8; plaintext.len() + 16];
        let n = self
            .crypter
            .update(plaintext, &mut output)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        output.truncate(n);
        Ok(output)
    }
}

/// Stateful AES-128-CFB8 decryptor.
pub struct Cfb8Decryptor {
    crypter: Crypter,
}

impl Cfb8Decryptor {
    /// Create a new decryptor with the given 16-byte key.
    /// The IV is the same as the key, as required by Minecraft.
    pub fn new(key: &[u8; 16]) -> io::Result<Self> {
        let mut crypter = Crypter::new(Cipher::aes_128_cfb8(), Mode::Decrypt, key, Some(key))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        crypter.pad(false);
        Ok(Self { crypter })
    }

    /// Decrypt a slice of ciphertext bytes, returning the plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = vec![0u8; ciphertext.len() + 16];
        let n = self
            .crypter
            .update(ciphertext, &mut output)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        output.truncate(n);
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Sync encrypted stream wrapper
// ---------------------------------------------------------------------------

/// A synchronous read-half that transparently decrypts incoming bytes.
pub struct Cfb8ReadHalf<R> {
    inner: R,
    decryptor: Cfb8Decryptor,
}

impl<R: Read> Cfb8ReadHalf<R> {
    /// Wrap a reader with AES-128-CFB8 decryption.
    pub fn new(inner: R, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            decryptor: Cfb8Decryptor::new(key)?,
        })
    }

    /// Unwrap, discarding the decryptor state.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Cfb8ReadHalf<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }
        let decrypted = self.decryptor.decrypt(&buf[..n])?;
        buf[..n].copy_from_slice(&decrypted[..n]);
        Ok(n)
    }
}

/// A synchronous write-half that transparently encrypts outgoing bytes.
pub struct Cfb8WriteHalf<W> {
    inner: W,
    encryptor: Cfb8Encryptor,
}

impl<W: Write> Cfb8WriteHalf<W> {
    /// Wrap a writer with AES-128-CFB8 encryption.
    pub fn new(inner: W, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            encryptor: Cfb8Encryptor::new(key)?,
        })
    }

    /// Unwrap, discarding the encryptor state.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Cfb8WriteHalf<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let encrypted = self.encryptor.encrypt(buf)?;
        self.inner.write_all(&encrypted)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Async encrypted stream wrappers
// ---------------------------------------------------------------------------

/// Async read-half that transparently decrypts incoming bytes.
#[cfg(feature = "async")]
pub struct AsyncCfb8ReadHalf<R> {
    inner: R,
    decryptor: Cfb8Decryptor,
}

#[cfg(feature = "async")]
impl<R> AsyncCfb8ReadHalf<R> {
    /// Wrap an async reader with decryption.
    pub fn new(inner: R, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            decryptor: Cfb8Decryptor::new(key)?,
        })
    }

    /// Unwrap the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> AsyncRead for AsyncCfb8ReadHalf<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &poll {
            let new_data = &mut buf.filled_mut()[pre_len..];
            if !new_data.is_empty() {
                match self.decryptor.decrypt(new_data) {
                    Ok(decrypted) => new_data.copy_from_slice(&decrypted[..new_data.len()]),
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }

        poll
    }
}

/// Async write-half that transparently encrypts outgoing bytes.
#[cfg(feature = "async")]
pub struct AsyncCfb8WriteHalf<W> {
    inner: W,
    encryptor: Cfb8Encryptor,
}

#[cfg(feature = "async")]
impl<W> AsyncCfb8WriteHalf<W> {
    /// Wrap an async writer with encryption.
    pub fn new(inner: W, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            encryptor: Cfb8Encryptor::new(key)?,
        })
    }

    /// Unwrap the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(feature = "async")]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncCfb8WriteHalf<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encrypted = match self.encryptor.encrypt(buf) {
            Ok(e) => e,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Combined async stream
// ---------------------------------------------------------------------------

/// A combined async read/write stream with AES-128-CFB8 encryption.
///
/// Created from a `TcpStream` after the encryption handshake is complete.
#[cfg(feature = "async")]
pub struct Cfb8Stream<R, W> {
    /// The decrypting read half.
    pub read_half: AsyncCfb8ReadHalf<R>,
    /// The encrypting write half.
    pub write_half: AsyncCfb8WriteHalf<W>,
}

#[cfg(feature = "async")]
impl Cfb8Stream<OwnedReadHalf, OwnedWriteHalf> {
    /// Create an encrypted stream wrapping a `TcpStream`.
    ///
    /// The TCP stream is split into read and write halves, each wrapped with
    /// an independent AES-128-CFB8 cipher instance sharing the same key.
    pub fn new_from_tcp(stream: TcpStream, key: &[u8; 16]) -> io::Result<Self> {
        let (r, w) = stream.into_split();
        Ok(Self {
            read_half: AsyncCfb8ReadHalf::new(r, key)?,
            write_half: AsyncCfb8WriteHalf::new(w, key)?,
        })
    }
}

#[cfg(feature = "async")]
impl<R, W> Cfb8Stream<R, W> {
    /// Create a stream from pre-existing read and write halves.
    pub fn new(read_half: R, write_half: W, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            read_half: AsyncCfb8ReadHalf::new(read_half, key)?,
            write_half: AsyncCfb8WriteHalf::new(write_half, key)?,
        })
    }

    /// Split into individual read and write halves.
    pub fn split(self) -> (AsyncCfb8ReadHalf<R>, AsyncCfb8WriteHalf<W>) {
        (self.read_half, self.write_half)
    }

    /// Unwrap into the bare inner read and write halves.
    pub fn into_inner(self) -> (R, W) {
        (self.read_half.into_inner(), self.write_half.into_inner())
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Cfb8Stream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read_half).poll_read(cx, buf)
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for Cfb8Stream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write_half).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write_half).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write_half).poll_shutdown(cx)
    }
}
