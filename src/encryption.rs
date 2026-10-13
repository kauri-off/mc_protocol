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
//! # #[cfg(feature = "async")]
//! # #[tokio::main] async fn main() -> std::io::Result<()> {
//! use tokio::net::TcpStream;
//! use mc_protocol::encryption::Cfb8Stream;
//!
//! let stream = TcpStream::connect("127.0.0.1:25565").await?;
//! let key = [0u8; 16];
//! let encrypted = Cfb8Stream::new_from_tcp(stream, &key)?;
//! # Ok(()) }
//! # #[cfg(not(feature = "async"))] fn main() {}
//! ```

use aes::Aes128;
use cfb8::cipher::KeyIvInit;
use std::io::{self, Read, Write};

#[cfg(feature = "async")]
use {
    std::pin::Pin,
    std::task::{Context, Poll},
    tokio::io::{AsyncRead, AsyncWrite, ReadBuf},
    tokio::net::TcpStream,
    tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

// ---------------------------------------------------------------------------
// Low-level encryptor / decryptor
// ---------------------------------------------------------------------------

/// Stateful AES-128-CFB8 encryptor.
pub struct Cfb8Encryptor {
    cipher: cfb8::Encryptor<Aes128>,
}

impl Cfb8Encryptor {
    /// Create a new encryptor with the given 16-byte key.
    /// The IV is the same as the key, as required by Minecraft.
    pub fn new(key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            cipher: cfb8::Encryptor::new(&(*key).into(), &(*key).into()),
        })
    }

    /// Encrypt a slice of plaintext bytes, returning the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = plaintext.to_vec();
        self.encrypt_in_place(&mut output);
        Ok(output)
    }

    /// Encrypt `data` in place, without allocating.
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.cipher.encrypt(data);
    }
}

/// Stateful AES-128-CFB8 decryptor.
pub struct Cfb8Decryptor {
    cipher: cfb8::Decryptor<Aes128>,
}

impl Cfb8Decryptor {
    /// Create a new decryptor with the given 16-byte key.
    /// The IV is the same as the key, as required by Minecraft.
    pub fn new(key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            cipher: cfb8::Decryptor::new(&(*key).into(), &(*key).into()),
        })
    }

    /// Decrypt a slice of ciphertext bytes, returning the plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = ciphertext.to_vec();
        self.decrypt_in_place(&mut output);
        Ok(output)
    }

    /// Decrypt `data` in place, without allocating.
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.cipher.decrypt(data);
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
        self.decryptor.decrypt_in_place(&mut buf[..n]);
        Ok(n)
    }
}

/// A synchronous write-half that transparently encrypts outgoing bytes.
pub struct Cfb8WriteHalf<W> {
    inner: W,
    encryptor: Cfb8Encryptor,
    /// Scratch space for ciphertext, reused across writes.
    buffer: Vec<u8>,
}

impl<W: Write> Cfb8WriteHalf<W> {
    /// Wrap a writer with AES-128-CFB8 encryption.
    pub fn new(inner: W, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            encryptor: Cfb8Encryptor::new(key)?,
            buffer: Vec::new(),
        })
    }

    /// Unwrap, discarding the encryptor state.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Cfb8WriteHalf<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.clear();
        self.buffer.extend_from_slice(buf);
        self.encryptor.encrypt_in_place(&mut self.buffer);
        self.inner.write_all(&self.buffer)?;
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
            self.decryptor
                .cipher
                .decrypt(&mut buf.filled_mut()[pre_len..]);
        }

        poll
    }
}

/// Async write-half that transparently encrypts outgoing bytes.
///
/// Input is encrypted exactly once and held in an internal buffer until the
/// inner writer accepts it, so backpressure (`Poll::Pending`) or partial
/// writes from the inner writer never desynchronize the cipher state.
/// Call `flush().await` (or `shutdown().await`) to ensure buffered ciphertext
/// reaches the inner writer.
#[cfg(feature = "async")]
pub struct AsyncCfb8WriteHalf<W> {
    inner: W,
    encryptor: Cfb8Encryptor,
    /// Encrypted bytes not yet accepted by the inner writer.
    buffer: Vec<u8>,
    /// Number of bytes at the front of `buffer` already written.
    written: usize,
}

#[cfg(feature = "async")]
impl<W> AsyncCfb8WriteHalf<W> {
    /// Wrap an async writer with encryption.
    pub fn new(inner: W, key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            inner,
            encryptor: Cfb8Encryptor::new(key)?,
            buffer: Vec::new(),
            written: 0,
        })
    }

    /// Unwrap the inner writer.
    ///
    /// Any encrypted bytes still buffered (not yet flushed) are discarded.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(feature = "async")]
impl<W: AsyncWrite + Unpin> AsyncCfb8WriteHalf<W> {
    /// Write buffered ciphertext to the inner writer until empty or blocked.
    fn poll_drain_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.buffer.len() {
            let Self {
                inner,
                buffer,
                written,
                ..
            } = self;
            match Pin::new(&mut *inner).poll_write(cx, &buffer[*written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner writer accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.buffer.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "async")]
impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncCfb8WriteHalf<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Previously encrypted bytes must reach the writer first, otherwise
        // the cipher state and the wire would diverge.
        match self.poll_drain_buffer(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // The drain above emptied the buffer, so only fresh plaintext is encrypted here.
        let this = &mut *self;
        debug_assert!(this.buffer.is_empty());
        this.buffer.extend_from_slice(buf);
        this.encryptor.encrypt_in_place(&mut this.buffer);

        // Opportunistically write; whatever the inner writer doesn't take now
        // stays buffered and is drained on the next write/flush/shutdown.
        if let Poll::Ready(Err(e)) = self.poll_drain_buffer(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_buffer(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_buffer(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
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
