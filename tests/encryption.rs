//! Tests for AES-128-CFB8 encryption.

use mc_protocol::encryption::{Cfb8Decryptor, Cfb8Encryptor};

const TEST_KEY: &[u8; 16] = b"abcdefghijklmnop";
const ZERO_KEY: &[u8; 16] = &[0u8; 16];

// ---------------------------------------------------------------------------
// Low-level encryptor / decryptor
// ---------------------------------------------------------------------------

#[test]
fn encrypt_then_decrypt_returns_original() {
    let plaintext = b"Hello, Minecraft!";

    let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let mut dec = Cfb8Decryptor::new(TEST_KEY).unwrap();

    let ciphertext = enc.encrypt(plaintext).unwrap();
    assert_ne!(
        &ciphertext, plaintext,
        "Encrypted data should differ from plaintext"
    );

    let recovered = dec.decrypt(&ciphertext).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_empty_input() {
    let mut enc = Cfb8Encryptor::new(ZERO_KEY).unwrap();
    let result = enc.encrypt(&[]).unwrap();
    assert!(result.is_empty());
}

#[test]
fn decrypt_empty_input() {
    let mut dec = Cfb8Decryptor::new(ZERO_KEY).unwrap();
    let result = dec.decrypt(&[]).unwrap();
    assert!(result.is_empty());
}

#[test]
fn encrypt_single_byte() {
    let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let mut dec = Cfb8Decryptor::new(TEST_KEY).unwrap();
    let plaintext = b"\x42";
    let ciphertext = enc.encrypt(plaintext).unwrap();
    let recovered = dec.decrypt(&ciphertext).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_256_bytes_round_trip() {
    let plaintext: Vec<u8> = (0u8..=255).collect();
    let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let mut dec = Cfb8Decryptor::new(TEST_KEY).unwrap();
    let ciphertext = enc.encrypt(&plaintext).unwrap();
    let recovered = dec.decrypt(&ciphertext).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn stateful_byte_by_byte_encryption_matches_bulk() {
    let plaintext = b"Hello";
    let mut enc_bulk = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let mut enc_byte = Cfb8Encryptor::new(TEST_KEY).unwrap();

    let bulk = enc_bulk.encrypt(plaintext).unwrap();

    let mut per_byte = Vec::new();
    for &b in plaintext {
        let encrypted = enc_byte.encrypt(&[b]).unwrap();
        per_byte.extend_from_slice(&encrypted);
    }

    assert_eq!(
        bulk, per_byte,
        "Byte-by-byte and bulk encryption must produce identical results"
    );
}

#[test]
fn stateful_byte_by_byte_decryption_matches_bulk() {
    let plaintext = b"Streaming test data for Minecraft protocol";
    let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let ciphertext = enc.encrypt(plaintext).unwrap();

    let mut dec_bulk = Cfb8Decryptor::new(TEST_KEY).unwrap();
    let mut dec_byte = Cfb8Decryptor::new(TEST_KEY).unwrap();

    let bulk = dec_bulk.decrypt(&ciphertext).unwrap();

    let mut per_byte = Vec::new();
    for &b in &ciphertext {
        let decrypted = dec_byte.decrypt(&[b]).unwrap();
        per_byte.extend_from_slice(&decrypted);
    }

    assert_eq!(bulk, per_byte);
    assert_eq!(bulk, plaintext);
}

#[test]
fn matches_openssl_known_answer() {
    // openssl enc -aes-128-cfb8 -K 000102..0f -iv 000102..0f
    let key: [u8; 16] = std::array::from_fn(|i| i as u8);
    let plaintext = b"Hello, Minecraft protocol! CFB8 known-answer test.";
    let expected: Vec<u8> = (0..100)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(
                &"42ea5ed4daf864eae7ef5c17728310d5ecaf34e37de59a5240e722d18c3c1cfa7bad3f2a3da9ab073caf0b67aec2cfc1824b"[i..i + 2],
                16,
            )
            .unwrap()
        })
        .collect();

    let ciphertext = Cfb8Encryptor::new(&key)
        .unwrap()
        .encrypt(plaintext)
        .unwrap();
    assert_eq!(ciphertext, expected);
    let decrypted = Cfb8Decryptor::new(&key)
        .unwrap()
        .decrypt(&ciphertext)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn ciphers_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Cfb8Encryptor>();
    assert_send_sync::<Cfb8Decryptor>();
}

#[test]
fn different_keys_produce_different_ciphertexts() {
    let key1 = b"key_one_xxxxxxxx";
    let key2 = b"key_two_xxxxxxxx";
    let plaintext = b"same plaintext";

    let mut enc1 = Cfb8Encryptor::new(key1).unwrap();
    let mut enc2 = Cfb8Encryptor::new(key2).unwrap();

    let ct1 = enc1.encrypt(plaintext).unwrap();
    let ct2 = enc2.encrypt(plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn wrong_key_fails_to_decrypt_correctly() {
    let enc_key = b"correct_key12345";
    let dec_key = b"wrong_key_000000";

    let mut enc = Cfb8Encryptor::new(enc_key).unwrap();
    let mut dec = Cfb8Decryptor::new(dec_key).unwrap();

    let ciphertext = enc.encrypt(b"secret data").unwrap();
    let result = dec.decrypt(&ciphertext).unwrap();

    assert_ne!(result, b"secret data");
}

// ---------------------------------------------------------------------------
// Sync stream wrappers
// ---------------------------------------------------------------------------

#[test]
fn sync_read_half_decrypts_on_read() {
    use mc_protocol::encryption::Cfb8ReadHalf;
    use std::io::Read;

    let plaintext = b"Sync read test data";
    let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
    let ciphertext = enc.encrypt(plaintext).unwrap();

    let mut read_half = Cfb8ReadHalf::new(std::io::Cursor::new(ciphertext), TEST_KEY).unwrap();
    let mut output = vec![0u8; plaintext.len()];
    read_half.read_exact(&mut output).unwrap();

    assert_eq!(output, plaintext);
}

#[test]
fn sync_write_half_encrypts_on_write() {
    use mc_protocol::encryption::{Cfb8ReadHalf, Cfb8WriteHalf};
    use std::io::{Read, Write};

    let plaintext = b"Sync write test data";

    let mut buf = Vec::new();
    let mut write_half = Cfb8WriteHalf::new(&mut buf, TEST_KEY).unwrap();
    write_half.write_all(plaintext).unwrap();
    drop(write_half);

    // Decrypt what was written
    let mut read_half = Cfb8ReadHalf::new(std::io::Cursor::new(&buf), TEST_KEY).unwrap();
    let mut decoded = vec![0u8; plaintext.len()];
    read_half.read_exact(&mut decoded).unwrap();

    assert_eq!(decoded, plaintext);
}

// ---------------------------------------------------------------------------
// Async stream (requires async feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "async")]
mod async_tests {
    use mc_protocol::encryption::{AsyncCfb8ReadHalf, AsyncCfb8WriteHalf, Cfb8Encryptor};
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_KEY: &[u8; 16] = b"abcdefghijklmnop";

    #[tokio::test]
    async fn async_write_half_encrypts() {
        let plaintext = b"Async encrypted packet data";

        let mut buf = Vec::new();
        let mut write_half = AsyncCfb8WriteHalf::new(&mut buf, TEST_KEY).unwrap();
        write_half.write_all(plaintext).await.unwrap();
        write_half.flush().await.unwrap();
        drop(write_half);

        // Re-encrypt the decrypted buf to verify round-trip...
        let mut dec = mc_protocol::encryption::Cfb8Decryptor::new(TEST_KEY).unwrap();
        let recovered = dec.decrypt(&buf).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn async_read_half_decrypts() {
        let plaintext = b"Async read half test";
        let mut enc = Cfb8Encryptor::new(TEST_KEY).unwrap();
        let ciphertext = enc.encrypt(plaintext).unwrap();

        let mut read_half = AsyncCfb8ReadHalf::new(Cursor::new(ciphertext), TEST_KEY).unwrap();
        let mut output = vec![0u8; plaintext.len()];
        read_half.read_exact(&mut output).await.unwrap();
        assert_eq!(output, plaintext);
    }

    /// An `AsyncWrite` that exercises backpressure: it alternates between
    /// returning `Poll::Pending` and accepting a single byte per call.
    struct BackpressuredWriter {
        data: Vec<u8>,
        pending_next: bool,
    }

    impl BackpressuredWriter {
        fn new() -> Self {
            Self {
                data: Vec::new(),
                pending_next: true,
            }
        }
    }

    impl tokio::io::AsyncWrite for BackpressuredWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.pending_next {
                self.pending_next = false;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            self.pending_next = true;
            self.data.push(buf[0]);
            std::task::Poll::Ready(Ok(1))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Regression test: `Poll::Pending` or partial writes from the inner
    /// writer must not desynchronize the cipher state or drop ciphertext.
    #[tokio::test]
    async fn async_write_half_survives_backpressure_and_partial_writes() {
        let plaintext = b"Backpressure must not corrupt the encrypted stream";

        let mut write_half = AsyncCfb8WriteHalf::new(BackpressuredWriter::new(), TEST_KEY).unwrap();
        // Write in small chunks to interleave encryption with backpressure
        for chunk in plaintext.chunks(7) {
            write_half.write_all(chunk).await.unwrap();
        }
        write_half.flush().await.unwrap();

        let written = write_half.into_inner().data;
        assert_eq!(written.len(), plaintext.len(), "no ciphertext may be lost");

        let mut dec = mc_protocol::encryption::Cfb8Decryptor::new(TEST_KEY).unwrap();
        let recovered = dec.decrypt(&written).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// `flush` must drain ciphertext still buffered after a `Pending` write.
    #[tokio::test]
    async fn async_write_half_flush_drains_buffer() {
        let plaintext = b"flush me";

        let mut write_half = AsyncCfb8WriteHalf::new(BackpressuredWriter::new(), TEST_KEY).unwrap();
        write_half.write_all(plaintext).await.unwrap();
        write_half.flush().await.unwrap();

        let written = write_half.into_inner().data;
        let mut dec = mc_protocol::encryption::Cfb8Decryptor::new(TEST_KEY).unwrap();
        assert_eq!(dec.decrypt(&written).unwrap(), plaintext);
    }
}
