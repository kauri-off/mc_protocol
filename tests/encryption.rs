//! Tests for AES-128-CFB8 encryption.

use minecraft_protocol::encryption::{Cfb8Decryptor, Cfb8Encryptor};

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
    use minecraft_protocol::encryption::Cfb8ReadHalf;
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
    use minecraft_protocol::encryption::{Cfb8ReadHalf, Cfb8WriteHalf};
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
    use minecraft_protocol::encryption::{AsyncCfb8ReadHalf, AsyncCfb8WriteHalf, Cfb8Encryptor};
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
        let mut dec = minecraft_protocol::encryption::Cfb8Decryptor::new(TEST_KEY).unwrap();
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
}
