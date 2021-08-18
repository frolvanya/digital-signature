use rand::{self, Rng};

use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;

use sha2::{Digest, Sha512};

fn sha512_hash(text: &str) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(text);

    hasher.finalize().to_vec()
}

fn encrypt_with_private_key(private_key: Vec<u8>, seed: String, message: &[u8]) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem_passphrase(&private_key, seed.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let _ = rsa
        .private_encrypt(message, &mut buf, Padding::PKCS1)
        .unwrap();

    buf
}

fn decrypt_with_public_key(public_key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(&public_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];

    let _ = rsa.public_decrypt(&data, &mut buf, Padding::PKCS1).unwrap();

    buf
}

fn main() {
    // +---------+-----------+
    // | MESSAGE | SIGNATURE |
    // +---------+-----------+

    let rsa = Rsa::generate(2048).unwrap();
    let seed: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let public_key = rsa.public_key_to_pem().unwrap();
    let private_key = rsa
        .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), seed.as_bytes())
        .unwrap();

    // Message = M
    let message = "Message";

    // Hash(M) = Mh
    let message_hash = sha512_hash(message);

    // Encrypt(Mh, PRIVATE_KEY) = Signature
    let encrypted_message_hash = encrypt_with_private_key(private_key, seed, &message_hash);

    // Digital Signature Authentication

    // Message = M'
    let another_message = "Message";

    // Hash(M') = Mh'
    let another_message_hash = sha512_hash(another_message);

    // Decrypt(Signature, PUBLIC_KEY) = Mh'
    let mut decrypted_another_message_hash =
        decrypt_with_public_key(public_key, encrypted_message_hash);

    // Remove all trailing zeros
    decrypted_another_message_hash.retain(|&x| x != 0);

    // Check if Mh' = Mh
    if another_message_hash == decrypted_another_message_hash {
        println!("Digital signature is genuine!");
    } else {
        println!("Digital signature is not genuine!");
    }

    println!(
        "{:?}\n\n\n{:?}",
        message_hash, decrypted_another_message_hash
    );
}
