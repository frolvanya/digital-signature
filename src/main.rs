use rand::{self, Rng};

use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;

fn encrypt_with_private_key(private_key: Vec<u8>, seed: String, message: &str) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem_passphrase(&private_key, seed.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let _ = rsa
        .private_encrypt(message.as_bytes(), &mut buf, Padding::PKCS1)
        .unwrap();

    buf
}

fn decrypt_with_public_key(public_key: Vec<u8>, data: Vec<u8>) -> String {
    let rsa = Rsa::public_key_from_pem(&public_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];

    let _ = rsa.public_decrypt(&data, &mut buf, Padding::PKCS1).unwrap();

    String::from_utf8(buf)
        .unwrap()
        .trim_matches(char::from(0))
        .to_string()
}

fn main() {
    let seed: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let message = "Message";

    let rsa = Rsa::generate(2048).unwrap();
    let private_key = rsa
        .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), seed.as_bytes())
        .unwrap();
    let public_key = rsa.public_key_to_pem().unwrap();

    let encrypted_message = encrypt_with_private_key(private_key, seed, message);
    let decrypted_message = decrypt_with_public_key(public_key, encrypted_message.clone());

    println!(
        "ENCRYPTED MESSAGE: {:?}\n\n\nDECRYPTED MESSAGE: {}",
        encrypted_message, decrypted_message
    );
}
