use rand::{self, Rng};

use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;

use sha2::{Digest, Sha512};

use serde_json::json;

fn generate_keys() -> (String, Vec<u8>, Vec<u8>) {
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

    (seed, public_key, private_key)
}

fn encrypt_with_private_key(private_key: Vec<u8>, seed: String, message: &[u8]) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem_passphrase(&private_key, seed.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let _ = rsa
        .private_encrypt(message, &mut buf, Padding::PKCS1)
        .unwrap();

    buf
}

fn decrypt_with_public_key(data: Vec<u8>, public_key: Vec<u8>) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(&public_key).unwrap();
    let mut buf = vec![0; rsa.size() as usize];

    let _ = rsa.public_decrypt(&data, &mut buf, Padding::PKCS1).unwrap();

    buf
}

fn create_signature(message: &str, private_key: Vec<u8>, seed: String) -> serde_json::Value {
    let signature = encrypt_with_private_key(private_key, seed, &sha512_hash(message));

    json!({
        "message": message,
        "signature": signature.iter().map(|element| format!("{:02X}", element)).collect::<Vec<String>>().join(""),
    })
}

fn message_verification(message_with_signature: serde_json::Value, public_key: Vec<u8>) -> bool {
    let mut decrypted_message_hash = decrypt_with_public_key(
        hex_to_bytes(message_with_signature["signature"].as_str().unwrap()).unwrap(),
        public_key,
    );

    while decrypted_message_hash.last().unwrap() == &0 {
        decrypted_message_hash.pop();
    }

    if sha512_hash(message_with_signature["message"].as_str().unwrap()) == decrypted_message_hash {
        return true;
    }

    false
}

fn sha512_hash(text: &str) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(text);

    hasher.finalize().to_vec()
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}

fn main() {
    let (seed, public_key, private_key) = generate_keys();
    let message = "Message";

    let message_to_send = create_signature(message, private_key, seed);

    if message_verification(message_to_send, public_key) {
        println!("Message verification successful!");
    } else {
        println!("Message verification failed!");
    }
}
