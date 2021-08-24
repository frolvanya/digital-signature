use openssl::rsa::{Padding, Rsa};
use serde_json::json;
use sha2::{Digest, Sha512};

struct PublicKey(Vec<u8>);
struct PrivateKey(Vec<u8>);

fn generate_keys() -> (PublicKey, PrivateKey) {
    let rsa = Rsa::generate(2048).unwrap();

    let public_key = PublicKey(rsa.public_key_to_pem().unwrap());
    let private_key = PrivateKey(rsa.private_key_to_pem().unwrap());

    (public_key, private_key)
}

fn encrypt_with_private_key(private_key: PrivateKey, message: &[u8]) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem(&private_key.0).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let _ = rsa
        .private_encrypt(message, &mut buf, Padding::PKCS1)
        .unwrap();

    buf
}

fn decrypt_with_public_key(data: Vec<u8>, public_key: PublicKey) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(&public_key.0).unwrap();
    let mut buf = vec![0; rsa.size() as usize];

    let buf_actual_len = rsa.public_decrypt(&data, &mut buf, Padding::PKCS1).unwrap();
    buf.truncate(buf_actual_len);

    buf
}

fn create_signature(message: &str, private_key: PrivateKey) -> serde_json::Value {
    let signature = encrypt_with_private_key(private_key, &sha512_hash(message));

    json!({
        "message": message,
        "signature": signature.iter().map(|element| format!("{:02X}", element)).collect::<Vec<String>>().join(""),
    })
}

fn message_verification(message_with_signature: serde_json::Value, public_key: PublicKey) -> bool {
    let decrypted_message_hash = decrypt_with_public_key(
        hex_to_bytes(message_with_signature["signature"].as_str().unwrap()).unwrap(),
        public_key,
    );

    sha512_hash(message_with_signature["message"].as_str().unwrap()) == decrypted_message_hash
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
    let (public_key, private_key) = generate_keys();
    let message = "Message";

    let message_to_send = create_signature(message, private_key);

    if message_verification(message_to_send, public_key) {
        println!("Message verification successful!");
    } else {
        println!("Message verification failed!");
    }
}
