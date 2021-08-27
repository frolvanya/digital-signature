use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Serialize, Deserialize)]
struct SignedMessage {
    message: String,
    signature: String,
}
struct PublicKey(Vec<u8>);
struct PrivateKey(Vec<u8>);
#[derive(Debug)]
struct VerificationError(String);

impl SignedMessage {
    fn new(message: String, private_key: PrivateKey) -> Self {
        SignedMessage {
            message: message.clone(),
            signature: encrypt_with_private_key(&sha512_hash(message.as_str()), private_key)
                .iter()
                .map(|element| format!("{:02X}", element))
                .collect::<Vec<String>>()
                .join(""),
        }
    }

    fn load(
        message: String,
        signature: String,
        public_key: PublicKey,
    ) -> Result<Self, VerificationError> {
        let decrypted_message_hash = decrypt_with_public_key(
            hex_to_bytes(signature.clone().as_str()).unwrap(),
            public_key,
        );

        if sha512_hash(message.as_str()) == decrypted_message_hash {
            return Ok(SignedMessage { message, signature });
        }

        Err(VerificationError(String::from(
            "Message verification failed!",
        )))
    }
}

fn generate_keys() -> (PublicKey, PrivateKey) {
    let rsa = Rsa::generate(2048).unwrap();

    let public_key = PublicKey(rsa.public_key_to_pem().unwrap());
    let private_key = PrivateKey(rsa.private_key_to_pem().unwrap());

    (public_key, private_key)
}

fn encrypt_with_private_key(message: &[u8], private_key: PrivateKey) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem(&private_key.0).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let buf_actual_len = rsa
        .private_encrypt(message, &mut buf, Padding::PKCS1)
        .unwrap();
    buf.truncate(buf_actual_len);

    buf
}

fn decrypt_with_public_key(data: Vec<u8>, public_key: PublicKey) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(&public_key.0).unwrap();
    let mut buf = vec![0; rsa.size() as usize];

    let buf_actual_len = rsa.public_decrypt(&data, &mut buf, Padding::PKCS1).unwrap();
    buf.truncate(buf_actual_len);

    buf
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

    let signed_message = SignedMessage::new(message.to_string(), private_key);

    match SignedMessage::load(
        signed_message.message.to_string(),
        signed_message.signature,
        public_key,
    ) {
        Ok(message_with_signature) => println!(
            "Message was successfully verificated!\nMessage: {}\nSignature: {}",
            message_with_signature.message, message_with_signature.signature
        ),
        Err(e) => println!("Message verification failed!\nError: {:?}", e),
    }
}
