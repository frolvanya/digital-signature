use rand::rngs::OsRng;

use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha512};

fn main() {
    // Initialization of the main variables
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();

    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // First Part

    let message = "Message";

    let mut hasher = Sha512::new(); // Message = M
    hasher.update(message);

    let message_hash = format!("{:x}", hasher.finalize()); // Hash(M) = Mh
    let bytes_message_hash = message_hash.as_bytes();

    let signature = private_key
        .encrypt(&mut rng, padding, &bytes_message_hash[..])
        .expect("failed to encrypt"); // Encrypt(Mh, private_key) = Signature

    println!("{:?}", signature);

    // Second Part

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let another_message = "Message"; // Message = M

    let mut hasher = Sha512::new();
    hasher.update(another_message);

    let another_message_hash = format!("{:x}", hasher.finalize()); // Hash(M) = Mh
    let bytes_another_message_hash = another_message_hash.as_bytes();

    let encrypted_another_message =
        public_key.encrypt(&mut rng, padding, &bytes_another_message_hash[..]); // Decrypt(Signature, public_key) = Mh'

    println!("{:?}\n\n\n{:?}", signature, encrypted_another_message);
}
