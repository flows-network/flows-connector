use std::env;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

fn main() {
	let passphrase = env::var("PASSPHRASE").unwrap();

	let rsa = Rsa::generate(2048).unwrap();
	let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes()).unwrap();
	let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

	println!("Private key: {}", String::from_utf8(private_key).unwrap());
	println!("Public key: {}", String::from_utf8(public_key).unwrap());
}

#[cfg(test)]
mod tests {
	use openssl::rsa::{Rsa, Padding};
	use std::env;

    #[test]
    fn it_works() {
		let passphrase = env::var("PASSPHRASE").unwrap();
    
		let public_key_pem = env::var("PUBLIC_KEY_PEM").unwrap();
		let private_key_pem = env::var("PRIVATE_KEY_PEM").unwrap();

		let data = "A quick brown fox jumps over the lazy dog.";

		// Encrypt with public key
		let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes()).unwrap();
		let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
		let _ = rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
		let data = hex::encode(buf);
		println!("Encrypted: {}", data);

		// Decrypt with private key
		let rsa = Rsa::private_key_from_pem_passphrase(private_key_pem.as_bytes(), passphrase.as_bytes()).unwrap();
		let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
		let l = rsa.private_decrypt(&hex::decode(data).unwrap(), &mut buf, Padding::PKCS1).unwrap();
		let data = String::from_utf8(buf[..l].to_vec()).unwrap();
		println!("Decrypted: {}", data);
        assert_eq!("A quick brown fox jumps over the lazy dog.", data);
    }
}