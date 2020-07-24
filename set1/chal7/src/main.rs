extern crate base64;
extern crate openssl;
use openssl::symm::{Cipher, Mode, Crypter};
use base64::decode;
use std::fs::File;
use std::io::prelude::*;

fn read_file(filepath: &str) -> String {
    let mut file = File::open(filepath)
        .unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .unwrap();
    contents
}

fn main() {
    let base64 = read_file("data/ciphertext.txt");
    let bytes = decode(base64);
    let ciphertext = match bytes {
        Ok(c) => c,
        Err(e) => panic!("Invalid base64 input: {}", e),
    };
    let key = b"YELLOW SUBMARINE";
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Decrypt,
        key,
        None).unwrap();
    let block_size = Cipher::aes_128_ecb().block_size();
    let data_len = ciphertext.len();
    let mut plaintext = vec![0; data_len + block_size];
    decrypter
        .update(&ciphertext[..data_len], &mut plaintext)
        .unwrap();
    decrypter
        .finalize(&mut plaintext)
        .unwrap();
    println!("{}", String::from_utf8(plaintext).unwrap());
}
